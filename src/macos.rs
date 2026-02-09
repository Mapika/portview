use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{get_username, PortInfo, TcpState};

// ── Constants ────────────────────────────────────────────────────────

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDTASKALLINFO: i32 = 2;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_TCP: i32 = 2;
const SOCKINFO_IN: i32 = 1;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const MAXPATHLEN: u32 = 1024;

// ── FFI declarations ─────────────────────────────────────────────────

extern "C" {
    fn proc_listpids(r#type: u32, typeinfo: u32, buffer: *mut libc::c_void, buffersize: i32) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: i32,
    ) -> i32;
    fn proc_pidfdinfo(
        pid: i32,
        fd: i32,
        flavor: i32,
        buffer: *mut libc::c_void,
        buffersize: i32,
    ) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    fn proc_listchildpids(pid: i32, buffer: *mut libc::c_void, buffersize: i32) -> i32;
}

// ── FFI structs ──────────────────────────────────────────────────────
// Definitions from XNU's bsd/sys/proc_info.h

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct In4in6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: u32, // in_addr.s_addr
}

#[repr(C)]
#[derive(Clone, Copy)]
union InAddrUnion {
    ina_46: In4in6Addr,
    ina_6: [u8; 16], // in6_addr
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    _padding: [u8; 2],
    rfu_1: u32,
    insi_faddr: InAddrUnion,
    insi_laddr: InAddrUnion,
    insi_v4: [u8; 4],  // in4_tos (1 byte) + 3 padding
    insi_v6: [u8; 12], // in6_hlim(1) + pad(3) + in6_cksum(4) + in6_ifindex(2) + in6_hops(2)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

// The soi_proto union — sized to the largest member (un_sockinfo):
// un_sockinfo = 2 x u64 + 2 x char[SOCK_MAXADDRLEN=255] = 528 bytes (with 8-byte alignment padding)
// We only read TCP and IN variants via read_unaligned, so the rest is unused padding.
const SOI_PROTO_SIZE: usize = 528;

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    soi_stat: VinfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: [u8; SOI_PROTO_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

// Validate struct sizes at compile time to catch layout mismatches
const _: () = assert!(std::mem::size_of::<ProcFdInfo>() == 8);
const _: () = assert!(std::mem::size_of::<ProcFileInfo>() == 24);
const _: () = assert!(std::mem::size_of::<SockbufInfo>() == 24);
const _: () = assert!(std::mem::size_of::<In4in6Addr>() == 16);

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcTaskInfo {
    pti_virtual_size: u64,
    pti_resident_size: u64,
    pti_total_user: u64,
    pti_total_system: u64,
    pti_threads_user: u64,
    pti_threads_system: u64,
    pti_policy: i32,
    pti_faults: i32,
    pti_pageins: i32,
    pti_cow_faults: i32,
    pti_messages_sent: i32,
    pti_messages_received: i32,
    pti_syscalls_mach: i32,
    pti_syscalls_unix: i32,
    pti_csw: i32,
    pti_threadnum: i32,
    pti_numrunning: i32,
    pti_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcTaskAllInfo {
    pbsd: ProcBsdInfo,
    ptinfo: ProcTaskInfo,
}

const _: () = assert!(std::mem::size_of::<ProcBsdInfo>() == 136);
const _: () = assert!(std::mem::size_of::<ProcTaskInfo>() == 96);
const _: () = assert!(std::mem::size_of::<ProcTaskAllInfo>() == 232);

// ── Helpers ──────────────────────────────────────────────────────────

fn list_all_pids() -> Vec<i32> {
    // First call with null to get required buffer size
    let size = unsafe { proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return vec![];
    }
    // Over-allocate to handle new processes appearing between calls
    let count = (size as usize / std::mem::size_of::<i32>()) + 64;
    let mut pids = vec![0i32; count];
    let actual = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut libc::c_void,
            (pids.len() * std::mem::size_of::<i32>()) as i32,
        )
    };
    if actual <= 0 {
        return vec![];
    }
    let actual_count = actual as usize / std::mem::size_of::<i32>();
    pids.truncate(actual_count);
    // Filter out PID 0 entries (padding from kernel)
    pids.retain(|&p| p > 0);
    pids
}

fn list_fds(pid: i32) -> Vec<ProcFdInfo> {
    let size = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 {
        return vec![];
    }
    let count = size as usize / std::mem::size_of::<ProcFdInfo>() + 16;
    let mut fds: Vec<ProcFdInfo> = vec![unsafe { std::mem::zeroed() }; count];
    let actual = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *mut libc::c_void,
            (fds.len() * std::mem::size_of::<ProcFdInfo>()) as i32,
        )
    };
    if actual <= 0 {
        return vec![];
    }
    let actual_count = actual as usize / std::mem::size_of::<ProcFdInfo>();
    fds.truncate(actual_count);
    fds
}

fn get_socket_info(pid: i32, fd: i32) -> Option<SocketFdInfo> {
    let mut info: SocketFdInfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            &mut info as *mut SocketFdInfo as *mut libc::c_void,
            std::mem::size_of::<SocketFdInfo>() as i32,
        )
    };
    if ret > 0 && ret as usize >= std::mem::size_of::<SocketFdInfo>() {
        Some(info)
    } else {
        None
    }
}

fn get_task_all_info(pid: i32) -> Option<ProcTaskAllInfo> {
    let mut info: ProcTaskAllInfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTASKALLINFO,
            0,
            &mut info as *mut ProcTaskAllInfo as *mut libc::c_void,
            std::mem::size_of::<ProcTaskAllInfo>() as i32,
        )
    };
    if ret > 0 && ret as usize >= std::mem::size_of::<ProcTaskAllInfo>() {
        Some(info)
    } else {
        None
    }
}

fn get_pid_path(pid: i32) -> String {
    let mut buf = [0u8; MAXPATHLEN as usize];
    let ret = unsafe {
        proc_pidpath(
            pid,
            buf.as_mut_ptr() as *mut libc::c_void,
            MAXPATHLEN,
        )
    };
    if ret > 0 {
        String::from_utf8_lossy(&buf[..ret as usize]).to_string()
    } else {
        String::new()
    }
}

fn count_children(pid: i32) -> u32 {
    // First call to get size
    let size = unsafe { proc_listchildpids(pid, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return 0;
    }
    let count = size as usize / std::mem::size_of::<i32>();
    count as u32
}

fn extract_addr(addr_union: &InAddrUnion, vflag: u8) -> IpAddr {
    if vflag & INI_IPV4 != 0 {
        let s_addr = unsafe { addr_union.ina_46.i46a_addr4 };
        IpAddr::V4(Ipv4Addr::from(u32::from_be(s_addr)))
    } else if vflag & INI_IPV6 != 0 {
        let octets = unsafe { addr_union.ina_6 };
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

fn process_name_from_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

// ── Main entry point ─────────────────────────────────────────────────

pub fn get_port_infos(filter_listening: bool) -> Vec<PortInfo> {
    let pids = list_all_pids();
    let mut infos: Vec<PortInfo> = Vec::new();

    for &pid in &pids {
        let fds = list_fds(pid);
        if fds.is_empty() {
            continue;
        }

        // First pass: collect qualifying sockets for this PID
        struct SocketHit {
            protocol: String,
            state: TcpState,
            local_port: u16,
            local_addr: IpAddr,
        }
        let mut hits: Vec<SocketHit> = Vec::new();

        for fd_info in &fds {
            if fd_info.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }

            let sock_info = match get_socket_info(pid, fd_info.proc_fd) {
                Some(s) => s,
                None => continue, // EPERM or other error — silently skip
            };

            let si = &sock_info.psi;

            // Only interested in AF_INET and AF_INET6
            if si.soi_family != libc::AF_INET as i32 && si.soi_family != libc::AF_INET6 as i32 {
                continue;
            }

            let (protocol, state, local_port, local_addr) = if si.soi_kind == SOCKINFO_TCP {
                let tcp: TcpSockInfo = unsafe {
                    std::ptr::read_unaligned(si.soi_proto.as_ptr() as *const TcpSockInfo)
                };
                let state = TcpState::from_tsi(tcp.tcpsi_state);
                let port = u16::from_be(tcp.tcpsi_ini.insi_lport as u16);
                let addr = extract_addr(&tcp.tcpsi_ini.insi_laddr, tcp.tcpsi_ini.insi_vflag);
                ("TCP".to_string(), state, port, addr)
            } else if si.soi_kind == SOCKINFO_IN {
                // UDP socket
                let in_info: InSockInfo = unsafe {
                    std::ptr::read_unaligned(si.soi_proto.as_ptr() as *const InSockInfo)
                };
                let port = u16::from_be(in_info.insi_lport as u16);
                let addr = extract_addr(&in_info.insi_laddr, in_info.insi_vflag);
                // UDP doesn't have LISTEN — treat bound sockets as listening
                ("UDP".to_string(), TcpState::Listen, port, addr)
            } else {
                continue;
            };

            if local_port == 0 {
                continue;
            }

            if filter_listening && state != TcpState::Listen {
                if protocol != "UDP" {
                    continue;
                }
            }

            hits.push(SocketHit { protocol, state, local_port, local_addr });
        }

        if hits.is_empty() {
            continue;
        }

        // Fetch process details once per PID
        let task_info = get_task_all_info(pid);
        let path = get_pid_path(pid);
        let process_name = if !path.is_empty() {
            process_name_from_path(&path)
        } else {
            task_info
                .as_ref()
                .map(|t| cstr_from_bytes(&t.pbsd.pbi_comm))
                .unwrap_or_default()
        };

        let command = if !path.is_empty() {
            path.clone()
        } else {
            format!("[{}]", &process_name)
        };

        let uid = task_info.as_ref().map(|t| t.pbsd.pbi_uid).unwrap_or(0);
        let rss_bytes = task_info
            .as_ref()
            .map(|t| t.ptinfo.pti_resident_size)
            .unwrap_or(0);

        // CPU time in nanoseconds → seconds
        let cpu_ns = task_info
            .as_ref()
            .map(|t| t.ptinfo.pti_total_user + t.ptinfo.pti_total_system)
            .unwrap_or(0);
        let cpu_seconds = cpu_ns as f64 / 1_000_000_000.0;

        let start_time = task_info.as_ref().and_then(|t| {
            if t.pbsd.pbi_start_tvsec > 0 {
                Some(UNIX_EPOCH + Duration::from_secs(t.pbsd.pbi_start_tvsec))
            } else {
                None
            }
        });

        let children = count_children(pid);
        let user = get_username(uid);

        for hit in hits {
            infos.push(PortInfo {
                port: hit.local_port,
                protocol: hit.protocol,
                pid: pid as u32,
                process_name: process_name.clone(),
                command: command.clone(),
                user: user.clone(),
                state: hit.state,
                memory_bytes: rss_bytes,
                cpu_seconds,
                start_time,
                children,
                local_addr: hit.local_addr,
            });
        }
    }

    // Sort by port number
    infos.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.protocol.cmp(&b.protocol)));

    // Deduplicate (same port+proto+pid can appear for v4 and v6)
    infos.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol && a.pid == b.pid);

    infos
}
