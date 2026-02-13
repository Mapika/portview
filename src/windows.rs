use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    QueryFullProcessImageNameW,
};

use crate::{PortInfo, TcpState};

// ── Socket enumeration ──────────────────────────────────────────────

struct RawSocket {
    protocol: String,
    local_addr: IpAddr,
    local_port: u16,
    state: TcpState,
    pid: u32,
}

fn get_tcp4_sockets() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    // First call to get required buffer size
    let ret = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0, // no sort
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return vec![];
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != 0 {
        return vec![];
    }

    let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table).table.as_ptr() };

    let mut sockets = Vec::with_capacity(count);
    for i in 0..count {
        let row: MIB_TCPROW_OWNER_PID = unsafe { std::ptr::read_unaligned(rows_ptr.add(i)) };
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let addr_bytes = row.dwLocalAddr.to_ne_bytes();
        let addr = IpAddr::V4(Ipv4Addr::new(
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        ));
        sockets.push(RawSocket {
            protocol: "TCP".to_string(),
            local_addr: addr,
            local_port: port,
            state: TcpState::from_mib(row.dwState),
            pid: row.dwOwningPid,
        });
    }
    sockets
}

fn get_tcp6_sockets() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return vec![];
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != 0 {
        return vec![];
    }

    let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table).table.as_ptr() };

    let mut sockets = Vec::with_capacity(count);
    for i in 0..count {
        let row: MIB_TCP6ROW_OWNER_PID = unsafe { std::ptr::read_unaligned(rows_ptr.add(i)) };
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let addr = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
        sockets.push(RawSocket {
            protocol: "TCP".to_string(),
            local_addr: addr,
            local_port: port,
            state: TcpState::from_mib(row.dwState),
            pid: row.dwOwningPid,
        });
    }
    sockets
}

fn get_udp4_sockets() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return vec![];
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != 0 {
        return vec![];
    }

    let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table).table.as_ptr() };

    let mut sockets = Vec::with_capacity(count);
    for i in 0..count {
        let row: MIB_UDPROW_OWNER_PID = unsafe { std::ptr::read_unaligned(rows_ptr.add(i)) };
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let addr_bytes = row.dwLocalAddr.to_ne_bytes();
        let addr = IpAddr::V4(Ipv4Addr::new(
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        ));
        sockets.push(RawSocket {
            protocol: "UDP".to_string(),
            local_addr: addr,
            local_port: port,
            state: TcpState::Listen, // UDP has no state — treat bound as listening
            pid: row.dwOwningPid,
        });
    }
    sockets
}

fn get_udp6_sockets() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return vec![];
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != 0 {
        return vec![];
    }

    let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table).table.as_ptr() };

    let mut sockets = Vec::with_capacity(count);
    for i in 0..count {
        let row: MIB_UDP6ROW_OWNER_PID = unsafe { std::ptr::read_unaligned(rows_ptr.add(i)) };
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let addr = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
        sockets.push(RawSocket {
            protocol: "UDP".to_string(),
            local_addr: addr,
            local_port: port,
            state: TcpState::Listen,
            pid: row.dwOwningPid,
        });
    }
    sockets
}

fn get_all_sockets() -> Vec<RawSocket> {
    let mut sockets = Vec::new();
    sockets.extend(get_tcp4_sockets());
    sockets.extend(get_tcp6_sockets());
    sockets.extend(get_udp4_sockets());
    sockets.extend(get_udp6_sockets());
    sockets
}

// ── Process info helpers ─────────────────────────────────────────────

// FILETIME epoch (1601-01-01) to Unix epoch (1970-01-01) offset in 100ns intervals
const FILETIME_UNIX_OFFSET: u64 = 116444736000000000;

fn filetime_to_u64(ft_low: u32, ft_high: u32) -> u64 {
    ((ft_high as u64) << 32) | (ft_low as u64)
}

fn filetime_to_system_time(ft_low: u32, ft_high: u32) -> Option<SystemTime> {
    let ticks = filetime_to_u64(ft_low, ft_high);
    if ticks < FILETIME_UNIX_OFFSET {
        return None;
    }
    let unix_100ns = ticks - FILETIME_UNIX_OFFSET;
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    Some(UNIX_EPOCH + Duration::new(secs, nanos))
}

fn get_process_name_and_path(handle: HANDLE) -> (String, String) {
    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    let ret = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size) };
    if ret == 0 || size == 0 {
        return (String::new(), String::new());
    }
    let path = String::from_utf16_lossy(&buf[..size as usize]);
    let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
    (name, path)
}

fn get_process_memory(handle: HANDLE) -> u64 {
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ret = unsafe {
        K32GetProcessMemoryInfo(
            handle,
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if ret != 0 {
        counters.WorkingSetSize as u64
    } else {
        0
    }
}

fn get_process_times(handle: HANDLE) -> (Option<SystemTime>, f64) {
    let mut creation = unsafe { std::mem::zeroed() };
    let mut exit = unsafe { std::mem::zeroed() };
    let mut kernel = unsafe { std::mem::zeroed() };
    let mut user = unsafe { std::mem::zeroed() };

    let ret = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    if ret == 0 {
        return (None, 0.0);
    }

    let start_time = filetime_to_system_time(creation.dwLowDateTime, creation.dwHighDateTime);

    // CPU time = kernel + user, both in 100ns intervals
    let kernel_ticks = filetime_to_u64(kernel.dwLowDateTime, kernel.dwHighDateTime);
    let user_ticks = filetime_to_u64(user.dwLowDateTime, user.dwHighDateTime);
    let cpu_seconds = (kernel_ticks + user_ticks) as f64 / 10_000_000.0;

    (start_time, cpu_seconds)
}

fn get_process_username(handle: HANDLE) -> String {
    let mut token: HANDLE = std::ptr::null_mut();
    let ret = unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) };
    if ret == 0 {
        return String::new();
    }

    // Get required buffer size for TOKEN_USER
    let mut size: u32 = 0;
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size) };
    if size == 0 {
        unsafe { CloseHandle(token) };
        return String::new();
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut size,
        )
    };
    if ret == 0 {
        unsafe { CloseHandle(token) };
        return String::new();
    }

    let token_user = buf.as_ptr() as *const TOKEN_USER;
    let sid = unsafe { (*token_user).User.Sid };

    let mut name_buf = [0u16; 256];
    let mut name_len = name_buf.len() as u32;
    let mut domain_buf = [0u16; 256];
    let mut domain_len = domain_buf.len() as u32;
    let mut sid_type = 0u32;

    let ret = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type as *mut u32 as *mut _,
        )
    };

    unsafe { CloseHandle(token) };

    if ret != 0 && name_len > 0 {
        String::from_utf16_lossy(&name_buf[..name_len as usize])
    } else {
        String::new()
    }
}

fn build_child_count_map() -> HashMap<u32, u32> {
    let mut children_count: HashMap<u32, u32> = HashMap::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return children_count;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            if entry.th32ParentProcessID != 0 {
                *children_count.entry(entry.th32ParentProcessID).or_insert(0) += 1;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    children_count
}

// ── Main entry point ─────────────────────────────────────────────────

pub fn get_port_infos(filter_listening: bool) -> Vec<PortInfo> {
    let sockets = get_all_sockets();
    let child_map = build_child_count_map();

    // Group sockets by PID to avoid opening the same process multiple times
    let mut pid_sockets: HashMap<u32, Vec<&RawSocket>> = HashMap::new();
    for sock in &sockets {
        if sock.local_port == 0 {
            continue;
        }
        if filter_listening && sock.state != TcpState::Listen {
            if sock.protocol != "UDP" {
                continue;
            }
        }
        pid_sockets.entry(sock.pid).or_default().push(sock);
    }

    let mut infos: Vec<PortInfo> = Vec::new();

    for (&pid, socks) in &pid_sockets {
        if pid == 0 {
            continue; // System Idle Process
        }

        // Open process handle — skip protected/system processes we can't access
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            // Try with limited access for name only
            let limited = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
            if limited.is_null() {
                // Can't access this process at all — emit entries with minimal info
                for sock in socks {
                    infos.push(PortInfo {
                        port: sock.local_port,
                        protocol: sock.protocol.clone(),
                        pid,
                        process_name: String::new(),
                        command: String::new(),
                        user: String::new(),
                        state: sock.state,
                        memory_bytes: 0,
                        cpu_seconds: 0.0,
                        start_time: None,
                        children: child_map.get(&pid).copied().unwrap_or(0),
                        local_addr: sock.local_addr,
                    });
                }
                continue;
            }

            let (name, path) = get_process_name_and_path(limited);
            let (start_time, cpu_seconds) = get_process_times(limited);
            let user = get_process_username(limited);
            let children = child_map.get(&pid).copied().unwrap_or(0);
            unsafe { CloseHandle(limited) };

            for sock in socks {
                infos.push(PortInfo {
                    port: sock.local_port,
                    protocol: sock.protocol.clone(),
                    pid,
                    process_name: name.clone(),
                    command: if path.is_empty() {
                        format!("[{}]", name)
                    } else {
                        path.clone()
                    },
                    user: user.clone(),
                    state: sock.state,
                    memory_bytes: 0, // Can't read without PROCESS_VM_READ
                    cpu_seconds,
                    start_time,
                    children,
                    local_addr: sock.local_addr,
                });
            }
            continue;
        }

        let (name, path) = get_process_name_and_path(handle);
        let memory_bytes = get_process_memory(handle);
        let (start_time, cpu_seconds) = get_process_times(handle);
        let user = get_process_username(handle);
        let children = child_map.get(&pid).copied().unwrap_or(0);

        unsafe { CloseHandle(handle) };

        let command = if path.is_empty() {
            format!("[{}]", name)
        } else {
            path
        };

        for sock in socks {
            infos.push(PortInfo {
                port: sock.local_port,
                protocol: sock.protocol.clone(),
                pid,
                process_name: name.clone(),
                command: command.clone(),
                user: user.clone(),
                state: sock.state,
                memory_bytes,
                cpu_seconds,
                start_time,
                children,
                local_addr: sock.local_addr,
            });
        }
    }

    // Drop entries where we couldn't read process details (other user's process without elevated privileges)
    infos.retain(|i| !i.process_name.is_empty());

    // Sort by port number, then protocol, then pid (pid needed for dedup_by adjacency)
    infos.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    // Deduplicate (same port+proto+pid can appear for v4 and v6)
    infos.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol && a.pid == b.pid);

    infos
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── filetime_to_u64 ─────────────────────────────────────────────

    #[test]
    fn filetime_to_u64_zero() {
        assert_eq!(filetime_to_u64(0, 0), 0);
    }

    #[test]
    fn filetime_to_u64_low_only() {
        assert_eq!(filetime_to_u64(42, 0), 42);
    }

    #[test]
    fn filetime_to_u64_high_only() {
        assert_eq!(filetime_to_u64(0, 1), 0x100000000);
    }

    #[test]
    fn filetime_to_u64_max() {
        assert_eq!(filetime_to_u64(u32::MAX, u32::MAX), u64::MAX);
    }

    #[test]
    fn filetime_to_u64_combined() {
        assert_eq!(
            filetime_to_u64(0x0000_0001, 0x0000_0002),
            0x0000_0002_0000_0001
        );
    }

    // ── filetime_to_system_time ─────────────────────────────────────

    #[test]
    fn filetime_to_system_time_zero() {
        assert_eq!(filetime_to_system_time(0, 0), None);
    }

    #[test]
    fn filetime_to_system_time_before_unix_epoch() {
        // Any value below FILETIME_UNIX_OFFSET should return None
        assert_eq!(filetime_to_system_time(1, 0), None);
    }

    #[test]
    fn filetime_to_system_time_unix_epoch() {
        // FILETIME_UNIX_OFFSET = 116444736000000000 = 0x019DB1DED53E8000
        let low = (FILETIME_UNIX_OFFSET & 0xFFFFFFFF) as u32;
        let high = (FILETIME_UNIX_OFFSET >> 32) as u32;
        let result = filetime_to_system_time(low, high);
        assert_eq!(result, Some(UNIX_EPOCH));
    }

    #[test]
    fn filetime_to_system_time_far_future_no_panic() {
        // Should not panic even with very large values
        let result = filetime_to_system_time(u32::MAX, u32::MAX);
        assert!(result.is_some());
    }

    #[test]
    fn filetime_to_system_time_one_second_after_epoch() {
        // Unix epoch + 1 second = FILETIME_UNIX_OFFSET + 10_000_000 (100ns intervals)
        let ft = FILETIME_UNIX_OFFSET + 10_000_000;
        let low = (ft & 0xFFFFFFFF) as u32;
        let high = (ft >> 32) as u32;
        let result = filetime_to_system_time(low, high);
        let expected = UNIX_EPOCH + Duration::from_secs(1);
        assert_eq!(result, Some(expected));
    }
}
