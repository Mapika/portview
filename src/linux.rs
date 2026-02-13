use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{PortInfo, TcpState, get_clock_ticks, get_username};

// ── Data types ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SocketEntry {
    protocol: String,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    state: TcpState,
    inode: u64,
}

// ── /proc parsers ────────────────────────────────────────────────────

fn parse_hex_addr_v4(hex: &str) -> IpAddr {
    let n = u32::from_str_radix(hex, 16).unwrap_or(0);
    IpAddr::V4(Ipv4Addr::from(n.to_be()))
}

fn parse_hex_addr_v6(hex: &str) -> IpAddr {
    if hex.len() != 32 {
        return IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    }
    // Linux stores IPv6 as 4 groups of little-endian 32-bit integers
    let mut octets = [0u8; 16];
    for group in 0..4 {
        let offset = group * 8;
        let word = u32::from_str_radix(&hex[offset..offset + 8], 16).unwrap_or(0);
        let bytes = word.to_be_bytes();
        // Each 4-byte group is stored in network byte order after endian swap
        let base = group * 4;
        octets[base] = bytes[3];
        octets[base + 1] = bytes[2];
        octets[base + 2] = bytes[1];
        octets[base + 3] = bytes[0];
    }
    IpAddr::V6(Ipv6Addr::from(octets))
}

fn parse_addr_port(s: &str, ipv6: bool) -> (IpAddr, u16) {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 2 {
        return if ipv6 {
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
    }
    let port = u16::from_str_radix(parts[parts.len() - 1], 16).unwrap_or(0);
    let addr_hex = &s[..s.rfind(':').unwrap()];
    let addr = if ipv6 {
        parse_hex_addr_v6(addr_hex)
    } else {
        parse_hex_addr_v4(addr_hex)
    };
    (addr, port)
}

fn parse_proc_net(path: &str, protocol: &str, ipv6: bool) -> Vec<SocketEntry> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let is_udp = protocol.starts_with("UDP");

    content
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return None;
            }

            let (local_addr, local_port) = parse_addr_port(fields[1], ipv6);
            let (remote_addr, remote_port) = parse_addr_port(fields[2], ipv6);
            let state = if is_udp {
                match fields[3] {
                    "07" => TcpState::Listen,      // UDP bound/receiving
                    "01" => TcpState::Established, // UDP connected via connect()
                    _ => TcpState::Unknown,
                }
            } else {
                TcpState::from_hex(fields[3])
            };
            let inode = fields[9].parse::<u64>().unwrap_or(0);

            if inode == 0 {
                return None;
            }

            Some(SocketEntry {
                protocol: protocol.to_string(),
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                inode,
            })
        })
        .collect()
}

fn get_all_sockets() -> Vec<SocketEntry> {
    let mut sockets = Vec::new();
    sockets.extend(parse_proc_net("/proc/net/tcp", "TCP", false));
    sockets.extend(parse_proc_net("/proc/net/tcp6", "TCP6", true));
    sockets.extend(parse_proc_net("/proc/net/udp", "UDP", false));
    sockets.extend(parse_proc_net("/proc/net/udp6", "UDP6", true));
    sockets
}

fn build_inode_to_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let pid: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_path = format!("/proc/{}/fd", pid);
        let fd_dir = match fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let link_str = link.to_string_lossy();
            if let Some(inode_str) = link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    map.insert(inode, pid);
                }
            }
        }
    }

    map
}

// ── Process info ─────────────────────────────────────────────────────

fn get_process_name(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn get_process_cmdline(pid: u32) -> String {
    let raw = fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
    let cmd: String = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect::<Vec<_>>()
        .join(" ");

    if cmd.is_empty() {
        format!("[{}]", get_process_name(pid))
    } else {
        cmd
    }
}

fn parse_proc_status(pid: u32) -> (u32, u64) {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
    let mut uid = 0u32;
    let mut rss_bytes = 0u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            rss_bytes = kb * 1024;
        }
    }
    (uid, rss_bytes)
}

fn get_boot_time() -> u64 {
    let stat = fs::read_to_string("/proc/stat").unwrap_or_default();
    for line in stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn parse_proc_stat(pid: u32, boot_time: u64, clock_ticks: u64) -> (Option<SystemTime>, f64) {
    let stat = match fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(s) => s,
        Err(_) => return (None, 0.0),
    };
    let after_comm = match stat.rfind(')') {
        Some(pos) => pos + 2,
        None => return (None, 0.0),
    };
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();

    // CPU time: utime (field 11) + stime (field 12)
    let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let cpu_seconds = if clock_ticks > 0 {
        (utime + stime) as f64 / clock_ticks as f64
    } else {
        0.0
    };

    // Start time: field 19 (starttime in ticks since boot)
    let start_time = fields
        .get(19)
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|ticks| {
            if clock_ticks == 0 {
                return None;
            }
            let start_secs = boot_time + (ticks / clock_ticks);
            Some(UNIX_EPOCH + Duration::from_secs(start_secs))
        });

    (start_time, cpu_seconds)
}

fn count_children(pid: u32) -> u32 {
    let children =
        fs::read_to_string(format!("/proc/{}/task/{}/children", pid, pid)).unwrap_or_default();
    children.split_whitespace().count() as u32
}

// ── Assemble port info ───────────────────────────────────────────────

pub fn get_port_infos(filter_listening: bool) -> Vec<PortInfo> {
    let sockets = get_all_sockets();
    let inode_map = build_inode_to_pid_map();
    let boot_time = get_boot_time();
    let clock_ticks = get_clock_ticks();

    let mut infos: Vec<PortInfo> = Vec::new();

    for sock in &sockets {
        if filter_listening && sock.state != TcpState::Listen {
            // For UDP, show all bound sockets since UDP doesn't have LISTEN state
            if !sock.protocol.starts_with("UDP") {
                continue;
            }
        }

        if sock.local_port == 0 {
            continue;
        }

        let pid = match inode_map.get(&sock.inode) {
            Some(&p) => p,
            None => continue,
        };

        let (uid, rss_bytes) = parse_proc_status(pid);
        let (start_time, cpu_seconds) = parse_proc_stat(pid, boot_time, clock_ticks);

        infos.push(PortInfo {
            port: sock.local_port,
            protocol: sock
                .protocol
                .strip_suffix('6')
                .unwrap_or(&sock.protocol)
                .to_string(),
            pid,
            process_name: get_process_name(pid),
            command: get_process_cmdline(pid),
            user: get_username(uid),
            state: sock.state,
            memory_bytes: rss_bytes,
            cpu_seconds,
            start_time,
            children: count_children(pid),
            local_addr: sock.local_addr,
        });
    }

    // Drop entries where we couldn't read process details (other user's process without sudo)
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

    // ── parse_hex_addr_v4 ───────────────────────────────────────────

    #[test]
    fn parse_hex_addr_v4_loopback() {
        // 0100007F = 127.0.0.1 in little-endian hex
        let addr = parse_hex_addr_v4("0100007F");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn parse_hex_addr_v4_unspecified() {
        let addr = parse_hex_addr_v4("00000000");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn parse_hex_addr_v4_192_168_1_1() {
        // 0101A8C0 = 192.168.1.1 in little-endian hex
        let addr = parse_hex_addr_v4("0101A8C0");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_hex_addr_v4_broadcast() {
        let addr = parse_hex_addr_v4("FFFFFFFF");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn parse_hex_addr_v4_invalid_hex() {
        let addr = parse_hex_addr_v4("ZZZZZZZZ");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    // ── parse_hex_addr_v6 ───────────────────────────────────────────

    #[test]
    fn parse_hex_addr_v6_unspecified() {
        let addr = parse_hex_addr_v6("00000000000000000000000000000000");
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn parse_hex_addr_v6_loopback() {
        // ::1 in Linux /proc format (4 groups of LE 32-bit words)
        let addr = parse_hex_addr_v6("00000000000000000000000001000000");
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn parse_hex_addr_v6_short_input() {
        let addr = parse_hex_addr_v6("0000");
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn parse_hex_addr_v6_empty() {
        let addr = parse_hex_addr_v6("");
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    // ── parse_addr_port ─────────────────────────────────────────────

    #[test]
    fn parse_addr_port_v4_loopback_80() {
        let (addr, port) = parse_addr_port("0100007F:0050", false);
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_addr_port_v6_any_443() {
        let (addr, port) = parse_addr_port("00000000000000000000000000000000:01BB", true);
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_addr_port_no_colon_v4() {
        let (addr, port) = parse_addr_port("nocolon", false);
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port, 0);
    }

    #[test]
    fn parse_addr_port_no_colon_v6() {
        let (addr, port) = parse_addr_port("nocolon", true);
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(port, 0);
    }

    #[test]
    fn parse_addr_port_bad_port() {
        let (_, port) = parse_addr_port("0100007F:ZZZZ", false);
        assert_eq!(port, 0);
    }
}
