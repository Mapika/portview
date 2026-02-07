use clap::Parser;
use colored::Colorize;
use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tabled::settings::Style;
use tabled::{Table, Tabled};

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "portview",
    about = "See what's on your ports, then act on it.",
    version,
    after_help = "Examples:\n  portview          Show all listening ports\n  portview 3000     Inspect port 3000 in detail\n  portview scan     Show all ports in a compact table\n  portview -k 3000  Kill the process on port 3000"
)]
struct Cli {
    /// Port number to inspect, or 'scan' to list all
    target: Option<String>,

    /// Kill the process on the specified port
    #[arg(short, long)]
    kill: Option<u16>,

    /// Force kill (SIGKILL instead of SIGTERM)
    #[arg(short, long)]
    force: bool,

    /// Show all ports including non-listening
    #[arg(short, long)]
    all: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Don't use colors
    #[arg(long)]
    no_color: bool,

    /// Live-refresh the display every second
    #[arg(short, long)]
    watch: bool,

}

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

#[derive(Debug, Clone)]
struct PortInfo {
    port: u16,
    protocol: String,
    pid: u32,
    process_name: String,
    command: String,
    user: String,
    state: TcpState,
    memory_bytes: u64,
    cpu_seconds: f64,
    start_time: Option<SystemTime>,
    children: u32,
    local_addr: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TcpState {
    Listen,
    Established,
    TimeWait,
    CloseWait,
    FinWait1,
    FinWait2,
    SynSent,
    SynRecv,
    Closing,
    LastAck,
    Close,
    Unknown,
}

impl TcpState {
    fn from_hex(s: &str) -> Self {
        match s {
            "0A" => TcpState::Listen,
            "01" => TcpState::Established,
            "06" => TcpState::TimeWait,
            "08" => TcpState::CloseWait,
            "04" => TcpState::FinWait1,
            "05" => TcpState::FinWait2,
            "02" => TcpState::SynSent,
            "03" => TcpState::SynRecv,
            "0B" => TcpState::Closing,
            "09" => TcpState::LastAck,
            "07" => TcpState::Close,
            _ => TcpState::Unknown,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TcpState::Listen => "LISTEN",
            TcpState::Established => "ESTABLISHED",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRecv => "SYN_RECV",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::Close => "CLOSE",
            TcpState::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Tabled)]
struct TableRow {
    #[tabled(rename = "PORT")]
    port: String,
    #[tabled(rename = "PROTO")]
    proto: String,
    #[tabled(rename = "PID")]
    pid: String,
    #[tabled(rename = "USER")]
    user: String,
    #[tabled(rename = "PROCESS")]
    process: String,
    #[tabled(rename = "UPTIME")]
    uptime: String,
    #[tabled(rename = "MEM")]
    memory: String,
    #[tabled(rename = "COMMAND")]
    command: String,
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
                    "07" => TcpState::Listen, // UDP bound/receiving
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
            if let Some(inode_str) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
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

fn get_process_cmdline(pid: u32, max_len: usize) -> String {
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
        // Truncate for display (safe for multi-byte UTF-8)
        if cmd.len() > max_len {
            let mut end = max_len - 1;
            while end > 0 && !cmd.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &cmd[..end])
        } else {
            cmd
        }
    }
}

fn parse_proc_status(pid: u32) -> (u32, u64) {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
    let mut uid = 0u32;
    let mut rss_bytes = 0u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
            rss_bytes = kb * 1024;
        }
    }
    (uid, rss_bytes)
}

fn get_username(uid: u32) -> String {
    let mut buf = vec![0u8; 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let ret = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if ret == 0 && !result.is_null() {
        let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
        name.to_string_lossy().into_owned()
    } else {
        uid.to_string()
    }
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

fn get_clock_ticks() -> u64 {
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 }
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
    let children = fs::read_to_string(format!("/proc/{}/task/{}/children", pid, pid))
        .unwrap_or_default();
    children.split_whitespace().count() as u32
}

// ── Assemble port info ───────────────────────────────────────────────

fn get_port_infos(filter_listening: bool, max_cmd_len: usize) -> Vec<PortInfo> {
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
            protocol: sock.protocol.strip_suffix('6').unwrap_or(&sock.protocol).to_string(),
            pid,
            process_name: get_process_name(pid),
            command: get_process_cmdline(pid, max_cmd_len),
            user: get_username(uid),
            state: sock.state,
            memory_bytes: rss_bytes,
            cpu_seconds,
            start_time,
            children: count_children(pid),
            local_addr: sock.local_addr,
        });
    }

    // Sort by port number
    infos.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.protocol.cmp(&b.protocol)));

    // Deduplicate (same port+proto can appear for v4 and v6)
    infos.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol && a.pid == b.pid);

    infos
}

// ── Formatting helpers ───────────────────────────────────────────────

fn format_uptime(start: Option<SystemTime>) -> String {
    let start = match start {
        Some(s) => s,
        None => return "-".to_string(),
    };

    let elapsed = match SystemTime::now().duration_since(start) {
        Ok(d) => d,
        Err(_) => return "-".to_string(),
    };

    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{}h {}m", h, m)
    } else {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        format!("{}d {}h", d, h)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "-".to_string();
    }
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.0} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_addr(addr: &IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                "*".to_string()
            } else {
                v4.to_string()
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                "*".to_string()
            } else if let Some(v4) = v6.to_ipv4_mapped() {
                if v4.is_unspecified() {
                    "*".to_string()
                } else {
                    v4.to_string()
                }
            } else {
                v6.to_string()
            }
        }
    }
}

// ── Display functions ────────────────────────────────────────────────

fn to_table_row(info: &PortInfo) -> TableRow {
    TableRow {
        port: info.port.to_string(),
        proto: info.protocol.clone(),
        pid: info.pid.to_string(),
        user: info.user.clone(),
        process: info.process_name.clone(),
        uptime: format_uptime(info.start_time),
        memory: format_bytes(info.memory_bytes),
        command: info.command.clone(),
    }
}

fn display_table(infos: &[PortInfo], use_color: bool) {
    if infos.is_empty() {
        if use_color {
            println!("{}", "No listening ports found.".dimmed());
        } else {
            println!("No listening ports found.");
        }
        return;
    }

    let rows: Vec<TableRow> = infos.iter().map(to_table_row).collect();

    let mut table = Table::new(&rows);
    table.with(Style::rounded());
    println!("{}", table);
}

fn display_detail(info: &PortInfo, use_color: bool) {
    let bind_str = format!("{}:{}", format_addr(&info.local_addr), info.port);
    let uptime = format_uptime(info.start_time);

    if use_color {
        println!(
            "\n{} {} ({}) {} {} (PID {})",
            "Port".bold(),
            info.port.to_string().bold().cyan(),
            info.protocol.dimmed(),
            "—".dimmed(),
            info.process_name.bold().green(),
            info.pid.to_string().yellow(),
        );
    } else {
        println!(
            "\nPort {} ({}) — {} (PID {})",
            info.port, info.protocol, info.process_name, info.pid,
        );
    }

    let rows: &[(&str, String)] = &[
        ("Bind:", bind_str),
        ("Command:", info.command.clone()),
        ("User:", info.user.clone()),
        ("Started:", if use_color { uptime.clone() } else { format!("{} ago", uptime) }),
        ("Memory:", format_bytes(info.memory_bytes)),
        ("CPU time:", format!("{:.1}s", info.cpu_seconds)),
        ("Children:", info.children.to_string()),
        ("State:", info.state.to_string()),
    ];

    for (label, value) in rows {
        if use_color {
            println!("  {}  {}", label.dimmed(), value);
        } else {
            println!("  {:<9} {}", label, value);
        }
    }
}

fn prompt_kill(pid: u32, force: bool) -> bool {
    print!("\n  Kill process {}? [y/N] ", pid);
    if io::stdout().flush().is_err() {
        return false;
    }

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    if input.trim().eq_ignore_ascii_case("y") {
        do_kill(pid, force);
        return true;
    }
    false
}

fn do_kill(pid: u32, force: bool) {
    // Guard against special PIDs and overflow on cast to i32
    if pid == 0 {
        eprintln!(
            "  {} Refusing to signal PID 0 (would target entire process group)",
            "✗".red().bold(),
        );
        return;
    }
    if pid > i32::MAX as u32 {
        eprintln!(
            "  {} PID {} exceeds safe range",
            "✗".red().bold(),
            pid
        );
        return;
    }

    let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
    let signal_name = if force { "SIGKILL" } else { "SIGTERM" };

    // Note: TOCTOU — the PID could have been recycled between reading /proc
    // and sending the signal. This is inherent to all kill-by-port tools.
    let result = unsafe { libc::kill(pid as i32, signal) };

    if result == 0 {
        println!(
            "  {} Sent {} to PID {}",
            "✓".green().bold(),
            signal_name,
            pid
        );
    } else {
        let err = io::Error::last_os_error();
        eprintln!(
            "  {} Failed to kill PID {}: {}",
            "✗".red().bold(),
            pid,
            err
        );
    }
}

fn json_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => escaped.push(c),
        }
    }
    escaped
}

fn display_json(infos: &[PortInfo]) {
    print!("[");
    for (i, info) in infos.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(
            r#"{{"port":{},"protocol":"{}","pid":{},"process":"{}","command":"{}","user":"{}","state":"{}","memory_bytes":{},"cpu_seconds":{:.1},"children":{}}}"#,
            info.port,
            json_escape(&info.protocol),
            info.pid,
            json_escape(&info.process_name),
            json_escape(&info.command),
            json_escape(&info.user),
            info.state,
            info.memory_bytes,
            info.cpu_seconds,
            info.children,
        );
    }
    println!("]");
}

// ── Watch-mode helpers ────────────────────────────────────────────────

static RUNNING: AtomicBool = AtomicBool::new(true);

fn enter_alt_screen() {
    print!("\x1B[?1049h");
    let _ = io::stdout().flush();
}

fn leave_alt_screen() {
    print!("\x1B[?1049l");
    let _ = io::stdout().flush();
}

fn clear_screen() {
    print!("\x1B[2J\x1B[H");
    let _ = io::stdout().flush();
}

fn hide_cursor() {
    print!("\x1B[?25l");
    let _ = io::stdout().flush();
}

fn show_cursor() {
    print!("\x1B[?25h");
    let _ = io::stdout().flush();
}

extern "C" fn handle_sigint(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn print_watch_footer(use_color: bool) {
    let now = chrono_free_time();
    let line = format!("Watching every 1s · Updated {} · Ctrl+C to quit", now);
    if use_color {
        println!("\n{}", line.dimmed());
    } else {
        println!("\n{}", line);
    }
}

fn chrono_free_time() -> String {
    // Get wall-clock HH:MM:SS without pulling in chrono
    let secs_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Read local timezone offset from libc
    let offset_secs: i64 = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let time = secs_since_epoch as libc::time_t;
        libc::localtime_r(&time, &mut tm);
        tm.tm_gmtoff
    };

    let local_secs = (secs_since_epoch as i64 + offset_secs) as u64;
    let day_secs = local_secs % 86400;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

// ── Terminal helpers ──────────────────────────────────────────────────

fn get_terminal_width() -> Option<u16> {
    unsafe {
        let mut winsize: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut winsize) == 0
            && winsize.ws_col > 0
        {
            Some(winsize.ws_col)
        } else {
            None
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let use_color = !cli.no_color && atty_stdout();

    if cli.no_color {
        colored::control::set_override(false);
    }

    // --watch + --kill is not allowed
    if cli.watch && cli.kill.is_some() {
        eprintln!("error: --watch and --kill cannot be used together");
        std::process::exit(2);
    }

    // --kill mode (not compatible with watch)
    if let Some(port) = cli.kill {
        let infos = get_port_infos(false, compute_max_cmd_len());
        let matches: Vec<&PortInfo> = infos.iter().filter(|i| i.port == port).collect();

        if matches.is_empty() {
            eprintln!("No process found on port {}", port);
            std::process::exit(1);
        }

        for info in matches {
            display_detail(info, use_color);
            do_kill(info.pid, cli.force);
        }
        return;
    }

    if cli.watch {
        // Register SIGINT handler for clean exit
        unsafe {
            libc::signal(libc::SIGINT, handle_sigint as libc::sighandler_t);
        }
        enter_alt_screen();
        hide_cursor();

        while RUNNING.load(Ordering::SeqCst) {
            clear_screen();
            run_display(&cli, use_color);
            print_watch_footer(use_color);

            // Sleep in small increments so we respond to Ctrl+C quickly
            for _ in 0..20 {
                if !RUNNING.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        show_cursor();
        leave_alt_screen();
    } else {
        run_display(&cli, use_color);
    }
}

fn compute_max_cmd_len() -> usize {
    let cols = get_terminal_width().unwrap_or(143) as usize;
    cols.saturating_sub(83).max(20)
}

fn run_display(cli: &Cli, use_color: bool) {
    let max_cmd_len = compute_max_cmd_len();
    match cli.target.as_deref() {
        None | Some("scan") => {
            // Default: show table of listening ports
            let infos = get_port_infos(!cli.all, max_cmd_len);
            if cli.json {
                display_json(&infos);
            } else {
                if use_color {
                    println!(
                        "\n{}",
                        format!(
                            " {} listening port{} ",
                            infos.len(),
                            if infos.len() == 1 { "" } else { "s" }
                        )
                        .bold()
                    );
                }
                display_table(&infos, use_color);
                if use_color && !infos.is_empty() && !cli.watch {
                    println!(
                        "{}",
                        "  Inspect a port: portview <port>".dimmed()
                    );
                }
            }
        }
        Some(target) => {
            // Try to parse as port number
            if let Ok(port) = target.parse::<u16>() {
                let infos = get_port_infos(false, max_cmd_len);
                let matches: Vec<&PortInfo> = infos.iter().filter(|i| i.port == port).collect();

                if matches.is_empty() {
                    if use_color {
                        println!(
                            "\n  {} Nothing on port {}",
                            "○".dimmed(),
                            port.to_string().bold()
                        );
                    } else {
                        println!("\n  Nothing on port {}", port);
                    }
                    if !cli.watch {
                        std::process::exit(0);
                    }
                    return;
                }

                for info in &matches {
                    display_detail(info, use_color);
                }

                // Offer to kill interactively (only when NOT watching)
                if !cli.watch && matches.len() == 1 && atty_stdout() && atty_stdin() {
                    prompt_kill(matches[0].pid, cli.force);
                }
            } else {
                // Search by process name
                let infos = get_port_infos(!cli.all, max_cmd_len);
                let target_lower = target.to_lowercase();
                let matches: Vec<&PortInfo> = infos
                    .iter()
                    .filter(|i| {
                        i.process_name.to_lowercase().contains(&target_lower)
                            || i.command.to_lowercase().contains(&target_lower)
                    })
                    .collect();

                if matches.is_empty() {
                    if use_color {
                        println!(
                            "\n  {} No ports found for '{}'",
                            "○".dimmed(),
                            target.bold()
                        );
                    } else {
                        println!("\n  No ports found for '{}'", target);
                    }
                    if !cli.watch {
                        std::process::exit(1);
                    }
                } else {
                    if use_color {
                        println!(
                            "\n {} matching '{}'",
                            format!(" {} port{}", matches.len(), if matches.len() == 1 { "" } else { "s" }).bold(),
                            target.cyan()
                        );
                    }

                    let rows: Vec<TableRow> = matches.iter().map(|i| to_table_row(i)).collect();

                    let mut table = Table::new(&rows);
                    table.with(Style::rounded());
                    println!("{}", table);
                }
            }
        }
    }
}

fn atty_stdout() -> bool {
    io::stdout().is_terminal()
}

fn atty_stdin() -> bool {
    io::stdin().is_terminal()
}
