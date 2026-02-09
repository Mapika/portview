use clap::Parser;
use colored::Colorize;
use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tabled::settings::object::Columns;
use tabled::settings::{Modify, Style, Width};
use tabled::{Table, Tabled};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::get_port_infos;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::get_port_infos;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::get_port_infos;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("portview only supports Linux, macOS, and Windows");

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

    /// Don't truncate the command column (use full terminal width)
    #[arg(long)]
    wide: bool,
}

// ── Data types ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct PortInfo {
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) pid: u32,
    pub(crate) process_name: String,
    pub(crate) command: String,
    pub(crate) user: String,
    pub(crate) state: TcpState,
    pub(crate) memory_bytes: u64,
    pub(crate) cpu_seconds: f64,
    pub(crate) start_time: Option<SystemTime>,
    pub(crate) children: u32,
    pub(crate) local_addr: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum TcpState {
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
    #[cfg(target_os = "linux")]
    pub(crate) fn from_hex(s: &str) -> Self {
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

    #[cfg(target_os = "macos")]
    pub(crate) fn from_tsi(state: i32) -> Self {
        // TSI_S_* constants from XNU's proc_info.h
        match state {
            0 => TcpState::Close,       // TSI_S_CLOSED
            1 => TcpState::Listen,      // TSI_S_LISTEN
            2 => TcpState::SynSent,     // TSI_S_SYN_SENT
            3 => TcpState::SynRecv,     // TSI_S_SYN_RECEIVED
            4 => TcpState::Established, // TSI_S_ESTABLISHED
            5 => TcpState::CloseWait,   // TSI_S_CLOSE_WAIT
            6 => TcpState::FinWait1,    // TSI_S_FIN_WAIT_1
            7 => TcpState::Closing,     // TSI_S_CLOSING
            8 => TcpState::LastAck,     // TSI_S_LAST_ACK
            9 => TcpState::FinWait2,    // TSI_S_FIN_WAIT_2
            10 => TcpState::TimeWait,   // TSI_S_TIME_WAIT
            _ => TcpState::Unknown,
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn from_mib(state: u32) -> Self {
        // MIB_TCP_STATE_* from iprtrmib.h
        match state {
            1 => TcpState::Close,       // MIB_TCP_STATE_CLOSED
            2 => TcpState::Listen,      // MIB_TCP_STATE_LISTEN
            3 => TcpState::SynSent,     // MIB_TCP_STATE_SYN_SENT
            4 => TcpState::SynRecv,     // MIB_TCP_STATE_SYN_RCVD
            5 => TcpState::Established, // MIB_TCP_STATE_ESTAB
            6 => TcpState::FinWait1,    // MIB_TCP_STATE_FIN_WAIT1
            7 => TcpState::FinWait2,    // MIB_TCP_STATE_FIN_WAIT2
            8 => TcpState::CloseWait,   // MIB_TCP_STATE_CLOSE_WAIT
            9 => TcpState::Closing,     // MIB_TCP_STATE_CLOSING
            10 => TcpState::LastAck,    // MIB_TCP_STATE_LAST_ACK
            11 => TcpState::TimeWait,   // MIB_TCP_STATE_TIME_WAIT
            12 => TcpState::Close,      // MIB_TCP_STATE_DELETE_TCB
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

// ── Shared helpers ───────────────────────────────────────────────────

#[cfg(unix)]
pub(crate) fn get_username(uid: u32) -> String {
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

#[cfg(target_os = "linux")]
pub(crate) fn get_clock_ticks() -> u64 {
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 }
}

// ── Formatting helpers ───────────────────────────────────────────────

pub(crate) fn format_uptime(start: Option<SystemTime>) -> String {
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

pub(crate) fn format_bytes(bytes: u64) -> String {
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

fn truncate_cmd(cmd: &str, max_len: usize) -> String {
    if cmd.len() > max_len {
        let mut end = max_len.saturating_sub(1);
        while end > 0 && !cmd.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &cmd[..end])
    } else {
        cmd.to_string()
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

// ── Color config ─────────────────────────────────────────────────────

struct ColorConfig {
    port: String,
    proto: String,
    pid: String,
    user: String,
    process: String,
    uptime: String,
    mem: String,
    command: String,
}

impl Default for ColorConfig {
    fn default() -> Self {
        Self {
            port: "cyan".into(),
            proto: "dimmed".into(),
            pid: "yellow".into(),
            user: "green".into(),
            process: "bold".into(),
            uptime: "dimmed".into(),
            mem: "dimmed".into(),
            command: "white".into(),
        }
    }
}

impl ColorConfig {
    fn from_env() -> Self {
        let mut config = Self::default();
        let val = match std::env::var("PORTVIEW_COLORS") {
            Ok(v) => v,
            Err(_) => return config,
        };
        for pair in val.split(',') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                if !is_valid_color(value) {
                    continue;
                }
                match key {
                    "port" => config.port = value.into(),
                    "proto" => config.proto = value.into(),
                    "pid" => config.pid = value.into(),
                    "user" => config.user = value.into(),
                    "process" => config.process = value.into(),
                    "uptime" => config.uptime = value.into(),
                    "mem" => config.mem = value.into(),
                    "command" => config.command = value.into(),
                    _ => {}
                }
            }
        }
        config
    }
}

fn is_valid_color(s: &str) -> bool {
    matches!(
        s,
        "red"
            | "green"
            | "blue"
            | "cyan"
            | "yellow"
            | "magenta"
            | "white"
            | "bold"
            | "dimmed"
            | "bright_red"
            | "bright_green"
            | "bright_blue"
            | "bright_cyan"
            | "bright_yellow"
            | "bright_magenta"
            | "bright_white"
            | "none"
    )
}

fn apply_color(s: &str, color: &str) -> String {
    match color {
        "red" => s.red().to_string(),
        "green" => s.green().to_string(),
        "blue" => s.blue().to_string(),
        "cyan" => s.cyan().to_string(),
        "yellow" => s.yellow().to_string(),
        "magenta" => s.magenta().to_string(),
        "white" => s.white().to_string(),
        "bold" => s.bold().to_string(),
        "dimmed" => s.dimmed().to_string(),
        "bright_red" => s.bright_red().to_string(),
        "bright_green" => s.bright_green().to_string(),
        "bright_blue" => s.bright_blue().to_string(),
        "bright_cyan" => s.bright_cyan().to_string(),
        "bright_yellow" => s.bright_yellow().to_string(),
        "bright_magenta" => s.bright_magenta().to_string(),
        "bright_white" => s.bright_white().to_string(),
        _ => s.to_string(),
    }
}

// ── Display functions ────────────────────────────────────────────────

fn to_table_row(info: &PortInfo, colors: &ColorConfig) -> TableRow {
    TableRow {
        port: apply_color(&info.port.to_string(), &colors.port),
        proto: apply_color(&info.protocol, &colors.proto),
        pid: apply_color(&info.pid.to_string(), &colors.pid),
        user: apply_color(&info.user, &colors.user),
        process: apply_color(&info.process_name, &colors.process),
        uptime: apply_color(&format_uptime(info.start_time), &colors.uptime),
        memory: apply_color(&format_bytes(info.memory_bytes), &colors.mem),
        command: apply_color(&info.command, &colors.command),
    }
}

fn display_table(
    infos: &[PortInfo],
    use_color: bool,
    colors: &ColorConfig,
    wide: bool,
    cmd_width: usize,
) {
    if infos.is_empty() {
        if use_color {
            println!("{}", "No listening ports found.".dimmed());
        } else {
            println!("No listening ports found.");
        }
        return;
    }

    let rows: Vec<TableRow> = infos.iter().map(|i| to_table_row(i, colors)).collect();

    let mut table = Table::new(&rows);
    table.with(Style::rounded());
    if wide {
        table.with(Modify::new(Columns::last()).with(Width::wrap(cmd_width)));
    }
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
        (
            "Started:",
            if use_color {
                uptime.clone()
            } else {
                format!("{} ago", uptime)
            },
        ),
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

#[cfg(unix)]
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
        eprintln!("  {} PID {} exceeds safe range", "✗".red().bold(), pid);
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
        eprintln!("  {} Failed to kill PID {}: {}", "✗".red().bold(), pid, err);
    }
}

#[cfg(windows)]
fn do_kill(pid: u32, _force: bool) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    if pid == 0 {
        eprintln!("  {} Refusing to terminate PID 0", "✗".red().bold(),);
        return;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            let err = io::Error::last_os_error();
            eprintln!("  {} Failed to open PID {}: {}", "✗".red().bold(), pid, err);
            return;
        }

        // Windows has no graceful SIGTERM equivalent — always force-terminates
        let result = TerminateProcess(handle, 1);
        CloseHandle(handle);

        if result != 0 {
            println!("  {} Terminated PID {}", "✓".green().bold(), pid);
        } else {
            let err = io::Error::last_os_error();
            eprintln!(
                "  {} Failed to terminate PID {}: {}",
                "✗".red().bold(),
                pid,
                err
            );
        }
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

fn cursor_home() {
    print!("\x1B[H");
    let _ = io::stdout().flush();
}

fn erase_below() {
    print!("\x1B[J");
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

#[cfg(unix)]
extern "C" fn handle_sigint(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

#[cfg(windows)]
unsafe extern "system" fn handle_ctrl(ctrl_type: u32) -> i32 {
    // CTRL_C_EVENT = 0, CTRL_BREAK_EVENT = 1
    if ctrl_type == 0 || ctrl_type == 1 {
        RUNNING.store(false, Ordering::SeqCst);
        1 // TRUE — handled
    } else {
        0 // FALSE — pass to next handler
    }
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

#[cfg(unix)]
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

#[cfg(windows)]
fn chrono_free_time() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;

    let mut st = unsafe { std::mem::zeroed::<windows_sys::Win32::Foundation::SYSTEMTIME>() };
    unsafe { GetLocalTime(&mut st) };
    format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
}

// ── Terminal helpers ──────────────────────────────────────────────────

#[cfg(unix)]
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

#[cfg(windows)]
fn get_terminal_width() -> Option<u16> {
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };

    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() {
            return None;
        }
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) != 0 {
            let width = info.srWindow.Right - info.srWindow.Left + 1;
            if width > 0 {
                Some(width as u16)
            } else {
                None
            }
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

    let colors = ColorConfig::from_env();

    // --watch + --kill is not allowed
    if cli.watch && cli.kill.is_some() {
        eprintln!("error: --watch and --kill cannot be used together");
        std::process::exit(2);
    }

    // --kill mode (not compatible with watch)
    if let Some(port) = cli.kill {
        let infos = get_port_infos(false);
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
        // Register signal/ctrl handler for clean exit
        #[cfg(unix)]
        unsafe {
            libc::signal(
                libc::SIGINT,
                handle_sigint as *const () as libc::sighandler_t,
            );
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
                Some(handle_ctrl),
                1, // TRUE — add handler
            );
        }

        if cli.json {
            // JSON watch: emit one JSON array per tick, no terminal escapes
            while RUNNING.load(Ordering::SeqCst) {
                if write_display_safe(&cli, use_color, &colors).is_err() {
                    break; // broken pipe
                }

                for _ in 0..20 {
                    if !RUNNING.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        } else {
            enter_alt_screen();
            hide_cursor();

            while RUNNING.load(Ordering::SeqCst) {
                // Synchronized update: terminal buffers all output between
                // begin/end markers and renders in a single
                // frame — no flicker even though we clear the screen.
                print!("\x1B[?2026h");
                cursor_home();
                erase_below();
                run_display(&cli, use_color, &colors);
                print_watch_footer(use_color);
                print!("\x1B[?2026l");
                let _ = io::stdout().flush();

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
        }
    } else {
        run_display(&cli, use_color, &colors);
    }
}

/// Compute available width for the command column based on actual data.
/// Accounts for the real widths of all other columns + table borders/padding.
fn compute_cmd_width(infos: &[PortInfo]) -> usize {
    let cols = get_terminal_width().unwrap_or(143) as usize;

    if infos.is_empty() {
        return cols.saturating_sub(83).max(20);
    }

    // Measure the max content width of each non-command column (min = header width)
    let port_w = infos
        .iter()
        .map(|i| i.port.to_string().len())
        .max()
        .unwrap_or(0)
        .max(4); // "PORT"
    let proto_w = infos
        .iter()
        .map(|i| i.protocol.len())
        .max()
        .unwrap_or(0)
        .max(5); // "PROTO"
    let pid_w = infos
        .iter()
        .map(|i| i.pid.to_string().len())
        .max()
        .unwrap_or(0)
        .max(3); // "PID"
    let user_w = infos.iter().map(|i| i.user.len()).max().unwrap_or(0).max(4); // "USER"
    let process_w = infos
        .iter()
        .map(|i| i.process_name.len())
        .max()
        .unwrap_or(0)
        .max(7); // "PROCESS"
    let uptime_w = infos
        .iter()
        .map(|i| format_uptime(i.start_time).len())
        .max()
        .unwrap_or(0)
        .max(6); // "UPTIME"
    let mem_w = infos
        .iter()
        .map(|i| format_bytes(i.memory_bytes).len())
        .max()
        .unwrap_or(0)
        .max(3); // "MEM"

    let data_width = port_w + proto_w + pid_w + user_w + process_w + uptime_w + mem_w;

    // Rounded style: 9 vertical borders + 1 space padding on each side of each of 8 columns
    let chrome = 9 + (8 * 2);

    cols.saturating_sub(data_width + chrome).max(20)
}

/// Run display and catch broken pipe errors (for piped JSON watch mode).
fn write_display_safe(cli: &Cli, use_color: bool, colors: &ColorConfig) -> io::Result<()> {
    run_display(cli, use_color, colors);
    io::stdout().flush()
}

fn run_display(cli: &Cli, use_color: bool, colors: &ColorConfig) {
    match cli.target.as_deref() {
        None | Some("scan") => {
            // Default: show table of listening ports
            let mut infos = get_port_infos(!cli.all);
            if cli.json {
                display_json(&infos);
            } else {
                let cmd_width = compute_cmd_width(&infos);
                if !cli.wide {
                    for info in &mut infos {
                        info.command = truncate_cmd(&info.command, cmd_width);
                    }
                }
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
                display_table(&infos, use_color, colors, cli.wide, cmd_width);
                if use_color && !infos.is_empty() && !cli.watch {
                    println!("{}", "  Inspect a port: portview <port>".dimmed());
                }
            }
        }
        Some(target) => {
            // Try to parse as port number
            if let Ok(port) = target.parse::<u16>() {
                let infos = get_port_infos(false);
                let matches: Vec<&PortInfo> = infos.iter().filter(|i| i.port == port).collect();

                if matches.is_empty() {
                    if cli.json {
                        println!("[]");
                    } else if use_color {
                        println!(
                            "\n  {} Nothing on port {}",
                            "○".dimmed(),
                            port.to_string().bold()
                        );
                    } else {
                        println!("\n  Nothing on port {}", port);
                    }
                    if !cli.watch {
                        std::process::exit(1);
                    }
                    return;
                }

                if cli.json {
                    let owned: Vec<PortInfo> = matches.into_iter().cloned().collect();
                    display_json(&owned);
                } else {
                    for info in &matches {
                        display_detail(info, use_color);
                    }

                    // Offer to kill interactively (only when NOT watching)
                    if !cli.watch && matches.len() == 1 && atty_stdout() && atty_stdin() {
                        prompt_kill(matches[0].pid, cli.force);
                    }
                }
            } else {
                // Search by process name — filter on full command, then truncate for display
                let mut infos = get_port_infos(!cli.all);
                let target_lower = target.to_lowercase();
                let mut matches: Vec<PortInfo> = infos
                    .drain(..)
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
                } else if cli.json {
                    display_json(&matches);
                } else {
                    let cmd_width = compute_cmd_width(&matches);
                    if !cli.wide {
                        for info in &mut matches {
                            info.command = truncate_cmd(&info.command, cmd_width);
                        }
                    }
                    if use_color {
                        println!(
                            "\n {} matching '{}'",
                            format!(
                                " {} port{}",
                                matches.len(),
                                if matches.len() == 1 { "" } else { "s" }
                            )
                            .bold(),
                            target.cyan()
                        );
                    }

                    display_table(&matches, use_color, colors, cli.wide, cmd_width);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── format_bytes ────────────────────────────────────────────────

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "-");
    }

    #[test]
    fn format_bytes_bytes_range() {
        assert_eq!(format_bytes(1), "1 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kb_range() {
        assert_eq!(format_bytes(1024), "1 KB");
        assert_eq!(format_bytes(1536), "2 KB"); // rounds
        assert_eq!(format_bytes(1024 * 1024 - 1), "1024 KB");
    }

    #[test]
    fn format_bytes_mb_range() {
        assert_eq!(format_bytes(1024 * 1024), "1 MB");
        assert_eq!(format_bytes(500 * 1024 * 1024), "500 MB");
    }

    #[test]
    fn format_bytes_gb_range() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    #[test]
    fn format_bytes_u64_max_no_panic() {
        let result = format_bytes(u64::MAX);
        assert!(result.contains("GB"));
    }

    // ── json_escape ─────────────────────────────────────────────────

    #[test]
    fn json_escape_plain() {
        assert_eq!(json_escape("hello world"), "hello world");
    }

    #[test]
    fn json_escape_empty() {
        assert_eq!(json_escape(""), "");
    }

    #[test]
    fn json_escape_quote() {
        assert_eq!(json_escape(r#"say "hi""#), r#"say \"hi\""#);
    }

    #[test]
    fn json_escape_backslash() {
        assert_eq!(json_escape(r"a\b"), r"a\\b");
    }

    #[test]
    fn json_escape_newline() {
        assert_eq!(json_escape("a\nb"), r"a\nb");
    }

    #[test]
    fn json_escape_carriage_return() {
        assert_eq!(json_escape("a\rb"), r"a\rb");
    }

    #[test]
    fn json_escape_tab() {
        assert_eq!(json_escape("a\tb"), r"a\tb");
    }

    #[test]
    fn json_escape_control_char() {
        assert_eq!(json_escape("\x01"), r"\u0001");
    }

    #[test]
    fn json_escape_null() {
        assert_eq!(json_escape("\0"), r"\u0000");
    }

    #[test]
    fn json_escape_mixed() {
        assert_eq!(json_escape("a\"b\\c\nd"), r#"a\"b\\c\nd"#);
    }

    #[test]
    fn json_escape_unicode_passthrough() {
        assert_eq!(json_escape("café ☕"), "café ☕");
    }

    // ── is_valid_color ──────────────────────────────────────────────

    #[test]
    fn is_valid_color_all_valid() {
        let valid = [
            "red",
            "green",
            "blue",
            "cyan",
            "yellow",
            "magenta",
            "white",
            "bold",
            "dimmed",
            "bright_red",
            "bright_green",
            "bright_blue",
            "bright_cyan",
            "bright_yellow",
            "bright_magenta",
            "bright_white",
            "none",
        ];
        for c in &valid {
            assert!(is_valid_color(c), "{} should be valid", c);
        }
    }

    #[test]
    fn is_valid_color_invalid() {
        assert!(!is_valid_color(""));
        assert!(!is_valid_color("fuchsia"));
        assert!(!is_valid_color("Red")); // case-sensitive
        assert!(!is_valid_color("#ff0000"));
    }

    // ── truncate_cmd ────────────────────────────────────────────────

    #[test]
    fn truncate_cmd_short() {
        assert_eq!(truncate_cmd("abc", 10), "abc");
    }

    #[test]
    fn truncate_cmd_exact_fit() {
        assert_eq!(truncate_cmd("abcde", 5), "abcde");
    }

    #[test]
    fn truncate_cmd_overflow() {
        let result = truncate_cmd("abcdef", 5);
        assert_eq!(result, "abcd…");
    }

    #[test]
    fn truncate_cmd_max_zero() {
        let result = truncate_cmd("abc", 0);
        assert_eq!(result, "…");
    }

    #[test]
    fn truncate_cmd_max_one() {
        let result = truncate_cmd("abc", 1);
        assert_eq!(result, "…");
    }

    #[test]
    fn truncate_cmd_empty_input() {
        assert_eq!(truncate_cmd("", 10), "");
    }

    #[test]
    fn truncate_cmd_multibyte_boundary() {
        // 'é' is 2 bytes in UTF-8; truncation must not split it
        let result = truncate_cmd("café123", 5);
        // "café" is 5 bytes, so end=4 would split 'é'; should back up
        assert!(result.is_char_boundary(result.len().saturating_sub("…".len())));
        assert!(result.ends_with('…'));
    }

    // ── format_addr ─────────────────────────────────────────────────

    #[test]
    fn format_addr_v4_unspecified() {
        let addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(format_addr(&addr), "*");
    }

    #[test]
    fn format_addr_v4_specific() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(format_addr(&addr), "127.0.0.1");
    }

    #[test]
    fn format_addr_v6_unspecified() {
        let addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        assert_eq!(format_addr(&addr), "*");
    }

    #[test]
    fn format_addr_v6_loopback() {
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(format_addr(&addr), "::1");
    }

    #[test]
    fn format_addr_v6_mapped_v4_unspecified() {
        // ::ffff:0.0.0.0
        let addr = IpAddr::V6(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped());
        assert_eq!(format_addr(&addr), "*");
    }

    #[test]
    fn format_addr_v6_mapped_v4_specific() {
        // ::ffff:192.168.1.1
        let addr = IpAddr::V6(Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped());
        assert_eq!(format_addr(&addr), "192.168.1.1");
    }

    #[test]
    fn format_addr_v6_real() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(format_addr(&addr), "2001:db8::1");
    }

    // ── TcpState Display ────────────────────────────────────────────

    #[test]
    fn tcp_state_display_matches_as_str() {
        let states = [
            TcpState::Listen,
            TcpState::Established,
            TcpState::TimeWait,
            TcpState::CloseWait,
            TcpState::FinWait1,
            TcpState::FinWait2,
            TcpState::SynSent,
            TcpState::SynRecv,
            TcpState::Closing,
            TcpState::LastAck,
            TcpState::Close,
            TcpState::Unknown,
        ];
        for state in &states {
            assert_eq!(state.to_string(), state.as_str());
        }
    }

    // ── TcpState::from_hex (Linux only) ─────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_state_from_hex_known() {
        assert_eq!(TcpState::from_hex("0A"), TcpState::Listen);
        assert_eq!(TcpState::from_hex("01"), TcpState::Established);
        assert_eq!(TcpState::from_hex("06"), TcpState::TimeWait);
        assert_eq!(TcpState::from_hex("08"), TcpState::CloseWait);
        assert_eq!(TcpState::from_hex("04"), TcpState::FinWait1);
        assert_eq!(TcpState::from_hex("05"), TcpState::FinWait2);
        assert_eq!(TcpState::from_hex("02"), TcpState::SynSent);
        assert_eq!(TcpState::from_hex("03"), TcpState::SynRecv);
        assert_eq!(TcpState::from_hex("0B"), TcpState::Closing);
        assert_eq!(TcpState::from_hex("09"), TcpState::LastAck);
        assert_eq!(TcpState::from_hex("07"), TcpState::Close);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_state_from_hex_unknown() {
        assert_eq!(TcpState::from_hex("FF"), TcpState::Unknown);
        assert_eq!(TcpState::from_hex(""), TcpState::Unknown);
    }

    // ── format_uptime ───────────────────────────────────────────────

    #[test]
    fn format_uptime_none() {
        assert_eq!(format_uptime(None), "-");
    }

    #[test]
    fn format_uptime_future() {
        let future = SystemTime::now() + Duration::from_secs(3600);
        assert_eq!(format_uptime(Some(future)), "-");
    }

    #[test]
    fn format_uptime_seconds() {
        let start = SystemTime::now() - Duration::from_secs(30);
        let result = format_uptime(Some(start));
        // Allow ±1s tolerance for test execution time
        assert!(
            result == "30s" || result == "29s" || result == "31s",
            "unexpected: {}",
            result
        );
    }

    #[test]
    fn format_uptime_minutes() {
        let start = SystemTime::now() - Duration::from_secs(300);
        let result = format_uptime(Some(start));
        assert!(result == "5m" || result == "4m", "unexpected: {}", result);
    }

    #[test]
    fn format_uptime_hours_and_minutes() {
        let start = SystemTime::now() - Duration::from_secs(3660);
        let result = format_uptime(Some(start));
        assert!(
            result == "1h 1m" || result == "1h 0m",
            "unexpected: {}",
            result
        );
    }

    #[test]
    fn format_uptime_days_and_hours() {
        let start = SystemTime::now() - Duration::from_secs(90000);
        let result = format_uptime(Some(start));
        assert!(result.contains("d"), "expected days format: {}", result);
        assert!(
            result.contains("h"),
            "expected hours in days format: {}",
            result
        );
    }
}
