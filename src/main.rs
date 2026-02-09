use clap::Parser;
use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::ExecutableCommand;
use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

mod tui;

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

    pub(crate) fn as_str(&self) -> &'static str {
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

pub(crate) fn truncate_cmd(cmd: &str, max_len: usize) -> String {
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

pub(crate) fn format_addr(addr: &IpAddr) -> String {
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

pub(crate) struct ColorConfig {
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

/// Convert a color name to a crossterm style (color + optional attribute).
pub(crate) fn color_name_to_style(name: &str) -> (Option<Color>, Option<Attribute>) {
    match name {
        "red" => (Some(Color::Red), None),
        "green" => (Some(Color::Green), None),
        "blue" => (Some(Color::Blue), None),
        "cyan" => (Some(Color::Cyan), None),
        "yellow" => (Some(Color::Yellow), None),
        "magenta" => (Some(Color::Magenta), None),
        "white" => (Some(Color::White), None),
        "bold" => (None, Some(Attribute::Bold)),
        "dimmed" => (None, Some(Attribute::Dim)),
        "bright_red" => (Some(Color::DarkRed), Some(Attribute::Bold)),
        "bright_green" => (Some(Color::DarkGreen), Some(Attribute::Bold)),
        "bright_blue" => (Some(Color::DarkBlue), Some(Attribute::Bold)),
        "bright_cyan" => (Some(Color::DarkCyan), Some(Attribute::Bold)),
        "bright_yellow" => (Some(Color::DarkYellow), Some(Attribute::Bold)),
        "bright_magenta" => (Some(Color::DarkMagenta), Some(Attribute::Bold)),
        "bright_white" => (Some(Color::White), Some(Attribute::Bold)),
        _ => (None, None), // "none" or unknown
    }
}

/// Ratatui style from color name (for TUI mode).
pub(crate) fn color_name_to_ratatui_style(name: &str) -> ratatui::style::Style {
    use ratatui::style::{Modifier, Style};
    match name {
        "red" => Style::default().fg(ratatui::style::Color::Red),
        "green" => Style::default().fg(ratatui::style::Color::Green),
        "blue" => Style::default().fg(ratatui::style::Color::Blue),
        "cyan" => Style::default().fg(ratatui::style::Color::Cyan),
        "yellow" => Style::default().fg(ratatui::style::Color::Yellow),
        "magenta" => Style::default().fg(ratatui::style::Color::Magenta),
        "white" => Style::default().fg(ratatui::style::Color::White),
        "bold" => Style::default().add_modifier(Modifier::BOLD),
        "dimmed" => Style::default().add_modifier(Modifier::DIM),
        "bright_red" => Style::default().fg(ratatui::style::Color::LightRed),
        "bright_green" => Style::default().fg(ratatui::style::Color::LightGreen),
        "bright_blue" => Style::default().fg(ratatui::style::Color::LightBlue),
        "bright_cyan" => Style::default().fg(ratatui::style::Color::LightCyan),
        "bright_yellow" => Style::default().fg(ratatui::style::Color::LightYellow),
        "bright_magenta" => Style::default().fg(ratatui::style::Color::LightMagenta),
        "bright_white" => Style::default()
            .fg(ratatui::style::Color::White)
            .add_modifier(Modifier::BOLD),
        _ => Style::default(), // "none" or unknown
    }
}

/// StyleConfig for TUI: holds ratatui styles per column.
pub(crate) struct StyleConfig {
    pub(crate) port: ratatui::style::Style,
    pub(crate) proto: ratatui::style::Style,
    pub(crate) pid: ratatui::style::Style,
    pub(crate) user: ratatui::style::Style,
    pub(crate) process: ratatui::style::Style,
    pub(crate) uptime: ratatui::style::Style,
    pub(crate) mem: ratatui::style::Style,
    pub(crate) command: ratatui::style::Style,
}

impl StyleConfig {
    pub(crate) fn from_color_config(cc: &ColorConfig) -> Self {
        Self {
            port: color_name_to_ratatui_style(&cc.port),
            proto: color_name_to_ratatui_style(&cc.proto),
            pid: color_name_to_ratatui_style(&cc.pid),
            user: color_name_to_ratatui_style(&cc.user),
            process: color_name_to_ratatui_style(&cc.process),
            uptime: color_name_to_ratatui_style(&cc.uptime),
            mem: color_name_to_ratatui_style(&cc.mem),
            command: color_name_to_ratatui_style(&cc.command),
        }
    }

    pub(crate) fn no_color() -> Self {
        Self {
            port: ratatui::style::Style::default(),
            proto: ratatui::style::Style::default(),
            pid: ratatui::style::Style::default(),
            user: ratatui::style::Style::default(),
            process: ratatui::style::Style::default(),
            uptime: ratatui::style::Style::default(),
            mem: ratatui::style::Style::default(),
            command: ratatui::style::Style::default(),
        }
    }

    pub(crate) fn btop_default() -> Self {
        use ratatui::style::{Color, Modifier, Style};
        Self {
            port: Style::default().fg(Color::Rgb(80, 200, 200)),
            proto: Style::default().fg(Color::Rgb(100, 110, 120)),
            pid: Style::default().fg(Color::Rgb(220, 180, 80)),
            user: Style::default().fg(Color::Rgb(120, 200, 130)),
            process: Style::default()
                .fg(Color::Rgb(220, 225, 230))
                .add_modifier(Modifier::BOLD),
            uptime: Style::default().fg(Color::Rgb(100, 110, 120)),
            mem: Style::default().fg(Color::Rgb(160, 140, 200)),
            command: Style::default().fg(Color::Rgb(170, 175, 180)),
        }
    }
}

// ── Crossterm styled write helper ────────────────────────────────────

fn write_styled(w: &mut impl Write, text: &str, color_name: &str, use_color: bool) {
    if !use_color {
        let _ = write!(w, "{}", text);
        return;
    }
    let (color, attr) = color_name_to_style(color_name);
    if let Some(a) = attr {
        let _ = w.execute(SetAttribute(a));
    }
    if let Some(c) = color {
        let _ = w.execute(SetForegroundColor(c));
    }
    let _ = w.execute(Print(text));
    let _ = w.execute(ResetColor);
    let _ = w.execute(SetAttribute(Attribute::Reset));
}

// ── Display functions ────────────────────────────────────────────────

fn display_table(
    infos: &[PortInfo],
    use_color: bool,
    colors: &ColorConfig,
    wide: bool,
    cmd_width: usize,
) {
    if infos.is_empty() {
        let mut out = io::stdout();
        write_styled(&mut out, "No listening ports found.\n", "dimmed", use_color);
        return;
    }

    let mut out = io::stdout();

    // Compute column widths
    let port_w = infos
        .iter()
        .map(|i| i.port.to_string().len())
        .max()
        .unwrap_or(0)
        .max(4);
    let proto_w = infos
        .iter()
        .map(|i| i.protocol.len())
        .max()
        .unwrap_or(0)
        .max(5);
    let pid_w = infos
        .iter()
        .map(|i| i.pid.to_string().len())
        .max()
        .unwrap_or(0)
        .max(3);
    let user_w = infos.iter().map(|i| i.user.len()).max().unwrap_or(0).max(4);
    let proc_w = infos
        .iter()
        .map(|i| i.process_name.len())
        .max()
        .unwrap_or(0)
        .max(7);
    let uptime_w = infos
        .iter()
        .map(|i| format_uptime(i.start_time).len())
        .max()
        .unwrap_or(0)
        .max(6);
    let mem_w = infos
        .iter()
        .map(|i| format_bytes(i.memory_bytes).len())
        .max()
        .unwrap_or(0)
        .max(3);
    let actual_cmd_w = if wide {
        infos
            .iter()
            .map(|i| i.command.len())
            .max()
            .unwrap_or(0)
            .max(7)
    } else {
        cmd_width.max(7)
    };

    let widths = [
        port_w,
        proto_w,
        pid_w,
        user_w,
        proc_w,
        uptime_w,
        mem_w,
        actual_cmd_w,
    ];
    let headers = [
        "PORT", "PROTO", "PID", "USER", "PROCESS", "UPTIME", "MEM", "COMMAND",
    ];

    // Top border
    let _ = write!(out, "╭");
    for (i, &w) in widths.iter().enumerate() {
        let _ = write!(out, "{}", "─".repeat(w + 2));
        if i < widths.len() - 1 {
            let _ = write!(out, "┬");
        }
    }
    let _ = writeln!(out, "╮");

    // Header
    let _ = write!(out, "│");
    for (i, (&w, &h)) in widths.iter().zip(headers.iter()).enumerate() {
        let _ = write!(out, " ");
        if use_color {
            let _ = out.execute(SetAttribute(Attribute::Bold));
        }
        let _ = write!(out, "{:<width$}", h, width = w);
        if use_color {
            let _ = out.execute(SetAttribute(Attribute::Reset));
        }
        let _ = write!(out, " │");
        let _ = i; // used in loop
    }
    let _ = writeln!(out);

    // Separator
    let _ = write!(out, "├");
    for (i, &w) in widths.iter().enumerate() {
        let _ = write!(out, "{}", "─".repeat(w + 2));
        if i < widths.len() - 1 {
            let _ = write!(out, "┼");
        }
    }
    let _ = writeln!(out, "┤");

    // Data rows
    let color_names = [
        &colors.port,
        &colors.proto,
        &colors.pid,
        &colors.user,
        &colors.process,
        &colors.uptime,
        &colors.mem,
        &colors.command,
    ];

    for info in infos {
        let uptime_str = format_uptime(info.start_time);
        let mem_str = format_bytes(info.memory_bytes);
        let values = [
            info.port.to_string(),
            info.protocol.clone(),
            info.pid.to_string(),
            info.user.clone(),
            info.process_name.clone(),
            uptime_str,
            mem_str,
            info.command.clone(),
        ];

        let _ = write!(out, "│");
        for (i, (&w, val)) in widths.iter().zip(values.iter()).enumerate() {
            let _ = write!(out, " ");
            // Right-align UPTIME (5) and MEM (6) columns
            let padded = if i == 5 || i == 6 {
                format!("{:>width$}", val, width = w)
            } else {
                format!("{:<width$}", val, width = w)
            };
            write_styled(&mut out, &padded, color_names[i], use_color);
            let _ = write!(out, " │");
        }
        let _ = writeln!(out);
    }

    // Bottom border
    let _ = write!(out, "╰");
    for (i, &w) in widths.iter().enumerate() {
        let _ = write!(out, "{}", "─".repeat(w + 2));
        if i < widths.len() - 1 {
            let _ = write!(out, "┴");
        }
    }
    let _ = writeln!(out, "╯");
}

fn display_detail(info: &PortInfo, use_color: bool) {
    let mut out = io::stdout();
    let bind_str = format!("{}:{}", format_addr(&info.local_addr), info.port);
    let uptime = format_uptime(info.start_time);

    let _ = writeln!(out);
    if use_color {
        write_styled(&mut out, "Port", "bold", true);
        let _ = write!(out, " ");
        write_styled(&mut out, &info.port.to_string(), "cyan", true);
        let _ = write!(out, " ");
        write_styled(&mut out, &format!("({})", info.protocol), "dimmed", true);
        let _ = write!(out, " ");
        write_styled(&mut out, "—", "dimmed", true);
        let _ = write!(out, " ");
        write_styled(&mut out, &info.process_name, "green", true);
        let _ = write!(out, " ");
        write_styled(&mut out, &format!("(PID {})", info.pid), "yellow", true);
        let _ = writeln!(out);
    } else {
        let _ = writeln!(
            out,
            "Port {} ({}) — {} (PID {})",
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
            let _ = write!(out, "  ");
            write_styled(&mut out, label, "dimmed", true);
            let _ = writeln!(out, "  {}", value);
        } else {
            let _ = writeln!(out, "  {:<9} {}", label, value);
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
pub(crate) fn do_kill(pid: u32, force: bool) {
    let mut out = io::stderr();
    // Guard against special PIDs and overflow on cast to i32
    if pid == 0 {
        write_styled(&mut out, "  ✗", "red", true);
        let _ = writeln!(
            out,
            " Refusing to signal PID 0 (would target entire process group)"
        );
        return;
    }
    if pid > i32::MAX as u32 {
        write_styled(&mut out, "  ✗", "red", true);
        let _ = writeln!(out, " PID {} exceeds safe range", pid);
        return;
    }

    let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
    let signal_name = if force { "SIGKILL" } else { "SIGTERM" };

    // Note: TOCTOU — the PID could have been recycled between reading /proc
    // and sending the signal. This is inherent to all kill-by-port tools.
    let result = unsafe { libc::kill(pid as i32, signal) };

    if result == 0 {
        let mut out = io::stdout();
        write_styled(&mut out, "  ✓", "green", true);
        let _ = writeln!(out, " Sent {} to PID {}", signal_name, pid);
    } else {
        let err = io::Error::last_os_error();
        write_styled(&mut out, "  ✗", "red", true);
        let _ = writeln!(out, " Failed to kill PID {}: {}", pid, err);
    }
}

#[cfg(windows)]
pub(crate) fn do_kill(pid: u32, _force: bool) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let mut out = io::stderr();
    if pid == 0 {
        write_styled(&mut out, "  ✗", "red", true);
        let _ = writeln!(out, " Refusing to terminate PID 0");
        return;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            let err = io::Error::last_os_error();
            write_styled(&mut out, "  ✗", "red", true);
            let _ = writeln!(out, " Failed to open PID {}: {}", pid, err);
            return;
        }

        // Windows has no graceful SIGTERM equivalent — always force-terminates
        let result = TerminateProcess(handle, 1);
        CloseHandle(handle);

        if result != 0 {
            let mut out = io::stdout();
            write_styled(&mut out, "  ✓", "green", true);
            let _ = writeln!(out, " Terminated PID {}", pid);
        } else {
            let err = io::Error::last_os_error();
            write_styled(&mut out, "  ✗", "red", true);
            let _ = writeln!(out, " Failed to terminate PID {}: {}", pid, err);
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

// ── Watch-mode helpers (JSON watch only) ─────────────────────────────

static RUNNING: AtomicBool = AtomicBool::new(true);

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

#[cfg(unix)]
pub(crate) fn chrono_free_time() -> String {
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
pub(crate) fn chrono_free_time() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;

    let mut st = unsafe { std::mem::zeroed::<windows_sys::Win32::Foundation::SYSTEMTIME>() };
    unsafe { GetLocalTime(&mut st) };
    format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
}

// ── Terminal width (for one-shot display) ────────────────────────────

fn get_terminal_width() -> Option<u16> {
    crossterm::terminal::size().ok().map(|(w, _)| w)
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let use_color = !cli.no_color && atty_stdout();

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
        if cli.json {
            // JSON watch: emit one JSON array per tick, no terminal escapes
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
            // Interactive TUI mode
            let has_env_colors = std::env::var("PORTVIEW_COLORS").is_ok();
            let style_config = if cli.no_color {
                StyleConfig::no_color()
            } else if has_env_colors {
                StyleConfig::from_color_config(&colors)
            } else {
                StyleConfig::btop_default()
            };

            if let Err(e) = tui::run_tui(
                cli.target.as_deref(),
                cli.all,
                cli.wide,
                cli.force,
                cli.no_color,
                style_config,
            ) {
                eprintln!("TUI error: {}", e);
                std::process::exit(1);
            }
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

    // Box-drawing style: 9 vertical borders + 1 space padding on each side of each of 8 columns
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
                    let mut out = io::stdout();
                    write_styled(
                        &mut out,
                        &format!(
                            "\n {} listening port{} \n",
                            infos.len(),
                            if infos.len() == 1 { "" } else { "s" }
                        ),
                        "bold",
                        true,
                    );
                }
                display_table(&infos, use_color, colors, cli.wide, cmd_width);
                if use_color && !infos.is_empty() && !cli.watch {
                    let mut out = io::stdout();
                    write_styled(
                        &mut out,
                        "  Inspect a port: portview <port>\n",
                        "dimmed",
                        true,
                    );
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
                    } else {
                        let mut out = io::stdout();
                        if use_color {
                            let _ = write!(out, "\n  ");
                            write_styled(&mut out, "○", "dimmed", true);
                            let _ = write!(out, " Nothing on port ");
                            write_styled(&mut out, &port.to_string(), "bold", true);
                            let _ = writeln!(out);
                        } else {
                            let _ = writeln!(out, "\n  Nothing on port {}", port);
                        }
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
                    let mut out = io::stdout();
                    if use_color {
                        let _ = write!(out, "\n  ");
                        write_styled(&mut out, "○", "dimmed", true);
                        let _ = write!(out, " No ports found for '");
                        write_styled(&mut out, target, "bold", true);
                        let _ = writeln!(out, "'");
                    } else {
                        let _ = writeln!(out, "\n  No ports found for '{}'", target);
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
                        let mut out = io::stdout();
                        write_styled(
                            &mut out,
                            &format!(
                                "\n {} port{}",
                                matches.len(),
                                if matches.len() == 1 { "" } else { "s" }
                            ),
                            "bold",
                            true,
                        );
                        let _ = write!(out, " matching '");
                        write_styled(&mut out, target, "cyan", true);
                        let _ = writeln!(out, "'");
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

    // ── color_name_to_style ─────────────────────────────────────────

    #[test]
    fn color_name_to_style_basic_colors() {
        assert_eq!(color_name_to_style("red"), (Some(Color::Red), None));
        assert_eq!(color_name_to_style("green"), (Some(Color::Green), None));
        assert_eq!(color_name_to_style("cyan"), (Some(Color::Cyan), None));
    }

    #[test]
    fn color_name_to_style_modifiers() {
        assert_eq!(color_name_to_style("bold"), (None, Some(Attribute::Bold)));
        assert_eq!(color_name_to_style("dimmed"), (None, Some(Attribute::Dim)));
    }

    #[test]
    fn color_name_to_style_none() {
        assert_eq!(color_name_to_style("none"), (None, None));
        assert_eq!(color_name_to_style("unknown"), (None, None));
    }

    // ── color_name_to_ratatui_style ─────────────────────────────────

    #[test]
    fn ratatui_style_basic() {
        use ratatui::style::{Modifier, Style};

        let s = color_name_to_ratatui_style("red");
        assert_eq!(s, Style::default().fg(ratatui::style::Color::Red));

        let s = color_name_to_ratatui_style("bold");
        assert_eq!(s, Style::default().add_modifier(Modifier::BOLD));

        let s = color_name_to_ratatui_style("none");
        assert_eq!(s, Style::default());
    }
}
