# SSH Remote Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `portview ssh user@host` to inspect ports on remote machines by running portview remotely via SSH and rendering the output locally.

**Architecture:** New `src/ssh.rs` module handles SSH command building, JSON parsing into `PortInfo`, and remote action execution. The TUI gets a `remote` mode where `refresh_data()` reads from an SSH pipe instead of local `get_port_infos()`. One-shot mode runs SSH, parses JSON, and renders with existing display functions.

**Tech Stack:** Rust, `std::process::Command` for SSH, existing JSON output/parsing, existing TUI renderer.

---

## File Structure

| File | Changes |
|------|---------|
| `src/ssh.rs` | **New.** SSH command builder, JSON→PortInfo deserializer, remote TUI orchestrator, remote action executor |
| `src/cli.rs` | Add `Ssh` variant to `Command` enum |
| `src/main.rs` | Add `mod ssh`, dispatch `Command::Ssh`, add `local_addr` to JSON output, add `TcpState::from_str()`, make `display_table` reusable with arbitrary port data |
| `src/tui.rs` | Add `run_remote_tui()` that uses SSH pipe for data instead of local `get_port_infos()` |

---

### Task 1: Add local_addr to JSON output and TcpState::from_str

**Files:**
- Modify: `src/main.rs` — add `local_addr` field to `port_info_json`, add `TcpState::from_str`

These are prerequisites so the SSH module can deserialize remote JSON back into `PortInfo`.

- [ ] **Step 1: Write test for TcpState::from_str**

Add to the test module in `src/main.rs`:

```rust
    #[test]
    fn tcp_state_from_str_known() {
        assert_eq!(TcpState::from_state_str("LISTEN"), TcpState::Listen);
        assert_eq!(TcpState::from_state_str("ESTABLISHED"), TcpState::Established);
        assert_eq!(TcpState::from_state_str("TIME_WAIT"), TcpState::TimeWait);
        assert_eq!(TcpState::from_state_str("CLOSE_WAIT"), TcpState::CloseWait);
        assert_eq!(TcpState::from_state_str("UNKNOWN"), TcpState::Unknown);
    }

    #[test]
    fn tcp_state_from_str_unknown() {
        assert_eq!(TcpState::from_state_str("BOGUS"), TcpState::Unknown);
        assert_eq!(TcpState::from_state_str(""), TcpState::Unknown);
    }
```

- [ ] **Step 2: Implement TcpState::from_state_str**

Add to the `impl TcpState` block (after `as_str`):

```rust
    pub(crate) fn from_state_str(s: &str) -> Self {
        match s {
            "LISTEN" => TcpState::Listen,
            "ESTABLISHED" => TcpState::Established,
            "TIME_WAIT" => TcpState::TimeWait,
            "CLOSE_WAIT" => TcpState::CloseWait,
            "FIN_WAIT1" => TcpState::FinWait1,
            "FIN_WAIT2" => TcpState::FinWait2,
            "SYN_SENT" => TcpState::SynSent,
            "SYN_RECV" => TcpState::SynRecv,
            "CLOSING" => TcpState::Closing,
            "LAST_ACK" => TcpState::LastAck,
            "CLOSE" => TcpState::Close,
            _ => TcpState::Unknown,
        }
    }
```

- [ ] **Step 3: Add local_addr to JSON output**

In `port_info_json()`, add `,"local_addr":"{}"` to the format string and `info.local_addr` as argument. Add it after `children`:

Change the format string to end with:
```rust
        r#"...,"children":{},"local_addr":"{}""#,
```
And add `info.local_addr,` as the last argument.

- [ ] **Step 4: Run tests**

Run: `cargo test`

Expected: All tests pass, including the two new TcpState tests.

- [ ] **Step 5: Verify JSON output**

Run: `cargo run -- --json 2>/dev/null | head -c 300`

Verify `"local_addr":"..."` appears in the output.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: add local_addr to JSON output and TcpState::from_state_str"
```

---

### Task 2: Create ssh.rs with command builder and JSON deserializer

**Files:**
- Create: `src/ssh.rs`

- [ ] **Step 1: Write tests for JSON deserialization**

Create `src/ssh.rs` with test module:

```rust
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::{PortInfo, TcpState};

// ── JSON deserialization ────────────────────────────────────────────

/// Parse a JSON array of port info objects into Vec<PortInfo>.
pub(crate) fn parse_port_json(json: &str) -> Result<Vec<PortInfo>, String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_port() {
        let json = r#"[{"port":3000,"protocol":"TCP","pid":1234,"ppid":1,"process":"node","command":"next dev","user":"mark","state":"LISTEN","memory_bytes":248000000,"cpu_seconds":14.3,"children":3,"local_addr":"0.0.0.0"}]"#;
        let ports = parse_port_json(json).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 3000);
        assert_eq!(ports[0].pid, 1234);
        assert_eq!(ports[0].ppid, 1);
        assert_eq!(ports[0].process_name, "node");
        assert_eq!(ports[0].command, "next dev");
        assert_eq!(ports[0].user, "mark");
        assert_eq!(ports[0].state, TcpState::Listen);
        assert_eq!(ports[0].memory_bytes, 248000000);
        assert_eq!(ports[0].children, 3);
    }

    #[test]
    fn parse_empty_array() {
        let ports = parse_port_json("[]").unwrap();
        assert!(ports.is_empty());
    }

    #[test]
    fn parse_invalid_json() {
        assert!(parse_port_json("not json").is_err());
    }

    #[test]
    fn parse_missing_optional_fields() {
        // Older remote portview without ppid or local_addr
        let json = r#"[{"port":80,"protocol":"TCP","pid":100,"process":"nginx","command":"nginx","user":"root","state":"LISTEN","memory_bytes":50000,"cpu_seconds":1.0,"children":2}]"#;
        let ports = parse_port_json(json).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].ppid, 0); // default
        assert_eq!(ports[0].port, 80);
    }
}
```

- [ ] **Step 2: Add mod ssh to main.rs**

In `src/main.rs`, add after `mod doctor;`:

```rust
mod ssh;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test ssh::tests`

Expected: Compilation succeeds but tests fail (todo!()).

- [ ] **Step 4: Implement parse_port_json**

This is a hand-rolled JSON parser matching the existing codebase pattern (no serde dependency). Replace the `todo!()`:

```rust
pub(crate) fn parse_port_json(json: &str) -> Result<Vec<PortInfo>, String> {
    let json = json.trim();
    if !json.starts_with('[') || !json.ends_with(']') {
        return Err("Expected JSON array".to_string());
    }

    let inner = &json[1..json.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    // Split on },{ but handle nested objects (docker array)
    for obj_str in split_json_objects(inner) {
        ports.push(parse_one_port(obj_str)?);
    }
    Ok(ports)
}

fn split_json_objects(s: &str) -> Vec<&str> {
    let mut results = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, c) in s.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match c {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    results.push(&s[start..=i]);
                }
            }
            _ => {}
        }
    }
    results
}

fn parse_one_port(obj: &str) -> Result<PortInfo, String> {
    let get = |key: &str| -> Option<&str> {
        let pattern = format!("\"{}\":", key);
        let pos = obj.find(&pattern)?;
        let start = pos + pattern.len();
        let rest = obj[start..].trim_start();
        if rest.starts_with('"') {
            // String value
            let str_start = 1;
            let str_end = rest[1..].find('"').map(|i| i + 1)?;
            Some(&rest[str_start..str_end])
        } else {
            // Numeric or other value — read until , or }
            let end = rest.find([',', '}'])?;
            Some(rest[..end].trim())
        }
    };

    let port: u16 = get("port")
        .and_then(|v| v.parse().ok())
        .ok_or("missing port")?;
    let protocol = get("protocol").unwrap_or("TCP").to_string();
    let pid: u32 = get("pid").and_then(|v| v.parse().ok()).unwrap_or(0);
    let ppid: u32 = get("ppid").and_then(|v| v.parse().ok()).unwrap_or(0);
    let process_name = get("process").unwrap_or("").to_string();
    let command = get("command").unwrap_or("").to_string();
    let user = get("user").unwrap_or("").to_string();
    let state = TcpState::from_state_str(get("state").unwrap_or("UNKNOWN"));
    let memory_bytes: u64 = get("memory_bytes")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cpu_seconds: f64 = get("cpu_seconds")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let children: u32 = get("children")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let local_addr: IpAddr = get("local_addr")
        .and_then(|v| v.parse().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let start_time = None; // Not available from JSON

    Ok(PortInfo {
        port,
        protocol,
        pid,
        ppid,
        process_name,
        command,
        user,
        state,
        memory_bytes,
        cpu_seconds,
        start_time,
        children,
        local_addr,
    })
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test ssh::tests`

Expected: All 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/ssh.rs src/main.rs
git commit -m "feat(ssh): add JSON deserializer for remote port data"
```

---

### Task 3: Add SSH command builder and one-shot remote scan

**Files:**
- Modify: `src/ssh.rs` — add SshCommand builder and run_ssh_scan
- Modify: `src/cli.rs` — add Ssh variant to Command enum
- Modify: `src/main.rs` — add dispatch for Command::Ssh

- [ ] **Step 1: Add SshCommand builder to ssh.rs**

Add to `src/ssh.rs` (above the tests module):

```rust
use std::process;

// ── SSH command builder ─────────────────────────────────────────────

pub(crate) struct SshCommand {
    pub destination: String,
    pub ssh_opts: Vec<String>,
}

impl SshCommand {
    pub fn build(&self, remote_args: &[&str]) -> process::Command {
        let mut cmd = process::Command::new("ssh");
        cmd.arg("-T"); // No pseudo-terminal
        cmd.arg("-o").arg("BatchMode=yes"); // Fail fast, no prompts
        for opt in &self.ssh_opts {
            // Split opt on whitespace to handle "-p 2222" as two args
            for part in opt.split_whitespace() {
                cmd.arg(part);
            }
        }
        cmd.arg(&self.destination);
        cmd.arg("portview");
        for arg in remote_args {
            cmd.arg(arg);
        }
        cmd
    }

    pub fn run_oneshot(&self, remote_args: &[&str]) -> Result<String, String> {
        let output = self
            .build(remote_args)
            .output()
            .map_err(|e| format!("Failed to run ssh: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_ssh_error(&self.destination, &stderr));
        }

        String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 from remote: {}", e))
    }
}

fn classify_ssh_error(dest: &str, stderr: &str) -> String {
    let stderr_lower = stderr.to_lowercase();
    if stderr_lower.contains("command not found") || stderr_lower.contains("no such file") {
        format!(
            "portview is not installed on {}. Install with:\n  ssh {} 'curl -fsSL https://raw.githubusercontent.com/mapika/portview/main/install.sh | sh'",
            dest, dest
        )
    } else if stderr_lower.contains("permission denied") {
        format!("SSH authentication failed for {}. Check your SSH keys.", dest)
    } else if stderr_lower.contains("connection refused")
        || stderr_lower.contains("no route")
        || stderr_lower.contains("could not resolve")
    {
        format!("Failed to connect to {}: {}", dest, stderr.trim())
    } else {
        format!("SSH error ({}): {}", dest, stderr.trim())
    }
}
```

- [ ] **Step 2: Add run_ssh_scan function**

Add to `src/ssh.rs`:

```rust
use crate::{StyleConfig, ColorConfig, write_styled, format_bytes, format_uptime, format_addr};
use std::io::{self, Write};

pub(crate) fn run_ssh_scan(
    ssh: &SshCommand,
    remote_args: &[&str],
    use_color: bool,
) {
    match ssh.run_oneshot(remote_args) {
        Ok(json_output) => {
            match parse_port_json(&json_output) {
                Ok(ports) => {
                    if ports.is_empty() {
                        println!("No ports found on remote host.");
                    } else {
                        // Reuse the existing display infrastructure
                        crate::display_table(&ports, use_color, &crate::ColorConfig::from_env(), None, false);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse remote output: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 3: Make display_table accessible from ssh.rs**

The existing display logic in `main.rs` writes directly to stdout with specific formatting. We need to make `display_table` (or a variant) callable from `ssh.rs`. 

In `src/main.rs`, find the function that writes the table output (it's inside `run_display` or `write_display_safe`). Make the core table-writing function `pub(crate)`.

Find the function signature for the table display logic. It likely takes `&[PortInfo]`, `use_color`, and color config. Change its visibility to `pub(crate)`.

Search for `fn write_display` or `fn display_table` and make it `pub(crate) fn`.

- [ ] **Step 4: Add Ssh variant to Command enum**

In `src/cli.rs`, add after the `Doctor` variant:

```rust
    /// Inspect ports on a remote host via SSH
    Ssh {
        /// SSH destination (user@host or host)
        destination: String,
        /// Remote subcommand and arguments (e.g. "watch", "3000", "doctor")
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        remote_args: Vec<String>,
        /// Extra SSH options (e.g. "-p 2222")
        #[arg(long)]
        ssh_opt: Vec<String>,
        /// Disable all colors
        #[arg(long)]
        no_color: bool,
    },
```

- [ ] **Step 5: Add dispatch in main.rs**

In `main()`, add match arm after `Command::Doctor`:

```rust
            Command::Ssh {
                destination,
                remote_args,
                ssh_opt,
                no_color,
            } => {
                let use_color = !no_color && atty_stdout();
                ssh::run_ssh(destination, remote_args, ssh_opt, use_color);
                return;
            }
```

- [ ] **Step 6: Add run_ssh dispatcher in ssh.rs**

Add a top-level dispatcher that handles all SSH modes:

```rust
pub(crate) fn run_ssh(
    destination: &str,
    remote_args: &[String],
    ssh_opts: &[String],
    use_color: bool,
) {
    let ssh = SshCommand {
        destination: destination.to_string(),
        ssh_opts: ssh_opts.to_vec(),
    };

    // Determine what mode: watch, doctor, port inspection, or scan
    let first_arg = remote_args.first().map(|s| s.as_str());

    match first_arg {
        Some("watch") => {
            // Build remote args: watch --json + remaining flags
            let mut args = vec!["watch", "--json"];
            for arg in &remote_args[1..] {
                args.push(arg.as_str());
            }
            run_ssh_tui(&ssh, &args, use_color);
        }
        Some("doctor") => {
            // Pass through: run remote doctor and display output
            let mut args = vec!["doctor", "--json"];
            for arg in &remote_args[1..] {
                args.push(arg.as_str());
            }
            run_ssh_doctor(&ssh, &args, use_color);
        }
        _ => {
            // One-shot scan: portview --json [remote_args...]
            let mut args = vec!["--json"];
            for arg in remote_args {
                args.push(arg.as_str());
            }
            run_ssh_scan(&ssh, &args, use_color);
        }
    }
}

fn run_ssh_doctor(ssh: &SshCommand, remote_args: &[&str], use_color: bool) {
    match ssh.run_oneshot(remote_args) {
        Ok(output) => {
            // Doctor JSON — pass to doctor's renderer
            crate::doctor::render_remote_doctor(&output, use_color);
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

fn run_ssh_tui(_ssh: &SshCommand, _remote_args: &[&str], _use_color: bool) {
    // Implemented in Task 5
    eprintln!("Remote TUI mode not yet implemented. Use one-shot scan: portview ssh <host>");
    std::process::exit(1);
}
```

- [ ] **Step 7: Add render_remote_doctor to doctor.rs**

In `src/doctor.rs`, add a public function that parses doctor JSON and renders it:

```rust
pub fn render_remote_doctor(json_output: &str, use_color: bool) {
    let json = json_output.trim();
    // Doctor JSON is an array of {severity, check, title, detail}
    // For now, just print it pretty
    if json == "[]" {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out);
        write_styled(&mut out, "  All clear \u{2014} no issues found\n", "green", use_color);
        return;
    }
    // Pass through the raw output since it's already formatted by remote
    // In a more complete implementation, parse and re-render
    print!("{}", json_output);
}
```

Actually — for doctor, the simplest approach is to NOT pass `--json` and just forward the raw output. Let me simplify: for doctor mode, just run the remote command without `--json` and pipe stdout directly:

```rust
fn run_ssh_doctor(ssh: &SshCommand, remote_args: &[&str], _use_color: bool) {
    // For doctor, run without --json and forward output directly
    let args: Vec<&str> = remote_args.iter()
        .filter(|a| **a != "--json")
        .copied()
        .collect();
    match ssh.run_oneshot(&args) {
        Ok(output) => print!("{}", output),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 8: Build and test**

Run: `cargo build && cargo test`

Run: `cargo run -- ssh --help`

Expected: Shows Ssh subcommand help with destination and remote_args.

- [ ] **Step 9: Commit**

```bash
git add src/ssh.rs src/cli.rs src/main.rs src/doctor.rs
git commit -m "feat(ssh): add one-shot remote scan via SSH"
```

---

### Task 4: Make display_table reusable for remote data

**Files:**
- Modify: `src/main.rs` — extract display_table into a reusable function

- [ ] **Step 1: Find the display table function**

The scan display is in `run_display()` or `write_display_safe()` in `src/main.rs`. Read it and understand how it writes the table. It likely calls `port_info_json` for JSON mode and a custom table renderer for normal mode.

- [ ] **Step 2: Extract a pub(crate) function**

Create a `pub(crate) fn display_port_table(infos: &[PortInfo], use_color: bool, colors: &ColorConfig)` that writes the table to stdout. This is called by the existing scan path and by `run_ssh_scan`.

The exact refactoring depends on the current structure — the implementer should read the display code and extract the minimum needed for SSH to reuse it.

- [ ] **Step 3: Update run_ssh_scan to use it**

In `src/ssh.rs`, update `run_ssh_scan` to call the extracted function:

```rust
pub(crate) fn run_ssh_scan(ssh: &SshCommand, remote_args: &[&str], use_color: bool) {
    match ssh.run_oneshot(remote_args) {
        Ok(json_output) => {
            match parse_port_json(&json_output) {
                Ok(ports) => {
                    if ports.is_empty() {
                        println!("No ports found on remote host.");
                    } else {
                        let colors = crate::ColorConfig::from_env();
                        crate::display_port_table(&ports, use_color, &colors);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse remote output: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 4: Build and test**

Run: `cargo build && cargo test`

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/ssh.rs
git commit -m "feat(ssh): extract reusable display_port_table for remote scan rendering"
```

---

### Task 5: Remote TUI watch mode

**Files:**
- Modify: `src/tui.rs` — add `run_remote_tui` function
- Modify: `src/ssh.rs` — implement `run_ssh_tui`

- [ ] **Step 1: Add run_remote_tui to tui.rs**

This is a variant of `run_tui` that reads port data from an SSH pipe instead of calling `get_port_infos()`. Add after the existing `run_tui`:

```rust
#[allow(clippy::too_many_arguments)]
pub fn run_remote_tui(
    host: &str,
    mut child: std::process::Child,
    reader: std::io::BufReader<std::process::ChildStdout>,
    no_color: bool,
    sort: Option<SortColumn>,
) -> io::Result<()> {
    use std::io::BufRead;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let sort_column = sort.unwrap_or(SortColumn::Port);
    let theme = if no_color {
        TuiTheme::no_color()
    } else {
        TuiTheme::default_btop()
    };
    let styles = if no_color {
        StyleConfig::default()
    } else {
        StyleConfig::btop_default()
    };

    let mut app = App {
        ports: Vec::new(),
        docker_enabled: false,
        docker_map: DockerPortMap::default(),
        table_state: TableState::default(),
        mode: AppMode::Table,
        show_all: false,
        filter_text: String::new(),
        popup: None,
        target: None,
        styles,
        theme,
        wide: false,
        default_force: false,
        should_quit: false,
        last_refresh: Instant::now() - Duration::from_secs(2),
        detail_index: 0,
        status_message: Some((format!("remote: {}", host), Instant::now() + Duration::from_secs(86400))),
        sort_column,
        sort_direction: SortDirection::Asc,
        tree_mode: false,
    };

    let tick_rate = Duration::from_millis(100); // Check more often for SSH data
    let mut line_buf = String::new();
    let mut reader = reader;

    // Non-blocking: set the reader's underlying fd to non-blocking
    // Actually, we'll use try_clone and read in the event loop with a timeout

    loop {
        terminal.draw(|frame| render(frame, &mut app))?;

        if app.should_quit {
            break;
        }

        // Try to read a line of JSON from the SSH pipe (non-blocking via poll)
        // We read with a short timeout and check for input
        if app.last_refresh.elapsed() >= Duration::from_secs(1) {
            line_buf.clear();
            match reader.read_line(&mut line_buf) {
                Ok(0) => {
                    // EOF — SSH connection closed
                    app.status_message = Some(("Connection lost".to_string(), Instant::now()));
                    app.should_quit = true;
                    continue;
                }
                Ok(_) => {
                    if let Ok(ports) = crate::ssh::parse_port_json(line_buf.trim()) {
                        app.ports = ports;
                        app.last_refresh = Instant::now();
                        // Clamp selection
                        let count = app.display_ports().len();
                        if count == 0 {
                            app.table_state.select(None);
                        } else if let Some(sel) = app.table_state.selected() {
                            if sel >= count {
                                app.table_state.select(Some(count - 1));
                            }
                        } else {
                            app.table_state.select(Some(0));
                        }
                    }
                }
                Err(_) => {
                    app.status_message = Some(("Read error".to_string(), Instant::now()));
                    app.should_quit = true;
                    continue;
                }
            }
        }

        // Wait for key events
        if event::poll(tick_rate)?
            && let Event::Key(key) = event::read()?
        {
            if key.kind == KeyEventKind::Press {
                handle_key(&mut app, key.code, key.modifiers);
            }
        }
    }

    // Cleanup
    let _ = child.kill();
    let _ = child.wait();

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
```

- [ ] **Step 2: Implement run_ssh_tui in ssh.rs**

Replace the stub:

```rust
fn run_ssh_tui(ssh: &SshCommand, remote_args: &[&str], use_color: bool) {
    use std::io::BufReader;

    let mut cmd = ssh.build(remote_args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start SSH: {}", e);
            std::process::exit(1);
        }
    };

    let stdout = child.stdout.take().expect("piped stdout");
    let reader = BufReader::new(stdout);

    let no_color = !use_color;
    if let Err(e) = crate::tui::run_remote_tui(
        &ssh.destination,
        child,
        reader,
        no_color,
        None,
    ) {
        eprintln!("TUI error: {}", e);
        std::process::exit(1);
    }
}
```

- [ ] **Step 3: Disable `a` toggle and actions in remote TUI**

In `handle_table_key`, the `a` key calls `app.refresh_data()` which calls `get_port_infos()`. In remote mode this would break. The simplest fix: check if we're in remote mode before allowing `a`:

Add a field `remote_host: Option<String>` to App. If set, disable `a` toggle and kill actions. The `run_remote_tui` already sets `status_message` with the host — we can use that, or add a dedicated field.

Add to App struct:
```rust
    remote_host: Option<String>,
```

Initialize to `None` in `App::new()` and `make_test_app`, and `Some(host.to_string())` in `run_remote_tui`.

In `handle_table_key`, guard `a`:
```rust
        KeyCode::Char('a') if app.remote_host.is_none() => {
```

In `handle_table_key` and `handle_detail_key`, guard `d`/`D`:
```rust
        KeyCode::Char('d') if app.remote_host.is_none() => {
```
(For now. Remote kill is Task 6.)

- [ ] **Step 4: Update title bar for remote mode**

In `build_title_line`, if `remote_host` is set, show `portview@host` instead of `portview`:

```rust
    let title = if let Some(host) = &app.remote_host {
        format!(" portview@{}", host)
    } else {
        " portview".to_string()
    };
    let mut spans = vec![
        Span::styled(title, app.theme.title),
```

- [ ] **Step 5: Build and test**

Run: `cargo build && cargo test`

- [ ] **Step 6: Commit**

```bash
git add src/tui.rs src/ssh.rs
git commit -m "feat(ssh): add remote TUI watch mode via SSH pipe"
```

---

### Task 6: Remote kill actions

**Files:**
- Modify: `src/ssh.rs` — add remote kill function
- Modify: `src/tui.rs` — forward kill to SSH in remote mode

- [ ] **Step 1: Add remote_kill to ssh.rs**

```rust
pub(crate) fn remote_kill(ssh: &SshCommand, port: u16, force: bool) -> Result<String, String> {
    let mut args = vec!["kill", &port.to_string()];
    let force_flag;
    if force {
        force_flag = "--force".to_string();
        args.push(&force_flag);
    }
    // Need to own the strings for the slice
    let port_str = port.to_string();
    let args: Vec<&str> = if force {
        vec!["kill", &port_str, "--force"]
    } else {
        vec!["kill", &port_str]
    };
    ssh.run_oneshot(&args)
}
```

- [ ] **Step 2: Store SshCommand reference in App for remote actions**

This is tricky because `App` can't easily hold a reference to `SshCommand`. Instead, store the SSH destination and opts in App so we can reconstruct the command:

Add to App:
```rust
    ssh_opts: Vec<String>,
```

Initialize to empty in `App::new()` and `make_test_app`, populate in `run_remote_tui`.

- [ ] **Step 3: Handle remote kill in the kill popup handler**

In `handle_kill_popup_key` (where `y`/Enter confirms kill), check if `remote_host` is set. If so, spawn an SSH kill command instead of calling local `kill_process`:

```rust
        KeyCode::Char('y') | KeyCode::Enter => {
            if let Some(Popup::Kill(popup)) = &app.popup {
                if let Some(host) = &app.remote_host {
                    // Remote kill
                    let ssh = crate::ssh::SshCommand {
                        destination: host.clone(),
                        ssh_opts: app.ssh_opts.clone(),
                    };
                    let port_str = popup.port.to_string();
                    let args = if popup.force {
                        vec!["kill", port_str.as_str(), "--force"]
                    } else {
                        vec!["kill", port_str.as_str()]
                    };
                    match ssh.run_oneshot(&args) {
                        Ok(_) => {
                            app.status_message = Some((
                                format!("Killed remote port {}", popup.port),
                                Instant::now(),
                            ));
                        }
                        Err(e) => {
                            app.status_message = Some((format!("Kill failed: {}", e), Instant::now()));
                        }
                    }
                } else {
                    // Local kill (existing code)
                    kill_process(popup.pid, popup.force);
                    app.status_message = Some((
                        format!("Killed {} (PID {})", popup.process_name, popup.pid),
                        Instant::now(),
                    ));
                }
            }
            app.popup = None;
        }
```

- [ ] **Step 4: Re-enable `d`/`D` in remote mode**

Remove the `if app.remote_host.is_none()` guard on `d`/`D` (or change it to always allow). The popup handler now handles both local and remote kills.

- [ ] **Step 5: Build and test**

Run: `cargo build && cargo test`

- [ ] **Step 6: Commit**

```bash
git add src/tui.rs src/ssh.rs
git commit -m "feat(ssh): forward kill actions to remote host via SSH"
```

---

### Task 7: Final integration, clippy, and smoke test

**Files:**
- All modified files

- [ ] **Step 1: Run full test suite**

Run: `cargo test`

Expected: All tests pass.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy`

Expected: No warnings.

- [ ] **Step 3: Run fmt**

Run: `cargo fmt`

- [ ] **Step 4: Smoke test help**

Run: `cargo run -- ssh --help`

Expected:
```
Inspect ports on a remote host via SSH

Usage: portview ssh [OPTIONS] <DESTINATION> [REMOTE_ARGS]...
```

- [ ] **Step 5: Smoke test one-shot (if you have a remote host)**

Run: `cargo run -- ssh localhost`

If portview is installed locally, this should work via SSH to localhost (if SSH is running).

- [ ] **Step 6: Smoke test error handling**

Run: `cargo run -- ssh nonexistent.host.invalid`

Expected: Clean error message about connection failure.

- [ ] **Step 7: Final commit (if any fmt/clippy changes)**

```bash
git add -A
git commit -m "feat(ssh): complete SSH remote mode"
```
