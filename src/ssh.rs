use std::net::IpAddr;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::json::{extract_pairs, parse_f64, parse_string, parse_u64};
use crate::{PortInfo, TcpState};

// ── SSH command builder ──────────────────────────────────────────────

pub(crate) struct SshCommand {
    pub destination: String,
    pub ssh_opts: Vec<String>,
}

impl SshCommand {
    pub fn build(&self, remote_args: &[&str]) -> process::Command {
        let mut cmd = process::Command::new("ssh");
        cmd.arg("-T");
        cmd.arg("-o").arg("BatchMode=yes");
        for opt in &self.ssh_opts {
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

    /// Run an arbitrary shell snippet on the remote host instead of `portview`.
    /// Used by agentless mode, where nothing is installed on the far end.
    pub fn build_shell(&self, script: &str) -> process::Command {
        let mut cmd = process::Command::new("ssh");
        cmd.arg("-T");
        cmd.arg("-o").arg("BatchMode=yes");
        for opt in &self.ssh_opts {
            for part in opt.split_whitespace() {
                cmd.arg(part);
            }
        }
        cmd.arg(&self.destination);
        cmd.arg(script);
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

    /// Collect ports without portview installed remotely, by shipping a shell
    /// probe over the same connection.
    pub fn run_agentless(&self) -> Result<Vec<PortInfo>, String> {
        let output = self
            .build_shell(crate::agentless::PROBE)
            .output()
            .map_err(|e| format!("Failed to run ssh: {}", e))?;

        // The probe is `|| true`-guarded throughout, so a non-zero status means
        // the connection itself failed rather than a missing remote tool.
        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_ssh_error(&self.destination, &stderr));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        crate::agentless::parse_probe(&text)
    }
}

/// Does this SSH failure mean portview simply is not installed on the far end?
/// That is the case agentless mode exists to handle; anything else (auth, DNS,
/// refused connections) should surface as a real error.
///
/// Shells word this differently and the remote shell is not ours to choose:
/// bash says "command not found", while dash and ash — `/bin/sh` on Debian and
/// Alpine, so most containers — say only "not found".
fn is_missing_remote_portview(stderr_or_msg: &str) -> bool {
    let s = stderr_or_msg.to_lowercase();
    s.contains("not found") || s.contains("not installed on") || s.contains("no such file")
}

fn classify_ssh_error(dest: &str, stderr: &str) -> String {
    let stderr_lower = stderr.to_lowercase();
    if is_missing_remote_portview(&stderr_lower) {
        format!(
            "portview is not installed on {}. Install with:\n  ssh {} 'curl -fsSL https://raw.githubusercontent.com/mapika/portview/main/install.sh | sh'",
            dest, dest
        )
    } else if stderr_lower.contains("permission denied") {
        format!(
            "SSH authentication failed for {}. Check your SSH keys.",
            dest
        )
    } else if stderr_lower.contains("connection refused")
        || stderr_lower.contains("no route")
        || stderr_lower.contains("could not resolve")
    {
        format!("Failed to connect to {}: {}", dest, stderr.trim())
    } else {
        format!("SSH error ({}): {}", dest, stderr.trim())
    }
}

// ── Top-level dispatcher ─────────────────────────────────────────────

pub(crate) fn run_ssh(
    destination: &str,
    remote_args: &[String],
    ssh_opts: &[String],
    use_color: bool,
    agentless: bool,
) {
    let ssh = SshCommand {
        destination: destination.to_string(),
        ssh_opts: ssh_opts.to_vec(),
    };

    // `remote_args` is declared with trailing_var_arg so that remote flags
    // (`watch --sort mem`) pass through untouched. The side effect is that clap
    // stops parsing our own flags once a positional appears, so
    // `ssh host 3000 --agentless` lands here instead of in `agentless`. Accept
    // it from either position and strip it, since forwarding it to the remote
    // portview would only make the remote reject it.
    let agentless = agentless || remote_args.iter().any(|a| a == "--agentless");
    let remote_args: Vec<String> = remote_args
        .iter()
        .filter(|a| *a != "--agentless")
        .cloned()
        .collect();

    let first_arg = remote_args.first().map(|s| s.as_str());

    // watch still needs portview on the far end: the TUI consumes a streaming
    // JSON pipe. doctor does not — its checks are pure functions over collected
    // data, so they run locally against what the probe brought back.
    if agentless && first_arg == Some("watch") {
        eprintln!(
            "--agentless does not support `watch`; it needs portview installed on {}.",
            destination
        );
        std::process::exit(1);
    }

    if agentless && first_arg == Some("doctor") {
        let json = remote_args.iter().any(|a| a == "--json");
        run_agentless_doctor(&ssh, use_color, json);
        return;
    }

    match first_arg {
        Some("watch") => {
            let mut args = vec!["watch", "--json"];
            for arg in &remote_args[1..] {
                args.push(arg.as_str());
            }
            run_ssh_tui(&ssh, &args, use_color);
        }
        Some("doctor") => {
            // Forward doctor output directly (no --json, keep formatting)
            let args: Vec<&str> = remote_args.iter().map(|s| s.as_str()).collect();
            run_ssh_passthrough(&ssh, &args);
        }
        _ => {
            let mut args = vec!["--json"];
            for arg in &remote_args {
                args.push(arg.as_str());
            }
            run_ssh_scan(&ssh, &args, use_color, agentless);
        }
    }
}

/// Diagnose a remote host without portview installed on it.
///
/// The probe brings back the same shapes the local collectors produce, so the
/// identical checks run here rather than a second implementation that drifts.
fn run_agentless_doctor(ssh: &SshCommand, use_color: bool, json: bool) {
    let ports = match ssh.run_agentless() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let evidence = crate::doctor::Evidence {
        stale_counts: crate::agentless::stale_counts(&ports),
        ports,
        // The probe does not query Docker on the far end, so the Docker check
        // is reported as skipped rather than silently passing on no data.
        docker: None,
    };

    let (diagnostics, results) = crate::doctor::diagnose(&evidence);
    if crate::doctor::render(&diagnostics, &results, use_color, json) {
        std::process::exit(1);
    }
}

fn run_ssh_passthrough(ssh: &SshCommand, remote_args: &[&str]) {
    match ssh.run_oneshot(remote_args) {
        Ok(output) => print!("{}", output),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

fn run_ssh_tui(ssh: &SshCommand, remote_args: &[&str], use_color: bool) {
    let mut cmd = ssh.build(remote_args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start SSH: {}", e);
            std::process::exit(1);
        }
    };

    let no_color = !use_color;
    if let Err(e) =
        crate::tui::run_remote_tui(&ssh.destination, ssh.ssh_opts.clone(), child, no_color)
    {
        eprintln!("TUI error: {}", e);
        std::process::exit(1);
    }
}

fn run_ssh_scan(ssh: &SshCommand, remote_args: &[&str], use_color: bool, agentless: bool) {
    let show_all = remote_args.iter().any(|a| *a == "--all" || *a == "-a");

    // Anything that is neither a flag nor the injected --json is a filter:
    // a port number or a process name, same as the local CLI accepts.
    let target: Option<&str> = remote_args
        .iter()
        .find(|a| !a.starts_with('-') && **a != "--json")
        .copied();

    let ports = if agentless {
        match ssh.run_agentless() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    } else {
        match ssh.run_oneshot(remote_args) {
            Ok(json_output) => match parse_port_json(&json_output) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to parse remote output: {}", e);
                    std::process::exit(1);
                }
            },
            // portview is not installed over there — fall back automatically
            // rather than telling the user to go install it.
            Err(e) if is_missing_remote_portview(&e) => {
                eprintln!(
                    "portview not found on {} — falling back to agentless mode (ss + ps over SSH).",
                    ssh.destination
                );
                match ssh.run_agentless() {
                    Ok(p) => p,
                    Err(agentless_err) => {
                        eprintln!("{}", agentless_err);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    };

    // The remote portview applied these itself; the agentless probe returns
    // everything, so filtering happens here.
    let ports = if agentless || ports.iter().any(|p| p.state != crate::TcpState::Listen) {
        let filtered = if show_all {
            ports
        } else {
            crate::agentless::filter_listening(ports)
        };
        match target {
            Some(t) => filter_target(filtered, t),
            None => filtered,
        }
    } else {
        ports
    };

    if ports.is_empty() {
        println!("No ports found on remote host.");
    } else {
        let colors = crate::ColorConfig::from_env();
        crate::display_port_table(&ports, use_color, &colors);
    }
}

/// Apply a port-number or process-name filter, matching local CLI behaviour.
fn filter_target(ports: Vec<PortInfo>, target: &str) -> Vec<PortInfo> {
    if let Ok(port) = target.parse::<u16>() {
        return ports.into_iter().filter(|p| p.port == port).collect();
    }
    let needle = target.to_lowercase();
    ports
        .into_iter()
        .filter(|p| {
            p.process_name.to_lowercase().contains(&needle)
                || p.command.to_lowercase().contains(&needle)
        })
        .collect()
}

/// Parse a portview JSON array (as emitted by `--json`) back into `Vec<PortInfo>`.
///
/// The parser is intentionally minimal — it handles the exact format produced by
/// `port_info_json()` and tolerates missing optional fields (`ppid`, `local_addr`)
/// for backwards compatibility with older portview versions.
pub(crate) fn parse_port_json(input: &str) -> Result<Vec<PortInfo>, String> {
    let input = input.trim();

    // Must start with '[' and end with ']'
    if !input.starts_with('[') || !input.ends_with(']') {
        return Err(format!(
            "expected JSON array, got: {}",
            &input[..input.len().min(40)]
        ));
    }

    let inner = &input[1..input.len() - 1].trim();

    if inner.is_empty() {
        return Ok(vec![]);
    }

    let objects = split_objects(inner)?;
    let mut result = Vec::with_capacity(objects.len());
    for obj in objects {
        result.push(parse_object(obj.trim())?);
    }
    Ok(result)
}

/// Split the inner content of a JSON array into individual top-level `{…}` objects.
/// Uses brace-depth tracking so nested objects (e.g. docker arrays) don't confuse it.
fn split_objects(s: &str) -> Result<Vec<&str>, String> {
    let mut objects = Vec::new();
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut start: Option<usize> = None;

    for (i, c) in s.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_string {
            match c {
                '\\' => escape_next = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0
                    && let Some(s_pos) = start
                {
                    objects.push(&s[s_pos..=i]);
                    start = None;
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err("unbalanced braces in JSON".to_string());
    }

    Ok(objects)
}

/// Parse a single JSON object `{…}` into a `PortInfo`.
fn parse_object(obj: &str) -> Result<PortInfo, String> {
    if !obj.starts_with('{') || !obj.ends_with('}') {
        return Err(format!(
            "expected JSON object, got: {}",
            &obj[..obj.len().min(40)]
        ));
    }

    // Collect key-value pairs at the top level only (depth == 1)
    let inner = &obj[1..obj.len() - 1];
    let pairs = extract_pairs(inner)?;

    let mut port: Option<u16> = None;
    let mut protocol = String::new();
    let mut pid: Option<u32> = None;
    let mut ppid: u32 = 0;
    let mut process_name = String::new();
    let mut command = String::new();
    let mut user = String::new();
    let mut state = TcpState::Unknown;
    let mut memory_bytes: u64 = 0;
    let mut cpu_seconds: f64 = 0.0;
    let mut children: u32 = 0;
    let mut local_addr: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    let mut start_time: Option<SystemTime> = None;

    for (key, value) in &pairs {
        match key.as_str() {
            "port" => port = Some(parse_u64(value)? as u16),
            "protocol" => protocol = parse_string(value)?,
            "pid" => pid = Some(parse_u64(value)? as u32),
            "ppid" => ppid = parse_u64(value)? as u32,
            "process" => process_name = parse_string(value)?,
            "command" => command = parse_string(value)?,
            "user" => user = parse_string(value)?,
            "state" => state = TcpState::from_state_str(&parse_string(value)?),
            "memory_bytes" => memory_bytes = parse_u64(value)?,
            "cpu_seconds" => cpu_seconds = parse_f64(value)?,
            "children" => children = parse_u64(value)? as u32,
            "local_addr" => {
                let s = parse_string(value)?;
                local_addr = s
                    .parse::<IpAddr>()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            }
            // Absent on portview < 1.7 and `null` when the remote could not
            // determine it; both mean "unknown", so a parse failure is not an
            // error here.
            "start_time_unix" => {
                start_time = parse_u64(value)
                    .ok()
                    .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
            }
            // "docker" and any other unknown fields are ignored
            _ => {}
        }
    }

    let port = port.ok_or_else(|| "missing required field: port".to_string())?;
    let pid = pid.ok_or_else(|| "missing required field: pid".to_string())?;

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
        assert_eq!(ports[0].state, TcpState::Listen);
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
    fn start_time_round_trips() {
        let json = r#"[{"port":3000,"protocol":"TCP","pid":1234,"ppid":1,"process":"node","command":"next dev","user":"mark","state":"LISTEN","memory_bytes":1000,"cpu_seconds":1.0,"children":0,"local_addr":"0.0.0.0","start_time_unix":1700000000}]"#;
        let ports = parse_port_json(json).unwrap();
        let secs = ports[0]
            .start_time
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(secs, 1_700_000_000);
    }

    #[test]
    fn start_time_absent_or_null_means_unknown() {
        // Absent: a remote running portview < 1.7. Null: the remote had a row
        // with no start time, e.g. a Docker-synthesised entry.
        for json in [
            r#"[{"port":80,"protocol":"TCP","pid":100,"process":"nginx","command":"nginx","user":"root","state":"LISTEN","memory_bytes":1,"cpu_seconds":0.0,"children":0}]"#,
            r#"[{"port":80,"protocol":"TCP","pid":100,"process":"nginx","command":"nginx","user":"root","state":"LISTEN","memory_bytes":1,"cpu_seconds":0.0,"children":0,"start_time_unix":null}]"#,
        ] {
            let ports = parse_port_json(json).expect("must stay parseable");
            assert!(ports[0].start_time.is_none());
        }
    }

    #[test]
    fn missing_portview_detected_across_shells() {
        // The remote shell is not ours to choose, and they word this
        // differently. Missing any of these means the agentless fallback
        // silently fails to engage.
        for stderr in [
            "bash: portview: command not found", // bash
            "sh: 1: portview: not found",        // dash (Debian /bin/sh)
            "sh: portview: not found",           // ash (Alpine)
            "zsh: command not found: portview",  // zsh
            "-bash: portview: No such file or directory",
        ] {
            assert!(
                is_missing_remote_portview(&stderr.to_lowercase()),
                "not detected: {}",
                stderr
            );
        }
    }

    #[test]
    fn real_connection_errors_do_not_trigger_the_fallback() {
        // Falling back on these would mask the actual problem.
        for stderr in [
            "permission denied (publickey).",
            "ssh: could not resolve hostname nope",
            "ssh: connect to host x port 22: connection refused",
            "host key verification failed.",
        ] {
            assert!(
                !is_missing_remote_portview(&stderr.to_lowercase()),
                "false positive: {}",
                stderr
            );
        }
    }

    #[test]
    fn parse_missing_optional_fields() {
        let json = r#"[{"port":80,"protocol":"TCP","pid":100,"process":"nginx","command":"nginx","user":"root","state":"LISTEN","memory_bytes":50000,"cpu_seconds":1.0,"children":2}]"#;
        let ports = parse_port_json(json).unwrap();
        assert_eq!(ports[0].ppid, 0);
        assert_eq!(ports[0].port, 80);
    }
}
