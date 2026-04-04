use std::io::{self, Write};

use crate::docker::{DockerPortMap, get_docker_port_map};
use crate::{PortInfo, json_escape, write_styled};

#[cfg(target_os = "linux")]
use crate::linux::get_port_infos;
#[cfg(target_os = "macos")]
use crate::macos::get_port_infos;
#[cfg(target_os = "windows")]
use crate::windows::get_port_infos;

// ── Data model ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Severity {
    Error,
    Warning,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

#[derive(Debug, Clone)]
struct Diagnostic {
    severity: Severity,
    check: &'static str,
    title: String,
    detail: String,
}

/// Tracks which check categories were run (for rendering pass/skip).
#[derive(Default)]
struct CheckResults {
    port_conflicts: bool,
    wildcard_exposure: bool,
    docker_host_conflicts: bool,
    stale_connections: bool,
    resource_hogs: bool,
}

// ── Rendering ───────────────────────────────────────────────────────

fn render_diagnostics(
    w: &mut impl Write,
    diagnostics: &[Diagnostic],
    results: &CheckResults,
    use_color: bool,
) {
    let _ = writeln!(w);

    render_check_category(
        w,
        diagnostics,
        "port_conflict",
        "No port conflicts",
        true,
        use_color,
    );
    render_check_category(
        w,
        diagnostics,
        "wildcard_exposure",
        "No wildcard exposure issues",
        true,
        use_color,
    );
    render_check_category(
        w,
        diagnostics,
        "docker_host_conflict",
        "No Docker-host conflicts",
        results.docker_host_conflicts,
        use_color,
    );
    render_check_category(
        w,
        diagnostics,
        "stale_connections",
        "No stale connections",
        true,
        use_color,
    );
    render_check_category(
        w,
        diagnostics,
        "resource_hogs",
        "No high-resource listeners",
        true,
        use_color,
    );

    // Summary
    let errors = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warnings = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();
    let _ = writeln!(w);
    if errors == 0 && warnings == 0 {
        write_styled(
            w,
            "  All clear \u{2014} no issues found\n",
            "green",
            use_color,
        );
    } else {
        let mut parts = Vec::new();
        if errors > 0 {
            parts.push(format!(
                "{} error{}",
                errors,
                if errors == 1 { "" } else { "s" }
            ));
        }
        if warnings > 0 {
            parts.push(format!(
                "{} warning{}",
                warnings,
                if warnings == 1 { "" } else { "s" }
            ));
        }
        write_styled(
            w,
            &format!("  {} found\n", parts.join(", ")),
            "bold",
            use_color,
        );
    }
}

fn render_check_category(
    w: &mut impl Write,
    diagnostics: &[Diagnostic],
    check_name: &str,
    pass_message: &str,
    was_run: bool,
    use_color: bool,
) {
    let issues: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.check == check_name)
        .collect();
    if issues.is_empty() {
        if was_run {
            write_styled(w, "  \u{2713} ", "green", use_color);
            let _ = writeln!(w, "{}", pass_message);
        }
    } else {
        for d in &issues {
            render_issue(w, d, use_color);
        }
    }
}

fn render_issue(w: &mut impl Write, d: &Diagnostic, use_color: bool) {
    match d.severity {
        Severity::Error => write_styled(w, "  \u{2717} ", "red", use_color),
        Severity::Warning => write_styled(w, "  ! ", "yellow", use_color),
    }
    let _ = writeln!(w, "{}", d.detail);
}

fn render_diagnostics_json(w: &mut impl Write, diagnostics: &[Diagnostic]) {
    if diagnostics.is_empty() {
        let _ = writeln!(w, "[]");
        return;
    }
    let _ = write!(w, "[");
    for (i, d) in diagnostics.iter().enumerate() {
        if i > 0 {
            let _ = write!(w, ",");
        }
        let _ = write!(
            w,
            r#"{{"severity":"{}","check":"{}","title":"{}","detail":"{}"}}"#,
            d.severity.label(),
            d.check,
            json_escape(&d.title),
            json_escape(&d.detail),
        );
    }
    let _ = writeln!(w, "]");
}

// ── Orchestrator ────────────────────────────────────────────────────

pub fn run_doctor(use_color: bool, json: bool) {
    let ports = get_port_infos(false);
    let docker_map = get_docker_port_map();
    let docker_available = !docker_map.is_empty();

    let mut diagnostics = Vec::new();
    let mut results = CheckResults::default();

    diagnostics.extend(check_port_conflicts(&ports));
    results.port_conflicts = true;

    diagnostics.extend(check_wildcard_exposure(&ports));
    results.wildcard_exposure = true;

    if docker_available {
        diagnostics.extend(check_docker_host_conflicts(&ports, &docker_map));
        results.docker_host_conflicts = true;
    }

    diagnostics.extend(check_stale_connections(&ports));
    results.stale_connections = true;

    diagnostics.extend(check_resource_hogs(&ports));
    results.resource_hogs = true;

    let has_errors = diagnostics.iter().any(|d| d.severity == Severity::Error);

    let mut out = io::stdout().lock();
    if json {
        render_diagnostics_json(&mut out, &diagnostics);
    } else {
        render_diagnostics(&mut out, &diagnostics, &results, use_color);
    }

    if has_errors {
        std::process::exit(1);
    }
}

// ── Check implementations ────────────────────────────────────────────

fn check_port_conflicts(ports: &[PortInfo]) -> Vec<Diagnostic> {
    use std::collections::HashMap;

    // Group LISTEN entries by (port, protocol)
    let mut groups: HashMap<(u16, &str), Vec<&PortInfo>> = HashMap::new();
    for p in ports {
        if p.state == crate::TcpState::Listen {
            groups
                .entry((p.port, p.protocol.as_str()))
                .or_default()
                .push(p);
        }
    }

    let mut diagnostics = Vec::new();
    let mut keys: Vec<_> = groups.keys().cloned().collect();
    keys.sort();

    for (port, protocol) in keys {
        let entries = &groups[&(port, protocol)];
        // Deduplicate by PID
        let mut pids: Vec<u32> = entries.iter().map(|p| p.pid).collect();
        pids.sort();
        pids.dedup();

        if pids.len() > 1 {
            let process_list: Vec<String> = pids
                .iter()
                .filter_map(|&pid| {
                    entries
                        .iter()
                        .find(|p| p.pid == pid)
                        .map(|p| format!("{} (PID {})", p.process_name, pid))
                })
                .collect();
            let detail = format!(
                "Port {}/{} has conflicting listeners: {}",
                port,
                protocol,
                process_list.join(", ")
            );
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                check: "port_conflict",
                title: format!("Port conflict on {}", port),
                detail,
            });
        }
    }

    diagnostics
}

fn check_wildcard_exposure(_ports: &[PortInfo]) -> Vec<Diagnostic> {
    Vec::new()
}

fn check_docker_host_conflicts(
    _ports: &[PortInfo],
    _docker_map: &DockerPortMap,
) -> Vec<Diagnostic> {
    Vec::new()
}

fn check_stale_connections(_ports: &[PortInfo]) -> Vec<Diagnostic> {
    Vec::new()
}

fn check_resource_hogs(_ports: &[PortInfo]) -> Vec<Diagnostic> {
    Vec::new()
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TcpState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn make_port(port: u16, pid: u32, name: &str, state: TcpState, addr: IpAddr) -> PortInfo {
        PortInfo {
            port,
            protocol: "TCP".to_string(),
            pid,
            process_name: name.to_string(),
            command: name.to_string(),
            user: "test".to_string(),
            state,
            memory_bytes: 100 * 1024 * 1024,
            cpu_seconds: 1.0,
            start_time: Some(SystemTime::now()),
            children: 0,
            local_addr: addr,
        }
    }

    // ── Task 3: check_port_conflicts ─────────────────────────────────

    #[test]
    fn conflict_two_pids_same_port() {
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ports = vec![
            make_port(3000, 1234, "node", TcpState::Listen, localhost),
            make_port(3000, 5678, "python3", TcpState::Listen, localhost),
        ];
        let result = check_port_conflicts(&ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Error);
        assert!(result[0].detail.contains("node"));
        assert!(result[0].detail.contains("python3"));
    }

    #[test]
    fn no_conflict_different_ports() {
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ports = vec![
            make_port(3000, 1234, "node", TcpState::Listen, localhost),
            make_port(4000, 5678, "python3", TcpState::Listen, localhost),
        ];
        let result = check_port_conflicts(&ports);
        assert!(result.is_empty());
    }

    #[test]
    fn no_conflict_same_pid() {
        let v4 = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
        let ports = vec![
            make_port(3000, 1234, "node", TcpState::Listen, v4),
            make_port(3000, 1234, "node", TcpState::Listen, v6),
        ];
        let result = check_port_conflicts(&ports);
        assert!(result.is_empty());
    }

    #[test]
    fn render_no_issues() {
        let diagnostics: Vec<Diagnostic> = vec![];
        let mut buf = Vec::new();
        render_diagnostics(&mut buf, &diagnostics, &CheckResults::default(), false);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("All clear"));
    }

    #[test]
    fn render_error_and_warning() {
        let diagnostics = vec![
            Diagnostic {
                severity: Severity::Error,
                check: "port_conflict",
                title: "Port conflict on 3000".to_string(),
                detail:
                    "Port 3000/TCP has conflicting listeners: node (PID 1234), python3 (PID 5678)"
                        .to_string(),
            },
            Diagnostic {
                severity: Severity::Warning,
                check: "stale_connections",
                title: "Stale connections on 8080".to_string(),
                detail: "Port 8080 has 73 TIME_WAIT connections \u{2014} possible connection leak"
                    .to_string(),
            },
        ];
        let results = CheckResults {
            port_conflicts: true,
            wildcard_exposure: false,
            docker_host_conflicts: false,
            stale_connections: true,
            resource_hogs: false,
        };
        let mut buf = Vec::new();
        render_diagnostics(&mut buf, &diagnostics, &results, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Port 3000/TCP has conflicting listeners"));
        assert!(output.contains("73 TIME_WAIT"));
        assert!(output.contains("1 error"));
        assert!(output.contains("1 warning"));
    }

    #[test]
    fn render_json_empty() {
        let diagnostics: Vec<Diagnostic> = vec![];
        let mut buf = Vec::new();
        render_diagnostics_json(&mut buf, &diagnostics);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "[]");
    }

    #[test]
    fn render_json_with_issues() {
        let diagnostics = vec![Diagnostic {
            severity: Severity::Error,
            check: "port_conflict",
            title: "test title".to_string(),
            detail: "test detail".to_string(),
        }];
        let mut buf = Vec::new();
        render_diagnostics_json(&mut buf, &diagnostics);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"severity\":\"error\""));
        assert!(output.contains("\"check\":\"port_conflict\""));
        assert!(output.contains("\"title\":\"test title\""));
        assert!(output.contains("\"detail\":\"test detail\""));
    }
}
