use std::collections::HashMap;
use std::io::{self, Write};

use crate::docker::{DockerPortMap, get_docker_port_map};
use crate::{PortInfo, TcpState, json_escape, write_styled};

#[cfg(target_os = "linux")]
use crate::linux::{get_port_infos, get_stale_connection_counts};
#[cfg(target_os = "macos")]
use crate::macos::{get_port_infos, get_stale_connection_counts};
#[cfg(target_os = "windows")]
use crate::windows::{get_port_infos, get_stale_connection_counts};

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
pub(crate) struct Diagnostic {
    severity: Severity,
    check: &'static str,
    title: String,
    detail: String,
}

/// Tracks which check categories were run (for rendering pass/skip).
#[derive(Default)]
pub(crate) struct CheckResults {
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
        results.port_conflicts,
        use_color,
    );
    render_check_category(
        w,
        diagnostics,
        "wildcard_exposure",
        "No wildcard exposure issues",
        results.wildcard_exposure,
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
        results.stale_connections,
        use_color,
    );
    render_check_category(
        w,
        diagnostics,
        "resource_hogs",
        "No high-resource listeners",
        results.resource_hogs,
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

/// Everything the checks need, decoupled from where it was gathered.
///
/// The local collectors and the agentless SSH probe produce the same shapes, so
/// a remote host can be diagnosed with the identical checks rather than a second
/// implementation that drifts.
pub(crate) struct Evidence {
    pub ports: Vec<PortInfo>,
    pub stale_counts: HashMap<(u16, TcpState), u32>,
    /// `None` when Docker could not be inspected — which is different from an
    /// empty map, and is why the Docker check reports "skipped" rather than
    /// "passed" for a remote host.
    pub docker: Option<DockerPortMap>,
}

impl Evidence {
    /// Gather from the machine portview is running on.
    fn local() -> Self {
        let docker = get_docker_port_map();
        Self {
            ports: get_port_infos(false),
            stale_counts: get_stale_connection_counts(),
            docker: if docker.is_empty() {
                None
            } else {
                Some(docker)
            },
        }
    }
}

/// Run every check against gathered evidence. Pure — no I/O, no exit — so the
/// CLI renderer, MCP mode, and remote diagnosis can all drive it.
pub(crate) fn diagnose(evidence: &Evidence) -> (Vec<Diagnostic>, CheckResults) {
    let mut diagnostics = Vec::new();
    let mut results = CheckResults::default();

    diagnostics.extend(check_port_conflicts(&evidence.ports));
    results.port_conflicts = true;

    diagnostics.extend(check_wildcard_exposure(&evidence.ports));
    results.wildcard_exposure = true;

    if let Some(docker_map) = &evidence.docker {
        diagnostics.extend(check_docker_host_conflicts(&evidence.ports, docker_map));
        results.docker_host_conflicts = true;
    }

    diagnostics.extend(check_stale_connections(&evidence.stale_counts));
    results.stale_connections = true;

    diagnostics.extend(check_resource_hogs(&evidence.ports));
    results.resource_hogs = true;

    (diagnostics, results)
}

fn collect_diagnostics() -> (Vec<Diagnostic>, CheckResults) {
    diagnose(&Evidence::local())
}

/// Render a diagnosis. Returns true when anything error-severity was found, so
/// the caller decides the exit code — a remote diagnosis should not call
/// `process::exit` from inside a rendering helper.
pub(crate) fn render(
    diagnostics: &[Diagnostic],
    results: &CheckResults,
    use_color: bool,
    json: bool,
) -> bool {
    let mut out = io::stdout().lock();
    if json {
        render_diagnostics_json(&mut out, diagnostics);
    } else {
        render_diagnostics(&mut out, diagnostics, results, use_color);
    }
    diagnostics.iter().any(|d| d.severity == Severity::Error)
}

/// Diagnostics as a JSON array string. Used by MCP mode, which cannot let
/// `run_doctor` write to stdout (that channel carries JSON-RPC) or exit.
pub(crate) fn diagnostics_json_string() -> String {
    let (diagnostics, _) = collect_diagnostics();
    let mut buf: Vec<u8> = Vec::new();
    render_diagnostics_json(&mut buf, &diagnostics);
    // The CLI renderer terminates with a newline; a tool result should not.
    String::from_utf8_lossy(&buf).trim_end().to_owned()
}

pub fn run_doctor(use_color: bool, json: bool) {
    let (diagnostics, results) = collect_diagnostics();
    if render(&diagnostics, &results, use_color, json) {
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

fn check_wildcard_exposure(ports: &[PortInfo]) -> Vec<Diagnostic> {
    use std::net::IpAddr;

    const SENSITIVE_PROCESSES: &[&str] = &[
        "postgres",
        "redis",
        "redis-server",
        "mysql",
        "mysqld",
        "mariadbd",
        "mongod",
        "memcached",
        "elasticsearch",
    ];

    let mut diagnostics = Vec::new();

    for p in ports {
        if p.state != crate::TcpState::Listen {
            continue;
        }
        let is_unspecified = match p.local_addr {
            IpAddr::V4(a) => a.is_unspecified(),
            IpAddr::V6(a) => a.is_unspecified(),
        };
        if !is_unspecified {
            continue;
        }
        let name_lower = p.process_name.to_lowercase();
        if SENSITIVE_PROCESSES
            .iter()
            .any(|&s| name_lower == s.to_lowercase())
        {
            let addr_str = p.local_addr.to_string();
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                check: "wildcard_exposure",
                title: format!("{} exposed on wildcard address", p.process_name),
                detail: format!(
                    "{} is listening on {}:{} — consider binding to 127.0.0.1",
                    p.process_name, addr_str, p.port
                ),
            });
        }
    }

    diagnostics
}

fn check_docker_host_conflicts(ports: &[PortInfo], docker_map: &DockerPortMap) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    let mut docker_ports: Vec<u16> = docker_map.keys().cloned().collect();
    docker_ports.sort();

    for docker_port in docker_ports {
        let containers = &docker_map[&docker_port];
        // Find host LISTEN processes (pid != 0) on the same port
        let host_listeners: Vec<&PortInfo> = ports
            .iter()
            .filter(|p| p.port == docker_port && p.state == crate::TcpState::Listen && p.pid != 0)
            .collect();

        if !host_listeners.is_empty() {
            let container_names: Vec<&str> = containers
                .iter()
                .map(|c| c.container_name.as_str())
                .collect();
            let host_names: Vec<String> = host_listeners
                .iter()
                .map(|p| format!("{} (PID {})", p.process_name, p.pid))
                .collect();
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                check: "docker_host_conflict",
                title: format!("Docker-host conflict on port {}", docker_port),
                detail: format!(
                    "Port {} is used by Docker container(s) [{}] and host process(es) [{}]",
                    docker_port,
                    container_names.join(", "),
                    host_names.join(", "),
                ),
            });
        }
    }

    diagnostics
}

/// Takes counts gathered from the raw socket table rather than a `&[PortInfo]`.
/// `get_port_infos` deduplicates by (port, protocol, pid) and drops sockets with
/// no owning process, so counting its output yields at most 1 per port and these
/// thresholds could never trip.
fn check_stale_connections(counts: &HashMap<(u16, TcpState), u32>) -> Vec<Diagnostic> {
    let mut time_wait_counts: HashMap<u16, u32> = HashMap::new();
    let mut close_wait_counts: HashMap<u16, u32> = HashMap::new();

    for (&(port, state), &count) in counts {
        match state {
            TcpState::TimeWait => {
                *time_wait_counts.entry(port).or_insert(0) += count;
            }
            TcpState::CloseWait => {
                *close_wait_counts.entry(port).or_insert(0) += count;
            }
            _ => {}
        }
    }

    let mut diagnostics = Vec::new();

    let mut tw_ports: Vec<u16> = time_wait_counts.keys().cloned().collect();
    tw_ports.sort();
    for port in tw_ports {
        let count = time_wait_counts[&port];
        if count > 50 {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                check: "stale_connections",
                title: format!("Stale connections on {}", port),
                detail: format!(
                    "Port {} has {} TIME_WAIT connections \u{2014} possible connection leak",
                    port, count
                ),
            });
        }
    }

    let mut cw_ports: Vec<u16> = close_wait_counts.keys().cloned().collect();
    cw_ports.sort();
    for port in cw_ports {
        let count = close_wait_counts[&port];
        if count > 10 {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                check: "stale_connections",
                title: format!("Stale connections on {}", port),
                detail: format!(
                    "Port {} has {} CLOSE_WAIT connections \u{2014} possible connection leak",
                    port, count
                ),
            });
        }
    }

    diagnostics
}

fn check_resource_hogs(ports: &[PortInfo]) -> Vec<Diagnostic> {
    use std::collections::HashSet;

    const MEMORY_THRESHOLD: u64 = 1_000_000_000;

    let mut diagnostics = Vec::new();
    let mut seen_pids: HashSet<u32> = HashSet::new();

    for p in ports {
        if p.state != crate::TcpState::Listen {
            continue;
        }
        if seen_pids.contains(&p.pid) {
            continue;
        }
        if p.memory_bytes > MEMORY_THRESHOLD {
            seen_pids.insert(p.pid);
            let mem_str = crate::format_bytes(p.memory_bytes);
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                check: "resource_hogs",
                title: format!("{} is using excessive memory", p.process_name),
                detail: format!(
                    "{} (PID {}) is listening on port {} and using {} of memory",
                    p.process_name, p.pid, p.port, mem_str
                ),
            });
        }
    }

    diagnostics
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
            ppid: 0,
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

    // ── Task 4: check_wildcard_exposure ──────────────────────────────

    #[test]
    fn wildcard_postgres_flagged() {
        let wildcard = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ports = vec![make_port(5432, 100, "postgres", TcpState::Listen, wildcard)];
        let result = check_wildcard_exposure(&ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Warning);
        assert!(result[0].detail.contains("0.0.0.0"));
    }

    #[test]
    fn localhost_postgres_not_flagged() {
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ports = vec![make_port(
            5432,
            100,
            "postgres",
            TcpState::Listen,
            localhost,
        )];
        let result = check_wildcard_exposure(&ports);
        assert!(result.is_empty());
    }

    #[test]
    fn wildcard_unknown_process_not_flagged() {
        let wildcard = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ports = vec![make_port(8080, 200, "myapp", TcpState::Listen, wildcard)];
        let result = check_wildcard_exposure(&ports);
        assert!(result.is_empty());
    }

    // ── Task 5: check_docker_host_conflicts ──────────────────────────

    fn make_docker_map(port: u16, container: &str) -> DockerPortMap {
        use crate::docker::DockerPortOwner;
        let mut map = DockerPortMap::new();
        map.insert(
            port,
            vec![DockerPortOwner {
                container_id: "abc123".to_string(),
                container_name: container.to_string(),
                image: "test:latest".to_string(),
                container_port: 80,
                protocol: "TCP".to_string(),
            }],
        );
        map
    }

    #[test]
    fn docker_host_conflict_detected() {
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ports = vec![make_port(8080, 999, "nginx", TcpState::Listen, localhost)];
        let docker_map = make_docker_map(8080, "my-app");
        let result = check_docker_host_conflicts(&ports, &docker_map);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Error);
    }

    #[test]
    fn docker_no_conflict_different_port() {
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ports = vec![make_port(3000, 999, "node", TcpState::Listen, localhost)];
        let docker_map = make_docker_map(8080, "my-app");
        let result = check_docker_host_conflicts(&ports, &docker_map);
        assert!(result.is_empty());
    }

    #[test]
    fn docker_no_conflict_synthetic_entry() {
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        // pid=0 is a synthetic Docker entry
        let ports = vec![make_port(
            8080,
            0,
            "docker-proxy",
            TcpState::Listen,
            localhost,
        )];
        let docker_map = make_docker_map(8080, "my-app");
        let result = check_docker_host_conflicts(&ports, &docker_map);
        assert!(result.is_empty());
    }

    // ── Task 6: check_stale_connections ──────────────────────────────
    //
    // These previously built a Vec<PortInfo> of 51 entries with distinct PIDs
    // and passed — but the real pipeline can never produce that input, because
    // get_port_infos deduplicates by (port, protocol, pid) and drops sockets
    // with no owning process. The check was dead in practice while its tests
    // were green. The counts now come from the raw socket table, so the tests
    // below take the same shape the production caller does.

    #[test]
    fn stale_severity_is_warning() {
        let d = check_stale_connections(&counts(&[(3000, TcpState::TimeWait, 51)]));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].severity, Severity::Warning);
    }

    // ── Task 7: check_resource_hogs ──────────────────────────────────

    #[test]
    fn resource_hog_over_1gb_flagged() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut p = make_port(8080, 42, "bigapp", TcpState::Listen, addr);
        // 1.8 * 1024^3 = 1_932_735_283 bytes → format_bytes returns "1.8 GB"
        p.memory_bytes = 1_932_735_283;
        let result = check_resource_hogs(&[p]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Warning);
        assert!(result[0].detail.contains("1.8 GB"));
    }

    #[test]
    fn resource_normal_not_flagged() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let p = make_port(8080, 42, "app", TcpState::Listen, addr);
        // default memory_bytes is 100MB
        let result = check_resource_hogs(&[p]);
        assert!(result.is_empty());
    }

    #[test]
    fn resource_non_listener_not_flagged() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut p = make_port(8080, 42, "app", TcpState::Established, addr);
        p.memory_bytes = 2_000_000_000;
        let result = check_resource_hogs(&[p]);
        assert!(result.is_empty());
    }

    #[test]
    fn render_no_issues() {
        let diagnostics: Vec<Diagnostic> = vec![];
        let mut buf = Vec::new();
        let results = CheckResults {
            port_conflicts: true,
            wildcard_exposure: true,
            docker_host_conflicts: true,
            stale_connections: true,
            resource_hogs: true,
        };
        render_diagnostics(&mut buf, &diagnostics, &results, false);
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

    fn counts(entries: &[(u16, TcpState, u32)]) -> HashMap<(u16, TcpState), u32> {
        entries.iter().map(|&(p, s, c)| ((p, s), c)).collect()
    }

    #[test]
    fn close_wait_pileup_is_reported() {
        // The regression this guards: counts used to come from the deduplicated
        // PortInfo list, where 16 leaked sockets on one port collapsed to 1 and
        // the threshold could never trip.
        let d = check_stale_connections(&counts(&[(7000, TcpState::CloseWait, 16)]));
        assert_eq!(d.len(), 1);
        assert!(d[0].detail.contains("16 CLOSE_WAIT"), "{}", d[0].detail);
        assert!(d[0].detail.contains("7000"));
    }

    #[test]
    fn time_wait_pileup_is_reported() {
        let d = check_stale_connections(&counts(&[(8080, TcpState::TimeWait, 51)]));
        assert_eq!(d.len(), 1);
        assert!(d[0].detail.contains("51 TIME_WAIT"), "{}", d[0].detail);
    }

    #[test]
    fn counts_at_or_below_threshold_are_quiet() {
        // Thresholds are strictly-greater-than: >10 CLOSE_WAIT, >50 TIME_WAIT.
        let d = check_stale_connections(&counts(&[
            (7000, TcpState::CloseWait, 10),
            (8080, TcpState::TimeWait, 50),
        ]));
        assert!(d.is_empty(), "{:?}", d);
    }

    #[test]
    fn other_states_are_ignored() {
        let d = check_stale_connections(&counts(&[
            (3000, TcpState::Listen, 900),
            (3001, TcpState::Established, 900),
        ]));
        assert!(d.is_empty(), "{:?}", d);
    }

    #[test]
    fn each_offending_port_is_reported_once_in_port_order() {
        let d = check_stale_connections(&counts(&[
            (9000, TcpState::CloseWait, 12),
            (7000, TcpState::CloseWait, 20),
            (8080, TcpState::TimeWait, 60),
        ]));
        assert_eq!(d.len(), 3);
        // TIME_WAIT findings come first, then CLOSE_WAIT, each group by port.
        assert!(d[0].detail.contains("8080"), "{}", d[0].detail);
        assert!(d[1].detail.contains("7000"), "{}", d[1].detail);
        assert!(d[2].detail.contains("9000"), "{}", d[2].detail);
    }

    #[test]
    fn no_stale_sockets_means_no_findings() {
        assert!(check_stale_connections(&HashMap::new()).is_empty());
    }
}
