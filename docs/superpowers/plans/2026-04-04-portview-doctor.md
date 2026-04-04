# portview doctor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `portview doctor` subcommand that scans all ports and Docker mappings to surface common problems — port conflicts, wildcard exposure, Docker-host collisions, stale connections, and high-resource listeners.

**Architecture:** Single-pass scan using existing `get_port_infos(false)` + `get_docker_port_map()`. Five check functions each return `Vec<Diagnostic>`. Results are rendered as a checklist (green checkmarks / red X / yellow bang). New file `src/doctor.rs` contains all logic. CLI wiring in `src/cli.rs` + `src/main.rs`.

**Tech Stack:** Rust, clap (CLI), crossterm (colored output), existing `write_styled()` helper.

---

### Task 1: Add Doctor subcommand to CLI and wire up dispatch

**Files:**
- Modify: `src/cli.rs` — add `Doctor` variant to `Command` enum
- Modify: `src/main.rs` — add `mod doctor`, match arm, and `run_doctor` stub
- Create: `src/doctor.rs` — empty `run_doctor()` function

- [ ] **Step 1: Add Doctor variant to Command enum in `src/cli.rs`**

Add after the `Completions` variant (line 97):

```rust
    /// Diagnose common port problems
    Doctor {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Disable all colors
        #[arg(long)]
        no_color: bool,
    },
```

- [ ] **Step 2: Create `src/doctor.rs` with a stub**

```rust
use std::io::{self, Write};

use crate::docker::DockerPortMap;
use crate::PortInfo;

pub fn run_doctor(use_color: bool, json: bool) {
    let mut out = io::stdout().lock();
    if json {
        let _ = writeln!(out, "[]");
    } else {
        let _ = writeln!(out, "All clear — no issues found");
    }
}
```

- [ ] **Step 3: Wire up in `src/main.rs`**

Add `mod doctor;` after `mod docker;` (line 25):

```rust
mod doctor;
```

Add match arm after the `Command::Completions` arm (after line 1272):

```rust
            Command::Doctor { json, no_color } => {
                let use_color = !no_color && atty_stdout();
                if *json {
                    doctor::run_doctor(use_color, true);
                } else {
                    doctor::run_doctor(use_color, false);
                }
                return;
            }
```

- [ ] **Step 4: Build and smoke test**

Run: `cargo build && cargo run -- doctor && cargo run -- doctor --json`

Expected:
```
All clear — no issues found
```
and
```
[]
```

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/main.rs src/doctor.rs
git commit -m "feat(doctor): add subcommand stub with CLI wiring"
```

---

### Task 2: Data model and check infrastructure

**Files:**
- Modify: `src/doctor.rs` — add `Severity`, `Diagnostic`, check runner, and renderer

- [ ] **Step 1: Write test for rendering diagnostics**

Add at the bottom of `src/doctor.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
                detail: "Port 3000/TCP has conflicting listeners: node (PID 1234), python3 (PID 5678)".to_string(),
            },
            Diagnostic {
                severity: Severity::Warning,
                check: "stale_connections",
                title: "Stale connections on 8080".to_string(),
                detail: "Port 8080 has 73 TIME_WAIT connections — possible connection leak".to_string(),
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p portview doctor::tests -- --nocapture`

Expected: Compilation errors — `Diagnostic`, `Severity`, `render_diagnostics`, etc. don't exist yet.

- [ ] **Step 3: Implement data model and renderers**

Replace the contents of `src/doctor.rs` (keeping the test module):

```rust
use std::io::{self, Write};

use crate::docker::{DockerPortMap, get_docker_port_map};
use crate::{PortInfo, TcpState, json_escape, write_styled};

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

/// Tracks which check categories produced any diagnostics.
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

    // Port conflicts
    let issues: Vec<_> = diagnostics.iter().filter(|d| d.check == "port_conflict").collect();
    if issues.is_empty() {
        write_styled(w, "  \u{2713} ", "green", use_color);
        let _ = writeln!(w, "No port conflicts");
    } else {
        for d in &issues {
            render_issue(w, d, use_color);
        }
    }

    // Wildcard exposure
    let issues: Vec<_> = diagnostics.iter().filter(|d| d.check == "wildcard_exposure").collect();
    if issues.is_empty() {
        write_styled(w, "  \u{2713} ", "green", use_color);
        let _ = writeln!(w, "No wildcard exposure issues");
    } else {
        for d in &issues {
            render_issue(w, d, use_color);
        }
    }

    // Docker-host conflicts
    let issues: Vec<_> = diagnostics.iter().filter(|d| d.check == "docker_host_conflict").collect();
    if issues.is_empty() && results.docker_host_conflicts {
        write_styled(w, "  \u{2713} ", "green", use_color);
        let _ = writeln!(w, "No Docker-host conflicts");
    } else if !issues.is_empty() {
        for d in &issues {
            render_issue(w, d, use_color);
        }
    }
    // If docker_host_conflicts is false, docker wasn't available — skip silently

    // Stale connections
    let issues: Vec<_> = diagnostics.iter().filter(|d| d.check == "stale_connections").collect();
    if issues.is_empty() {
        write_styled(w, "  \u{2713} ", "green", use_color);
        let _ = writeln!(w, "No stale connections");
    } else {
        for d in &issues {
            render_issue(w, d, use_color);
        }
    }

    // Resource hogs
    let issues: Vec<_> = diagnostics.iter().filter(|d| d.check == "resource_hogs").collect();
    if issues.is_empty() {
        write_styled(w, "  \u{2713} ", "green", use_color);
        let _ = writeln!(w, "No high-resource listeners");
    } else {
        for d in &issues {
            render_issue(w, d, use_color);
        }
    }

    // Summary
    let errors = diagnostics.iter().filter(|d| d.severity == Severity::Error).count();
    let warnings = diagnostics.iter().filter(|d| d.severity == Severity::Warning).count();
    let _ = writeln!(w);
    if errors == 0 && warnings == 0 {
        write_styled(w, "  All clear — no issues found\n", "green", use_color);
    } else {
        let mut parts = Vec::new();
        if errors > 0 {
            parts.push(format!("{} error{}", errors, if errors == 1 { "" } else { "s" }));
        }
        if warnings > 0 {
            parts.push(format!("{} warning{}", warnings, if warnings == 1 { "" } else { "s" }));
        }
        write_styled(w, &format!("  {} found\n", parts.join(", ")), "bold", use_color);
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

// ── Check stubs (implemented in subsequent tasks) ───────────────────

fn check_port_conflicts(_ports: &[PortInfo]) -> Vec<Diagnostic> {
    Vec::new()
}

fn check_wildcard_exposure(_ports: &[PortInfo]) -> Vec<Diagnostic> {
    Vec::new()
}

fn check_docker_host_conflicts(_ports: &[PortInfo], _docker_map: &DockerPortMap) -> Vec<Diagnostic> {
    Vec::new()
}

fn check_stale_connections(_ports: &[PortInfo]) -> Vec<Diagnostic> {
    Vec::new()
}

fn check_resource_hogs(_ports: &[PortInfo]) -> Vec<Diagnostic> {
    Vec::new()
}
```

- [ ] **Step 4: Make `write_styled` and `json_escape` accessible from doctor.rs**

In `src/main.rs`, change the visibility of `write_styled` (line 469) and `json_escape` (line 968) from private to `pub(crate)`:

```rust
pub(crate) fn write_styled(w: &mut impl Write, text: &str, color_name: &str, use_color: bool) {
```

```rust
pub(crate) fn json_escape(s: &str) -> String {
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test doctor::tests -- --nocapture`

Expected: All 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/doctor.rs src/main.rs
git commit -m "feat(doctor): add data model, renderer, and orchestrator with check stubs"
```

---

### Task 3: Implement `check_port_conflicts`

**Files:**
- Modify: `src/doctor.rs`

- [ ] **Step 1: Write the test**

Add to `doctor::tests`:

```rust
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

    #[test]
    fn conflict_two_pids_same_port() {
        let ports = vec![
            make_port(3000, 100, "node", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            make_port(3000, 200, "python3", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];
        let result = check_port_conflicts(&ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Error);
        assert!(result[0].detail.contains("node"));
        assert!(result[0].detail.contains("python3"));
    }

    #[test]
    fn no_conflict_different_ports() {
        let ports = vec![
            make_port(3000, 100, "node", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            make_port(5432, 200, "postgres", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];
        let result = check_port_conflicts(&ports);
        assert!(result.is_empty());
    }

    #[test]
    fn no_conflict_same_pid() {
        let ports = vec![
            make_port(3000, 100, "node", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            make_port(3000, 100, "node", TcpState::Listen, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let result = check_port_conflicts(&ports);
        assert!(result.is_empty());
    }
```

- [ ] **Step 2: Run tests to verify the new tests fail**

Run: `cargo test doctor::tests::conflict -- --nocapture`

Expected: Tests fail (stubs return empty Vec).

- [ ] **Step 3: Implement `check_port_conflicts`**

Replace the stub in `src/doctor.rs`:

```rust
fn check_port_conflicts(ports: &[PortInfo]) -> Vec<Diagnostic> {
    use std::collections::HashMap;

    let mut by_port: HashMap<(u16, &str), Vec<&PortInfo>> = HashMap::new();
    for p in ports {
        if p.state != TcpState::Listen {
            continue;
        }
        by_port
            .entry((p.port, p.protocol.as_str()))
            .or_default()
            .push(p);
    }

    let mut results = Vec::new();
    for ((port, proto), listeners) in &by_port {
        // Deduplicate by PID (same process can listen on v4 + v6)
        let mut seen_pids = std::collections::HashSet::new();
        let unique: Vec<&&PortInfo> = listeners
            .iter()
            .filter(|p| seen_pids.insert(p.pid))
            .collect();

        if unique.len() > 1 {
            let names: Vec<String> = unique
                .iter()
                .map(|p| format!("{} (PID {})", p.process_name, p.pid))
                .collect();
            results.push(Diagnostic {
                severity: Severity::Error,
                check: "port_conflict",
                title: format!("Port conflict on {}/{}", port, proto),
                detail: format!(
                    "Port {}/{} has conflicting listeners: {}",
                    port,
                    proto,
                    names.join(", ")
                ),
            });
        }
    }
    results
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test doctor::tests -- --nocapture`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/doctor.rs
git commit -m "feat(doctor): implement port conflict detection"
```

---

### Task 4: Implement `check_wildcard_exposure`

**Files:**
- Modify: `src/doctor.rs`

- [ ] **Step 1: Write the tests**

Add to `doctor::tests`:

```rust
    #[test]
    fn wildcard_postgres_flagged() {
        let ports = vec![
            make_port(5432, 100, "postgres", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];
        let result = check_wildcard_exposure(&ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Warning);
        assert!(result[0].detail.contains("0.0.0.0"));
    }

    #[test]
    fn localhost_postgres_not_flagged() {
        let ports = vec![
            make_port(5432, 100, "postgres", TcpState::Listen, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let result = check_wildcard_exposure(&ports);
        assert!(result.is_empty());
    }

    #[test]
    fn wildcard_unknown_process_not_flagged() {
        let ports = vec![
            make_port(8080, 100, "myapp", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];
        let result = check_wildcard_exposure(&ports);
        assert!(result.is_empty());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test doctor::tests::wildcard -- --nocapture`

Expected: `wildcard_postgres_flagged` fails (stub returns empty).

- [ ] **Step 3: Implement `check_wildcard_exposure`**

Replace the stub:

```rust
fn check_wildcard_exposure(ports: &[PortInfo]) -> Vec<Diagnostic> {
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

    let mut results = Vec::new();
    for p in ports {
        if p.state != TcpState::Listen {
            continue;
        }
        let is_wildcard = p.local_addr.is_unspecified();
        if !is_wildcard {
            continue;
        }
        let name_lower = p.process_name.to_lowercase();
        if SENSITIVE_PROCESSES.iter().any(|s| *s == name_lower) {
            results.push(Diagnostic {
                severity: Severity::Warning,
                check: "wildcard_exposure",
                title: format!("{} exposed on all interfaces", p.process_name),
                detail: format!(
                    "{} (PID {}) is listening on {}:{} \u{2014} consider binding to 127.0.0.1",
                    p.process_name, p.pid, p.local_addr, p.port
                ),
            });
        }
    }
    results
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test doctor::tests -- --nocapture`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/doctor.rs
git commit -m "feat(doctor): implement wildcard exposure detection"
```

---

### Task 5: Implement `check_docker_host_conflicts`

**Files:**
- Modify: `src/doctor.rs`

- [ ] **Step 1: Write the tests**

Add to `doctor::tests`:

```rust
    use crate::docker::DockerPortOwner;

    fn make_docker_map(port: u16, container: &str) -> DockerPortMap {
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
        let ports = vec![
            make_port(8080, 500, "nginx", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];
        let docker_map = make_docker_map(8080, "my-app");
        let result = check_docker_host_conflicts(&ports, &docker_map);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Error);
        assert!(result[0].detail.contains("nginx"));
        assert!(result[0].detail.contains("my-app"));
    }

    #[test]
    fn docker_no_conflict_different_port() {
        let ports = vec![
            make_port(3000, 500, "node", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];
        let docker_map = make_docker_map(8080, "my-app");
        let result = check_docker_host_conflicts(&ports, &docker_map);
        assert!(result.is_empty());
    }

    #[test]
    fn docker_no_conflict_synthetic_entry() {
        // pid=0 means it's a synthesized Docker entry, not a real host process
        let ports = vec![
            make_port(8080, 0, "my-app", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];
        let docker_map = make_docker_map(8080, "my-app");
        let result = check_docker_host_conflicts(&ports, &docker_map);
        assert!(result.is_empty());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test doctor::tests::docker -- --nocapture`

Expected: `docker_host_conflict_detected` fails.

- [ ] **Step 3: Implement `check_docker_host_conflicts`**

Replace the stub:

```rust
fn check_docker_host_conflicts(ports: &[PortInfo], docker_map: &DockerPortMap) -> Vec<Diagnostic> {
    let mut results = Vec::new();
    for (docker_port, owners) in docker_map {
        // Find host processes (non-synthetic, pid != 0) listening on this port
        let host_listeners: Vec<&PortInfo> = ports
            .iter()
            .filter(|p| p.port == *docker_port && p.state == TcpState::Listen && p.pid != 0)
            .collect();

        if host_listeners.is_empty() {
            continue;
        }

        for host in &host_listeners {
            let container_names: Vec<&str> = owners
                .iter()
                .map(|o| o.container_name.as_str())
                .collect();
            results.push(Diagnostic {
                severity: Severity::Error,
                check: "docker_host_conflict",
                title: format!("Docker-host conflict on port {}", docker_port),
                detail: format!(
                    "Port {}/TCP: host process {} (PID {}) conflicts with Docker container {}",
                    docker_port,
                    host.process_name,
                    host.pid,
                    container_names.join(", ")
                ),
            });
        }
    }
    results
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test doctor::tests -- --nocapture`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/doctor.rs
git commit -m "feat(doctor): implement Docker-host conflict detection"
```

---

### Task 6: Implement `check_stale_connections`

**Files:**
- Modify: `src/doctor.rs`

- [ ] **Step 1: Write the tests**

Add to `doctor::tests`:

```rust
    #[test]
    fn stale_time_wait_flagged() {
        let mut ports = Vec::new();
        for i in 0..51 {
            ports.push(make_port(3000, 100 + i, "node", TcpState::TimeWait, IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        }
        let result = check_stale_connections(&ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Warning);
        assert!(result[0].detail.contains("TIME_WAIT"));
    }

    #[test]
    fn stale_close_wait_flagged() {
        let mut ports = Vec::new();
        for i in 0..11 {
            ports.push(make_port(5432, 200 + i, "postgres", TcpState::CloseWait, IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        }
        let result = check_stale_connections(&ports);
        assert_eq!(result.len(), 1);
        assert!(result[0].detail.contains("CLOSE_WAIT"));
    }

    #[test]
    fn stale_below_threshold_not_flagged() {
        let mut ports = Vec::new();
        for i in 0..10 {
            ports.push(make_port(3000, 100 + i, "node", TcpState::TimeWait, IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        }
        let result = check_stale_connections(&ports);
        assert!(result.is_empty());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test doctor::tests::stale -- --nocapture`

Expected: `stale_time_wait_flagged` and `stale_close_wait_flagged` fail.

- [ ] **Step 3: Implement `check_stale_connections`**

Replace the stub:

```rust
fn check_stale_connections(ports: &[PortInfo]) -> Vec<Diagnostic> {
    use std::collections::HashMap;

    let mut time_wait: HashMap<u16, u32> = HashMap::new();
    let mut close_wait: HashMap<u16, u32> = HashMap::new();

    for p in ports {
        match p.state {
            TcpState::TimeWait => *time_wait.entry(p.port).or_default() += 1,
            TcpState::CloseWait => *close_wait.entry(p.port).or_default() += 1,
            _ => {}
        }
    }

    let mut results = Vec::new();

    for (port, count) in &time_wait {
        if *count > 50 {
            results.push(Diagnostic {
                severity: Severity::Warning,
                check: "stale_connections",
                title: format!("Stale TIME_WAIT on port {}", port),
                detail: format!(
                    "Port {} has {} TIME_WAIT connections \u{2014} possible connection leak",
                    port, count
                ),
            });
        }
    }

    for (port, count) in &close_wait {
        if *count > 10 {
            results.push(Diagnostic {
                severity: Severity::Warning,
                check: "stale_connections",
                title: format!("Stale CLOSE_WAIT on port {}", port),
                detail: format!(
                    "Port {} has {} CLOSE_WAIT connections \u{2014} process may not be closing sockets",
                    port, count
                ),
            });
        }
    }

    results
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test doctor::tests -- --nocapture`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/doctor.rs
git commit -m "feat(doctor): implement stale connection detection"
```

---

### Task 7: Implement `check_resource_hogs`

**Files:**
- Modify: `src/doctor.rs`

- [ ] **Step 1: Write the tests**

Add to `doctor::tests`:

```rust
    #[test]
    fn resource_hog_over_1gb_flagged() {
        let mut p = make_port(3000, 100, "node", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        p.memory_bytes = 1_800_000_000; // 1.8 GB
        let result = check_resource_hogs(&[p]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Warning);
        assert!(result[0].detail.contains("1.8 GB"));
    }

    #[test]
    fn resource_normal_not_flagged() {
        let p = make_port(3000, 100, "node", TcpState::Listen, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        // default is 100 MB from make_port
        let result = check_resource_hogs(&[p]);
        assert!(result.is_empty());
    }

    #[test]
    fn resource_non_listener_not_flagged() {
        let mut p = make_port(3000, 100, "node", TcpState::Established, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        p.memory_bytes = 2_000_000_000;
        let result = check_resource_hogs(&[p]);
        assert!(result.is_empty());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test doctor::tests::resource -- --nocapture`

Expected: `resource_hog_over_1gb_flagged` fails.

- [ ] **Step 3: Implement `check_resource_hogs`**

Replace the stub:

```rust
fn check_resource_hogs(ports: &[PortInfo]) -> Vec<Diagnostic> {
    const ONE_GB: u64 = 1_000_000_000;

    let mut results = Vec::new();
    let mut seen_pids = std::collections::HashSet::new();

    for p in ports {
        if p.state != TcpState::Listen {
            continue;
        }
        if !seen_pids.insert(p.pid) {
            continue; // already reported this PID
        }
        if p.memory_bytes > ONE_GB {
            results.push(Diagnostic {
                severity: Severity::Warning,
                check: "resource_hogs",
                title: format!("{} using excessive memory", p.process_name),
                detail: format!(
                    "{} (PID {}) on port {} is using {}",
                    p.process_name,
                    p.pid,
                    p.port,
                    crate::format_bytes(p.memory_bytes),
                ),
            });
        }
    }
    results
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test doctor::tests -- --nocapture`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/doctor.rs
git commit -m "feat(doctor): implement high-resource listener detection"
```

---

### Task 8: Final integration test, clippy, and cleanup

**Files:**
- Modify: `src/doctor.rs` (if needed)

- [ ] **Step 1: Run full test suite**

Run: `cargo test`

Expected: All tests pass (87 existing + new doctor tests).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy`

Expected: No warnings.

- [ ] **Step 3: Run fmt**

Run: `cargo fmt`

- [ ] **Step 4: Smoke test the full doctor command**

Run: `cargo run -- doctor`

Expected: Checklist output with real system data. Verify symbols render correctly.

Run: `cargo run -- doctor --json`

Expected: JSON array output.

Run: `cargo run -- doctor --no-color`

Expected: Same output without ANSI escape codes.

- [ ] **Step 5: Verify help text**

Run: `cargo run -- doctor --help`

Expected:
```
Diagnose common port problems

Usage: portview doctor [OPTIONS]

Options:
      --json      Output as JSON
      --no-color  Disable all colors
  -h, --help      Print help
```

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat(doctor): complete portview doctor with all five diagnostic checks"
```
