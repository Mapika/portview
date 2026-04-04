# portview doctor — Design Spec

## Summary

`portview doctor` is a diagnostic subcommand that scans all ports, connections, and Docker mappings to surface common problems: port conflicts, wildcard exposure, Docker-host collisions, stale connections, and high-resource listeners. Output is a checklist-style report with colored symbols.

## CLI Interface

```
portview doctor [--json] [--no-color]
```

- No `--docker` flag — Docker is auto-detected. If Docker is unavailable, Docker checks are silently skipped.
- Always scans all ports and states (calls `get_port_infos(false)`).
- `--json` emits a JSON array of diagnostics.
- `--no-color` disables colored output.

## Data Model

```rust
enum Severity {
    Error,
    Warning,
}

struct Diagnostic {
    severity: Severity,
    check: &'static str,   // check name for JSON output (e.g. "port_conflict")
    title: String,          // short summary
    detail: String,         // actionable message
}
```

Each check function has the signature:

```rust
fn check_X(ports: &[PortInfo], docker_map: &DockerPortMap) -> Vec<Diagnostic>
```

## Checks

### 1. Port conflicts (`check_port_conflicts`)

- Group all LISTEN entries by (port, protocol).
- If multiple distinct PIDs are listening on the same port+protocol: **Error**.
- Message: `"Port 3000/TCP has conflicting listeners: node (PID 1234), python3 (PID 5678)"`

### 2. Wildcard exposure (`check_wildcard_exposure`)

- For each LISTEN entry bound to `0.0.0.0` or `::` (all interfaces):
- Check process name against a known list: `postgres`, `redis`, `mysql`, `mysqld`, `mariadbd`, `mongod`, `memcached`, `elasticsearch`.
- If match: **Warning**.
- Message: `"postgres (PID 1203) is listening on 0.0.0.0:5432 — consider binding to 127.0.0.1"`

### 3. Docker-host conflicts (`check_docker_host_conflicts`)

- For each port in the Docker map, check if a non-Docker host process (pid != 0) is also listening on that port.
- If both a container and a host process claim the same port: **Error**.
- Message: `"Port 8080/TCP: host process python3 (PID 5678) conflicts with Docker container my-app"`

### 4. Stale connections (`check_stale_connections`)

- Group non-LISTEN entries by port.
- Count TIME_WAIT and CLOSE_WAIT per port.
- TIME_WAIT > 50: **Warning** — `"Port 3000 has 73 TIME_WAIT connections — possible connection leak"`
- CLOSE_WAIT > 10: **Warning** — `"Port 3000 has 15 CLOSE_WAIT connections — process may not be closing sockets"`

### 5. High resource listeners (`check_resource_hogs`)

- For each LISTEN process, flag if memory > 1 GB: **Warning**.
- Message: `"node (PID 1234) on port 3000 is using 1.8 GB memory"`

## Output Format

### Normal (terminal)

```
portview doctor

✓ No port conflicts
✗ postgres (PID 1203) is listening on 0.0.0.0:5432 — consider binding to 127.0.0.1
✗ redis (PID 1198) is listening on 0.0.0.0:6379 — consider binding to 127.0.0.1
✓ No Docker-host conflicts
! Port 8080 has 73 TIME_WAIT connections — possible connection leak
✓ No high-resource listeners

2 warnings, 1 error found
```

- `✓` green — check category passed (one summary line per category)
- `✗` red — error-severity issue (one line per issue)
- `!` yellow — warning-severity issue (one line per issue)
- Summary line at the end: count of errors and warnings, or "All clear — no issues found"

### JSON (`--json`)

```json
[
  {
    "severity": "warning",
    "check": "wildcard_exposure",
    "title": "postgres exposed on all interfaces",
    "detail": "postgres (PID 1203) is listening on 0.0.0.0:5432 — consider binding to 127.0.0.1"
  }
]
```

Empty array `[]` if no issues found.

## Exit Codes

- `0` — no issues, or warnings only
- `1` — at least one error-severity issue found

This enables `portview doctor` in CI/scripting: errors are actionable failures, warnings are informational.

## File Structure

Single new file: `src/doctor.rs` (~200-250 lines).

Contains:
- `Severity` enum and `Diagnostic` struct
- Five check functions
- `run_doctor()` orchestrator: collects data, runs checks, renders output
- `render_diagnostics()` for terminal output
- `render_diagnostics_json()` for JSON output

Integration:
- Add `Doctor` variant to `Command` enum in `src/cli.rs`
- Add match arm in `main()` in `src/main.rs`

## Non-Goals

- No TUI/interactive mode for doctor
- No auto-fix capabilities
- No network reachability checks (only local state)
- No custom threshold configuration (hardcoded for v1)
