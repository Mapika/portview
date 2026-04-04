# portview ssh — Remote Mode Design Spec

## Summary

Add `portview ssh user@host` to inspect ports on remote machines. Shells out to the system `ssh` binary, runs `portview --json` remotely, and renders the output locally. Supports one-shot scan, TUI watch mode, port inspection, and doctor — all remote. Actions (kill, Docker) are forwarded as separate SSH invocations.

## CLI Interface

```
portview ssh user@host                  # one-shot scan
portview ssh user@host watch            # interactive TUI
portview ssh user@host 3000             # inspect remote port
portview ssh user@host doctor           # run doctor remotely
portview ssh user@host watch --docker   # TUI with Docker context
portview ssh user@host --all            # include non-listening
```

The `ssh` subcommand takes a `destination` (user@host, host, or any SSH destination string) followed by an optional remote subcommand and flags.

### Flags

- `--json` — output remote JSON directly to stdout (pass-through, no local rendering)
- `--no-color` — disable colors on local output
- `--ssh-opt <OPT>` — pass extra options to the SSH command (e.g. `--ssh-opt "-p 2222"` for custom port)

## Architecture

### One-shot mode

1. Build command: `ssh <destination> portview --json [flags...]`
2. Run via `std::process::Command`, capture stdout
3. Parse JSON array from stdout
4. Deserialize into `Vec<PortInfo>`
5. Render with the existing `display_table()` locally

### TUI watch mode

1. Build command: `ssh <destination> portview watch --json [flags...]`
2. Spawn via `std::process::Command` with piped stdout
3. In the TUI event loop, read one JSON line per tick from the SSH pipe
4. Parse each line into `Vec<PortInfo>`
5. Replace `app.ports` with the parsed data
6. Render locally using the existing TUI (same render_table, tree mode, etc.)
7. On quit, kill the SSH child process

### Remote port inspection

`portview ssh user@host 3000` → runs `ssh user@host portview 3000 --json` → parses the detail JSON → renders locally with `display_detail()`.

### Remote doctor

`portview ssh user@host doctor` → runs `ssh user@host portview doctor --json` → parses doctor JSON → renders locally with doctor's renderer.

### Remote actions (kill, Docker)

When the user presses `d`/`D` in the remote TUI to kill a process:

1. Spawn a separate SSH command: `ssh <destination> portview kill <port> [--force]`
2. Capture stdout/stderr
3. Show result in the TUI status bar
4. The main watch SSH process continues streaming — the next tick will reflect the change

Docker actions (stop, restart, logs) work the same way — spawn a separate SSH command for each action.

## JSON Deserialization

The remote portview outputs JSON with this structure (per entry):

```json
{
  "port": 3000,
  "protocol": "TCP",
  "pid": 1234,
  "ppid": 1,
  "process": "node",
  "command": "next dev",
  "user": "mark",
  "state": "LISTEN",
  "memory_bytes": 248000000,
  "cpu_seconds": 14.3,
  "children": 3
}
```

Deserialize into `PortInfo`. Fields mapping:
- `"process"` → `process_name`
- `"state"` → parse back into `TcpState` enum
- `local_addr` is not in JSON currently — default to `0.0.0.0` for remote entries
- `start_time` is not in JSON — compute from context or leave as None

### Missing fields handling

Some fields aren't in the current JSON output:
- `local_addr` — not present. Add it to JSON output as part of this work.
- `start_time` — not directly serializable. Use `uptime_seconds` in JSON instead, reconstruct `start_time` from `SystemTime::now() - Duration::from_secs(uptime_seconds)`.

Both changes to JSON output should be backwards-compatible additions.

## SSH Command Builder

```rust
struct SshCommand {
    destination: String,
    ssh_opts: Vec<String>,
}

impl SshCommand {
    fn build(&self, remote_args: &[&str]) -> std::process::Command {
        let mut cmd = std::process::Command::new("ssh");
        // Disable pseudo-terminal for non-interactive
        cmd.arg("-T");
        // Batch mode — fail fast instead of prompting
        cmd.arg("-o").arg("BatchMode=yes");
        for opt in &self.ssh_opts {
            cmd.arg(opt);
        }
        cmd.arg(&self.destination);
        cmd.arg("portview");
        for arg in remote_args {
            cmd.arg(arg);
        }
        cmd
    }
}
```

## Error Handling

| Error | Detection | Message |
|-------|-----------|---------|
| SSH connection failed | Non-zero exit, stderr contains "Connection refused" / "No route" | `"Failed to connect to <host>: <ssh error>"` |
| Remote portview not found | stderr contains "command not found" or "No such file" | `"portview is not installed on <host>. Install with:\n  ssh <host> 'curl -fsSL https://raw.githubusercontent.com/mapika/portview/main/install.sh \| sh'"` |
| Remote portview too old | JSON parse fails on missing fields | Graceful degradation — fill missing fields with defaults |
| SSH auth failed | stderr contains "Permission denied" | `"SSH authentication failed for <host>. Check your SSH keys."` |
| Pipe broken mid-TUI | Read returns EOF or error | Show "Connection lost" in status bar, exit cleanly |

## TUI Differences in Remote Mode

- Title bar shows `portview@<host>` instead of just `portview`
- Kill confirmation popup mentions it's a remote action
- Docker popup actions are forwarded over SSH
- `a` (toggle all) is NOT supported in remote TUI mode — the remote `--all` flag is set at launch time. (Changing it would require restarting the SSH process.)

## File Structure

| File | Purpose |
|------|---------|
| `src/ssh.rs` | SshCommand builder, JSON deserializer, remote action executor, remote TUI orchestrator |
| `src/cli.rs` | Add `Ssh` variant to Command enum |
| `src/main.rs` | Add dispatch for `Command::Ssh`, add `local_addr` and uptime to JSON output |
| `src/tui.rs` | Add `remote: Option<SshRemote>` to App, use it for data refresh and actions |

## No New Dependencies

Uses only `std::process::Command` for SSH. No SSH libraries.

## Non-Goals

- No auto-deployment of portview binary to remote host
- No embedded SSH client (uses system ssh)
- No multi-host support (one host per invocation)
- No SSH config file parsing (delegated to the ssh binary)
- No remote `portview watch` with local `--sort`/tree mode toggle for the `a` (all) flag — set at launch
