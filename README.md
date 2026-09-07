# portview

[![CI](https://github.com/mapika/portview/actions/workflows/ci.yml/badge.svg)](https://github.com/mapika/portview/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portview)](https://crates.io/crates/portview)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

portview lists ports and the processes using them on Linux, macOS, and Windows.
It shows process names, commands, memory usage, and uptime. You can inspect a
port, stop its process, or monitor changes in an interactive terminal UI.

<p align="center">
  <img src="demo/demo.gif" alt="portview demo" width="100%" loop=infinite>
</p>

It also supports [Docker](#docker-integration), [remote hosts over SSH](#ssh-remote-mode),
and an [MCP server](#mcp-server-for-ai-agents) for coding agents.

## Install

Homebrew:

```bash
brew install mapika/tap/portview
```

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/mapika/portview/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/mapika/portview/main/install.ps1 | iex
```

Or use `cargo install portview`, or download a binary from
[Releases](https://github.com/mapika/portview/releases).

## What it does

```bash
portview                          # list all listening ports
portview 3000                     # inspect port 3000 in detail
portview node                     # find ports by process name
portview watch                    # interactive TUI with live refresh
portview watch --docker           # TUI with Docker containers as rows
portview kill 3000 --force        # terminate the process using port 3000
portview doctor                   # diagnose port conflicts and issues
portview ssh user@server          # inspect ports on a remote host
portview ssh user@server watch    # remote TUI over SSH
portview ssh user@server --agentless   # no portview needed on the remote
portview mcp                      # run as an MCP server for AI agents
```

## Features

### Scan

```
$ portview
╭──────┬───────┬─────┬──────────────┬──────┬────────────┬────────┬────────┬────────────────────────────╮
│ PORT │ PROTO │ PID │ ADDR         │ USER │ PROCESS    │ UPTIME │ MEM    │ COMMAND                    │
├──────┼───────┼─────┼──────────────┼──────┼────────────┼────────┼────────┼────────────────────────────┤
│ 3000 │ TCP   │ 8   │ 127.0.0.1    │ root │ node       │     7s │  44 MB │ node /opt/app/web.js       │
│ 5000 │ TCP   │ 11  │ 127.0.0.1    │ root │ python3.12 │     7s │  18 MB │ python3 /opt/app/worker.py │
│ 6380 │ TCP   │ 12  │ 127.0.0.1    │ root │ node       │     7s │ 1.2 GB │ node /opt/app/cache.js     │
│ 7000 │ TCP   │ 10  │ 127.0.0.1    │ root │ node       │     7s │  45 MB │ node /opt/app/ingest.js    │
│ 8080 │ TCP   │ 9   │ 127.0.0.1    │ root │ node       │     7s │  44 MB │ node /opt/app/api.js       │
╰──────┴───────┴─────┴──────────────┴──────┴────────────┴────────┴────────┴────────────────────────────╯
```

`--all` includes non-listening connections, with one row per connection.
`--wide` shows full commands. `--json` produces JSON output for scripts.

Ports whose owner can't be resolved are still listed, with `-` in the columns that can't be filled. That happens for another user's process without `sudo`, and for sockets like `TIME_WAIT` that outlive the process that opened them.

> The scan, doctor, and MCP examples below are real output, captured by [`demo/record.sh`](demo/README.md) inside an isolated namespace — which is why the user is `root` and the paths are `/opt/app`. The Docker example is illustrative, since it needs a running daemon.

### MCP server (for AI agents)

`portview mcp` provides port queries, diagnostics, and process termination over
the [Model Context Protocol](https://modelcontextprotocol.io) using stdio.
To register it with Claude Code:

```bash
claude mcp add portview -- portview mcp
```

Or configure it manually:

```json
{
  "mcpServers": {
    "portview": {
      "command": "portview",
      "args": ["mcp"]
    }
  }
}
```

| Tool | What it does |
|------|--------------|
| `list_ports` | List listening ports with available process details |
| `inspect_port` | Inspect a port, including process working directories and descendants |
| `find_process` | Find ports by process name or command substring |
| `doctor` | Check for conflicts, wildcard exposure, connection buildup, and high memory usage |
| `diff_ports` | Report ports that opened, closed, or changed owner since a baseline |
| `kill_port` | Terminate processes using a port; `dry_run` previews the targets. Marked destructive to the client |

<p align="center">
  <img src="demo/mcp.gif" alt="portview MCP server demo" width="100%" loop=infinite>
</p>

The MCP server is included in the portview binary. Pass `--read-only` to disable
the `kill_port` tool:

```bash
portview mcp --read-only
```

Listed in the [MCP Registry](https://registry.modelcontextprotocol.io) as
`mcp-name: io.github.Mapika/portview`.

### Watch mode (interactive TUI)

```bash
portview watch                    # live-refresh every 1s
portview watch --docker           # include Docker containers
portview watch --sort mem         # sort by memory on launch
```

| Key | Action |
|-----|--------|
| `j`/`k`, `↑`/`↓` | Navigate rows |
| `Enter` | Inspect port (full command, cwd, children, connections) |
| `d`/`D` | Kill process or manage Docker container |
| `/` | Filter across all columns |
| `←`/`→`, `r` | Cycle sort column, reverse direction |
| `t` | Toggle process tree view |
| `a` | Toggle all/listening-only |
| `q` | Quit |

**Tree view** (`t`): Groups child processes under their parents.

**Detail view** (`Enter`): Shows the full unwrapped command, working directory, child process list with ports, and open connections (in `--all` mode).

### Doctor

`portview doctor` checks for port conflicts, wildcard bindings, connection
buildup, and high memory usage:

```
$ portview doctor
  ✓ No port conflicts
  ✓ No wildcard exposure issues
  ! Port 7000 has 16 CLOSE_WAIT connections — possible connection leak
  ! node (PID 12) is listening on port 6380 and using 1.2 GB of memory

  2 warnings found
```

| Check | Flags |
|-------|-------|
| Port conflicts | Multiple PIDs bound to the same port |
| Wildcard exposure | Databases (postgres, redis, mysql, mongod, …) listening on `0.0.0.0` |
| Docker-host conflicts | A container publishing a port the host already uses |
| Connection buildup | High counts of TIME_WAIT or CLOSE_WAIT connections on one port; these do not by themselves establish a leak |
| High memory usage | Listening processes using more than 1 GB of resident memory |

Docker is auto-detected. `portview doctor --json` for scripting (exit code 1 on errors).

#### In CI

The GitHub Action runs `doctor` and can fail a workflow on errors or warnings:

```yaml
- uses: mapika/portview@v2
  with:
    fail-on: error        # error | warning | never
```

It annotates each finding inline on the run, writes a summary table, and exposes
`findings` (JSON), `count`, `errors`, and `warnings` as step outputs:

```yaml
- uses: mapika/portview@v2
  id: doctor
  with:
    fail-on: never
- run: echo '${{ steps.doctor.outputs.findings }}' | jq .
```

Set `install: false` if portview is already on PATH. Linux and macOS runners.

### SSH remote mode

Inspect ports on a remote host over SSH:

```bash
portview ssh user@server              # one-shot scan
portview ssh user@server watch        # full interactive TUI
portview ssh user@server doctor       # remote diagnostics
portview ssh user@server 3000         # inspect a remote port
portview ssh user@server --ssh-opt "-p 2222"  # custom SSH port
```

Kill actions in the remote TUI are forwarded over SSH.

If portview is not installed on the remote host, SSH mode collects data using
`ss` and `ps`, or `lsof` and `ps` where `ss` is unavailable. This requires a
POSIX shell and the collection tools on the remote host.

```
$ portview ssh user@server
portview not found on user@server — falling back to agentless mode (ss + ps over SSH).
╭──────┬───────┬─────┬──────────────┬──────┬─────────┬────────┬───────┬──────────────────────╮
│ PORT │ PROTO │ PID │ ADDR         │ USER │ PROCESS │ UPTIME │ MEM   │ COMMAND              │
├──────┼───────┼─────┼──────────────┼──────┼─────────┼────────┼───────┼──────────────────────┤
│ 3000 │ TCP   │ 6   │ 127.0.0.1    │ root │ node    │     3s │ 45 MB │ node /opt/app/web.js │
│ 8080 │ TCP   │ 7   │ 127.0.0.1    │ root │ node    │     3s │ 45 MB │ node /opt/app/api.js │
╰──────┴───────┴─────┴──────────────┴──────┴─────────┴────────┴───────┴──────────────────────╯
```

Use `--agentless` to collect data this way even when portview is installed on
the remote host. It supports scans, port inspection, process search,
diagnostics, and watch mode.

Run diagnostics on the collected data:

```bash
portview ssh user@server doctor --agentless
```

This uses the same diagnostic checks as local mode. The Docker check is
skipped because agentless mode does not query remote containers.

Watch remote ports, with process termination available in the TUI:

```bash
portview ssh user@server watch --agentless
```

Watch mode collects updates through a single persistent SSH connection.

### Docker integration

Use `--docker` to include ports published by Docker containers:

```
$ portview --docker
╭──────┬───────┬───────┬──────────────┬────────┬──────────┬────────┬────────┬────────────────────────────╮
│ PORT │ PROTO │ PID   │ ADDR         │ USER   │ PROCESS  │ UPTIME │ MEM    │ COMMAND                    │
├──────┼───────┼───────┼──────────────┼────────┼──────────┼────────┼────────┼────────────────────────────┤
│ 3000 │ TCP   │ 48291 │ 127.0.0.1    │ mark   │ node     │ 3h 12m │ 248 MB │ next dev [docker:web]      │
│ 8080 │ TCP   │ -     │ 0.0.0.0      │ docker │ pv-nginx │      - │      - │ nginx:alpine :8080->80/tcp │
╰──────┴───────┴───────┴──────────────┴────────┴──────────┴────────┴────────┴────────────────────────────╯
```

Container-only rows have no host process, so `PID`, `UPTIME`, and `MEM` render as `-`.

In watch mode, press `d` on a Docker row to stop or restart the container, or
follow its logs.

### JSON output

```bash
portview --json                   # pipe to jq, scripts, dashboards
portview --docker --json          # includes Docker ownership data
portview watch --json             # streaming JSON, one array per tick
portview doctor --json            # machine-readable diagnostics
```

### Custom colors

```bash
PORTVIEW_COLORS="port=red,pid=magenta,command=bright_cyan" portview
```

Columns: `port`, `proto`, `pid`, `user`, `process`, `uptime`, `mem`, `command`. Use `--no-color` to disable.

## How it works

Local port and process data comes from OS interfaces:

| Field | Linux | macOS | Windows |
|-------|-------|-------|---------|
| Ports | `/proc/net/tcp{,6}`, `udp{,6}` | `proc_pidfdinfo` | `GetExtendedTcp/UdpTable` |
| PID | inode→pid via `/proc/*/fd/` | `proc_listpids` | Included in socket table |
| Process | `/proc/<pid>/exe` | `proc_pidpath` | `QueryFullProcessImageNameW` |
| Memory | `/proc/<pid>/status` VmRSS | `proc_pidinfo` | `K32GetProcessMemoryInfo` |
| Uptime | `/proc/<pid>/stat` | `proc_pidinfo` | `GetProcessTimes` |

On Linux, portview reads the executable name from `/proc/<pid>/exe`.
The thread name in `/proc/<pid>/comm` can be changed by the runtime and is
limited to 15 bytes.

Docker integration uses the `docker` CLI. SSH mode uses the system `ssh`
client to run portview or the agentless collection tools on the remote host.
MCP mode uses newline-delimited JSON-RPC 2.0 on stdin/stdout.

## Building from source

```bash
git clone https://github.com/mapika/portview
cd portview
cargo build --release
```

Requires Rust 1.85+ (edition 2024). Shell completions and man page are generated at build time.

The repository includes a `Dockerfile`. To inspect the host from a container,
share the host's network and PID namespaces:

```bash
docker run --rm -i --network host --pid host portview
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines, and
[demo/README.md](demo/README.md) for regenerating the recordings.

Changes should type-check on all three platforms, not just yours:

```bash
cargo check --target aarch64-apple-darwin
cargo check --target x86_64-pc-windows-msvc
```

## Limitations

- **Linux:** Other users' ports are listed, but naming the process needs `sudo` (it reads `/proc/<pid>/fd/`). Rows you can't attribute show `-` for PID, user, process, and command rather than being hidden.
- **macOS:** Other users' ports are *not* listed without `sudo` — sockets are enumerated per process via `proc_pidfdinfo`, so a process that can't be opened contributes nothing to enumerate. For the same reason doctor cannot detect TIME_WAIT pileups there; CLOSE_WAIT is detected normally.
- **Windows:** Ports owned by inaccessible system processes are listed with the PID but `-` for name and user. Kill always force-terminates. Run as Administrator for full detail.
- **Docker:** Requires `docker` CLI and daemon access
- **SSH:** every command falls back to agentless collection when portview is missing on the remote, using `ss` + `ps` on Linux and `lsof` where `ss` does not exist. The remote needs one of those and a POSIX shell. Agentless collection cannot see Docker on the far end, so that check reports as skipped rather than passed.

## License

MIT
