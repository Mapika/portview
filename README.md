# portview

[![CI](https://github.com/mapika/portview/actions/workflows/ci.yml/badge.svg)](https://github.com/mapika/portview/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portview)](https://crates.io/crates/portview)

See what's on your ports, then act on it.

A diagnostic-first port viewer for Linux, macOS, and Windows. No more `lsof -i :3000 | grep LISTEN` incantations. One command shows you what's listening, who owns it, how long it's been running, and offers to kill it if you want. Optional Docker-aware diagnostics are available with `--docker`.

~960 KB single binary. Zero runtime dependencies.

<p align="center">
  <img src="demo.gif" alt="portview --watch demo" width="100%" loop=infinite>
</p>

## Install

**One-liner** (downloads pre-built binary):

```bash
curl -fsSL https://raw.githubusercontent.com/mapika/portview/main/install.sh | sh
```

**PowerShell** (Windows):

```powershell
irm https://raw.githubusercontent.com/mapika/portview/main/install.ps1 | iex
```

**Homebrew**:

```bash
brew install mapika/tap/portview
```

**Cargo** (build from source):

```bash
cargo install portview
```

**Manual**: grab the binary from [Releases](https://github.com/mapika/portview/releases), `chmod +x`, drop in PATH.

## Usage

Preferred CLI style uses subcommands (`watch`, `kill`).
Legacy flags (`--watch`, `--kill`) are still supported.

### Show all listening ports

```
$ portview
╭──────┬───────┬───────┬──────┬──────────┬─────────┬────────┬─────────────────────────────────────╮
│ PORT │ PROTO │ PID   │ USER │ PROCESS  │ UPTIME  │ MEM    │ COMMAND                             │
├──────┼───────┼───────┼──────┼──────────┼─────────┼────────┼─────────────────────────────────────┤
│ 3000 │ TCP   │ 48291 │ mark │ node     │ 3h 12m  │ 248 MB │ next dev                            │
│ 5432 │ TCP   │ 1203  │ pg   │ postgres │ 14d 2h  │ 38 MB  │ /usr/lib/postgresql/16/bin/postgres │
│ 6379 │ TCP   │ 1198  │ redis│ redis    │ 14d 2h  │ 12 MB  │ redis-server *:6379                 │
│ 8080 │ TCP   │ 51002 │ mark │ python3  │ 22m     │ 45 MB  │ uvicorn main:app --port 8080        │
╰──────┴───────┴───────┴──────┴──────────┴─────────┴────────┴─────────────────────────────────────╯
```

### Inspect a specific port

```
$ portview 3000

Port 3000 (TCP) — node (PID 48291)
  Bind:     *:3000
  Command:  next dev
  User:     mark
  Started:  3h 12m ago
  Memory:   248 MB
  CPU time: 14.3s
  Children: 3
  State:    LISTEN

  Kill process 48291? [y/N]
```

### Search by process name

```
$ portview python
╭──────┬───────┬───────┬──────┬─────────┬────────┬───────┬──────────────────────────────────╮
│ PORT │ PROTO │ PID   │ USER │ PROCESS │ UPTIME │ MEM   │ COMMAND                          │
├──────┼───────┼───────┼──────┼─────────┼────────┼───────┼──────────────────────────────────┤
│ 8000 │ TCP   │ 51002 │ mark │ python3 │ 22m    │ 45 MB │ uvicorn main:app --port 8000     │
│ 8080 │ TCP   │ 51340 │ mark │ python3 │ 5m     │ 32 MB │ python3 -m http.server 8080      │
╰──────┴───────┴───────┴──────┴─────────┴────────┴───────┴──────────────────────────────────╯
```

### Docker-aware annotations

```bash
portview --docker
portview --docker 3000
portview --docker --json
```

When Docker is running, `--docker` annotates output with container ownership (`[docker:<container>]`) and includes a `docker` array per row in JSON mode.

### Kill directly

```bash
portview kill 3000          # SIGTERM (Unix) / TerminateProcess (Windows)
portview kill 3000 --force  # SIGKILL (Unix) / TerminateProcess (Windows)
```

> **Note:** On Windows, `portview kill` always force-terminates the process via `TerminateProcess`. There is no graceful shutdown equivalent to Unix SIGTERM.

### Watch mode (interactive TUI)

```bash
portview watch            # interactive TUI, refreshes every 1s
portview watch 3000       # watch a specific port
portview watch node       # watch filtered by process name
portview watch --docker   # interactive TUI with Docker context
portview watch --json     # streaming JSON, useful for piping
portview watch --json --docker # streaming JSON with Docker ownership
```

Watch mode opens an interactive TUI with a scrollable table, row selection, filtering, and kill confirmation.

#### Keybindings

**Table view:**

| Key | Action |
|-----|--------|
| `j` / `↓` | Select next row |
| `k` / `↑` | Select previous row |
| `g` / `Home` | Jump to first row |
| `G` / `End` | Jump to last row |
| `Enter` | Inspect selected port (detail view) |
| `d` | Kill process (SIGTERM, with confirmation) |
| `D` | Force kill (SIGKILL, with confirmation) |
| `/` | Enter filter mode |
| `<` / `>` | Cycle sort column left / right |
| `r` | Reverse sort direction |
| `1`-`8` | Jump to column N (same column toggles direction) |
| `a` | Toggle all/listening-only ports |
| `q` / `Esc` | Quit |
| `Ctrl+C` | Quit |

**Detail view:** `Esc` to go back, `d`/`D` to kill, `q` to quit.

**Filter mode:** Type to filter across all columns, `Enter` to apply, `Esc` to cancel and clear.

**Kill popup:** `y`/`Enter` to confirm, `n`/`Esc` to cancel.

Use `watch --json` for non-interactive streaming JSON output (no TUI).
With `--docker`, watch mode shows mapped container hints in the table and full Docker mapping details in the detail view.

### JSON output

```bash
portview --json | jq '.[] | select(.process == "node")'
portview --docker --json | jq '.[] | {port, process, docker}'
```

### Show all connections (not just listening)

```bash
portview --all
```

### Custom colors

Table columns are colored by default. Customize with the `PORTVIEW_COLORS` environment variable:

```bash
PORTVIEW_COLORS="port=red,pid=magenta,command=bright_cyan" portview
```

Available columns: `port`, `proto`, `pid`, `user`, `process`, `uptime`, `mem`, `command`

Available colors: `red`, `green`, `blue`, `cyan`, `yellow`, `magenta`, `white`, `bold`, `dimmed`, `bright_red`, `bright_green`, `bright_blue`, `bright_cyan`, `bright_yellow`, `bright_magenta`, `bright_white`, `none`

One-shot defaults: `port=cyan, proto=dimmed, pid=yellow, user=green, process=bold, uptime=dimmed, mem=dimmed, command=white`

Watch mode uses a soft RGB color palette by default. Set `PORTVIEW_COLORS` to override, or `--no-color` to disable all colors.

## What it shows

For each listening port:

| Field | Linux source | macOS source | Windows source |
|-------|-------------|--------------|----------------|
| Port & protocol | `/proc/net/tcp`, `/proc/net/udp` | `proc_pidfdinfo` | `GetExtendedTcpTable` / `GetExtendedUdpTable` |
| PID | inode→pid mapping via `/proc/*/fd/` | `proc_listpids` | Included in socket table |
| Process name | `/proc/<pid>/comm` | `proc_pidpath` | `QueryFullProcessImageNameW` |
| Full command | `/proc/<pid>/cmdline` | `proc_pidpath` | `QueryFullProcessImageNameW` |
| User | `/proc/<pid>/status` → `getpwuid` | `proc_pidinfo` → `getpwuid` | `OpenProcessToken` → `LookupAccountSidW` |
| Uptime | `/proc/<pid>/stat` starttime + btime | `proc_pidinfo` start time | `GetProcessTimes` |
| RSS memory | `/proc/<pid>/status` VmRSS | `proc_pidinfo` resident size | `K32GetProcessMemoryInfo` WorkingSetSize |
| CPU time | `/proc/<pid>/stat` utime + stime | `proc_pidinfo` total user + system | `GetProcessTimes` kernel + user |
| Child count | `/proc/<pid>/task/<pid>/children` | `proc_listchildpids` | `CreateToolhelp32Snapshot` |

Core process/port data is read directly from the OS. No shelling out to `lsof`, `ss`, `netstat`, or `netsh`.
When Docker-aware mode is enabled (`--docker`), ownership is collected from `docker ps`.

## Why not...

| Tool | Issue |
|------|-------|
| `lsof -i :3000` | Different flags per OS, cryptic output, slow |
| `ss -tlnp` | Powerful but unreadable, no uptime/memory info |
| `fkill-cli` | Node.js dependency, kill-first not diagnostic-first |
| `killport` | Rust but kill-only, no inspection |
| `procs` | General process viewer, not port-centric |

portview is diagnostic-first: understand what's on your ports, then optionally act.

## Building from source

```bash
git clone https://github.com/mapika/portview
cd portview
cargo build --release
cp target/release/portview /usr/local/bin/
```

## Limitations

- **Linux:** Needs read access to `/proc/<pid>/fd/` for inode→pid mapping. Processes owned by other users are hidden without `sudo`.
- **macOS:** Processes owned by other users may not be visible without `sudo`.
- **Windows:** Some system/protected processes may not be accessible. `portview kill` always force-terminates (no graceful SIGTERM equivalent). Run as Administrator to see all processes.
- **Docker integration:** `--docker` requires the `docker` CLI and access to the Docker daemon.

## License

MIT
