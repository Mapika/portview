# portview

See what's on your ports, then act on it.

A diagnostic-first port viewer for Linux and macOS. No more `lsof -i :3000 | grep LISTEN` incantations. One command shows you what's listening, who owns it, how long it's been running, and offers to kill it if you want.

~930 KB single binary. Zero runtime dependencies.

<p align="center">
  <img src="demo.gif" alt="portview --watch demo" width="100%" loop=infinite>
</p>

## Install

**One-liner** (downloads pre-built binary):

```bash
curl -fsSL https://raw.githubusercontent.com/mapika/portview/main/install.sh | sh
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

### Kill directly

```bash
portview -k 3000          # SIGTERM
portview -k 3000 --force  # SIGKILL
```

### Watch mode (live refresh)

```bash
portview --watch            # refresh all ports every 1s
portview -w 3000            # watch a specific port
portview -w node            # watch filtered by process name
portview -w --json          # streaming JSON, useful for piping
```

The display refreshes every second. Ctrl+C exits cleanly.

### JSON output

```bash
portview --json | jq '.[] | select(.process == "node")'
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

Defaults: `port=cyan, proto=dimmed, pid=yellow, user=green, process=bold, uptime=dimmed, mem=dimmed, command=white`

Use `--no-color` to disable all colors.

## What it shows

For each listening port:

| Field | Linux source | macOS source |
|-------|-------------|--------------|
| Port & protocol | `/proc/net/tcp`, `/proc/net/udp` | `proc_pidfdinfo` |
| PID | inode→pid mapping via `/proc/*/fd/` | `proc_listpids` |
| Process name | `/proc/<pid>/comm` | `proc_pidpath` |
| Full command | `/proc/<pid>/cmdline` | `proc_pidpath` |
| User | `/proc/<pid>/status` → `getpwuid` | `proc_pidinfo` → `getpwuid` |
| Uptime | `/proc/<pid>/stat` starttime + btime | `proc_pidinfo` start time |
| RSS memory | `/proc/<pid>/status` VmRSS | `proc_pidinfo` resident size |
| CPU time | `/proc/<pid>/stat` utime + stime | `proc_pidinfo` total user + system |
| Child count | `/proc/<pid>/task/<pid>/children` | `proc_listchildpids` |

Everything is read directly from the OS. No shelling out to `lsof`, `ss`, or `netstat`.

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

- Linux and macOS only. Windows is not supported.
- **Linux:** Needs read access to `/proc/<pid>/fd/` for inode→pid mapping. Some processes owned by other users may require `sudo`.
- **macOS:** Some processes owned by other users may not be visible without `sudo`.

## License

MIT
