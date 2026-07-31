# Demo recordings

`demo.gif` and `mcp.gif` in this directory are the recordings embedded in the
top-level README. Both are generated — do not edit them by hand.

## Regenerating

```bash
cargo build --release
./demo/record.sh
```

Requires `asciinema`, `agg`, `tmux`, `node`, `python3`, and `unshare`
(util-linux). asciinema and agg ship as single binaries:

- <https://github.com/asciinema/asciinema/releases>
- <https://github.com/asciinema/agg/releases>

## Why it looks the way it does

**The recording runs inside an isolated namespace.** `record.sh` re-executes
itself under `unshare --user --map-root-user --net --pid --mount --uts`. This is
a privacy control, not a convenience. A terminal recording published to a public
README would otherwise capture:

- your username and hostname (the `USER` column, the shell prompt)
- absolute paths under your home directory (the `COMMAND` column)
- **every service you happen to have listening at the time**

Inside the namespace the user maps to `root`, the hostname is fixed to `devbox`,
`/opt` is a fresh tmpfs holding the demo services, and the network stack is
empty — so the only ports that can appear are the ones `stage.sh` starts.

**Recordings are scanned before rendering.** `assert_no_leaks` in `stage.sh`
greps each `.cast` for your username, home directory, hostname, and any
`/home/` or `/Users/` path, and aborts rather than producing a GIF. The
namespace stops most leaks but not all: Node's `fork()` uses
`process.execPath`, an absolute path that under nvm lives inside `$HOME`, and it
showed up in the `COMMAND` column until `api.js` was switched to `spawn`.

**asciinema, not VHS.** VHS drives a real browser and a `ttyd` server, both of
which open listening sockets — they appear in portview's own output and pollute
the demo. asciinema records the pty directly and opens no ports.

## The demo services

`services/` holds small but genuinely functional programs. Nothing in the
recordings is staged output:

| Service | Port | Purpose |
|---|---|---|
| `web.js` | 3000 | A plain web server |
| `api.js` | 8080 | A supervisor that spawns three workers on 8081–8083, giving tree mode a real process tree |
| `worker.py` | 5000 | A Python worker |
| `cache.js` | 6380 | Really does allocate ~1.2 GB, so doctor's "excessive memory" finding is a real detection |
| `ingest.js` | 7000 | Really does leak 16 CLOSE_WAIT sockets |

`ingest.js` doubles as a regression fixture: doctor does **not** currently report
that leak, because `get_port_infos` deduplicates by `(port, protocol, pid)` and
collapses all 16 sockets into one row. When that is fixed, this service must make
`portview doctor` report a connection leak on `:7000`.

## Editing the choreography

`drive-demo.sh` and `drive-mcp.sh` send keystrokes to a tmux session while
asciinema records it.

Two traps worth knowing:

- **Never send a literal `;`** to `tmux send-keys` — tmux parses it as a command
  separator and silently mangles the command. Use `C-l` to clear the screen.
- **`portview <port>` ends with an interactive `Kill process N? [y/N]` prompt.**
  The driver must answer it, or the next command is typed into the prompt.
