# Process Tree View + Enhanced Detail View — Design Spec

## Summary

Two related improvements to the TUI watch mode:

1. **Tree view toggle** — press `t` to group port-owning processes by parent-child relationship with indented tree characters in the PROCESS column.
2. **Enhanced detail view** — pressing Enter on a row now shows open connections, child process list, full command with working directory, and Docker context.

Both require adding `ppid` to `PortInfo` (cheap on all platforms).

## Part 1: ppid Data Collection

### PortInfo change

Add `ppid: u32` field to `PortInfo` after `pid`.

### Platform implementations

- **Linux**: Extract `PPid:` from `/proc/{pid}/status` in the existing `parse_proc_status()` function. One additional line match — no new file reads.
- **macOS**: Read `task_info.pbsd.pbi_ppid` which is already populated by the existing `get_task_all_info()` call. Zero cost.
- **Windows**: Build a `HashMap<u32, u32>` (pid → ppid) from the existing `CreateToolhelp32Snapshot` enumeration in `build_child_count_map()`. Rename to `build_process_tree_map()` returning both child counts and ppid lookups.

### JSON output

Add `"ppid"` field to JSON output for all display modes. Placed after `"pid"`.

## Part 2: Tree View in TUI

### State

Add `tree_mode: bool` to `App` struct. Default `false`.

### Toggle

`t` key toggles `tree_mode`. No other keybinding changes.

### Tree ordering

When `tree_mode` is true, `sorted_ports()` is replaced with a tree-ordered list:

1. Collect all port-owning PIDs into a `HashSet`.
2. Build a `HashMap<u32, Vec<&PortInfo>>` mapping ppid to children (only where ppid is in the PID set — i.e., both parent and child own ports).
3. Roots = entries whose ppid is NOT in the PID set.
4. Sort roots by port ascending.
5. Walk depth-first: emit root, then its children (sorted by port), recursively.
6. Track depth and sibling position to determine tree characters.

### Tree characters in PROCESS column

Prepend to the process name cell:

- Root entries: no prefix (flush left)
- Non-last child: `├── ` (3 chars + space)
- Last child: `└── ` (3 chars + space)
- Nested deeper: `│   ` prefix per ancestor level for vertical continuation

Example:
```
PROCESS
node
├── node
│   └── node
└── node
postgres
```

### Sorting

When `tree_mode` is true:
- Sort keybindings (`<`, `>`, `r`, `1`-`9`, Left, Right) are ignored.
- Sort indicator is hidden from column headers.
- Footer hint changes from `t flat` to indicate current mode.

### Footer

- Normal mode: existing footer with `t tree` added
- Tree mode: replace sort hints with `t flat` (since sorting is disabled)

## Part 3: Enhanced Detail View

When pressing Enter on a row, the detail panel shows the existing info plus new sections.

### Current detail view (unchanged)

```
Port 3000 (TCP) — node (PID 1234)

  Bind:     *:3000
  Command:  next dev
  User:     mark
  Started:  3h 12m ago
  Memory:   248 MB
  CPU time: 14.3s
  Children: 3
  State:    LISTEN
```

### New sections

**Full command** (replaces the truncated one-liner):
```
  Command:  /home/mark/.nvm/versions/node/v20.11.0/bin/node
            /home/mark/projects/myapp/node_modules/.bin/next dev
```
Show the full, unwrapped command string. If it's multi-word, wrap at terminal width with indentation.

**Working directory** (Linux: `/proc/{pid}/cwd`, macOS: `proc_pidpath`, Windows: skip):
```
  Cwd:      /home/mark/projects/myapp
```

**Child processes** (using ppid data from port list + direct child PID enumeration):
```
  Children:
    PID 1235  node (worker)
    PID 1236  node (worker)
    PID 1237  node (worker)
```
Show up to 10 children with PID and process name. If more than 10, show `... and 5 more`. Only list children that own ports (from the current port list). If no port-owning children, fall back to showing the count as before.

**Open connections** (from non-LISTEN entries on the same port):
```
  Connections (3):
    ESTABLISHED  192.168.1.50:52341
    ESTABLISHED  192.168.1.51:52342
    TIME_WAIT    10.0.0.1:48001
```
Show up to 10 connections. Group by state. If more than 10, show `... and N more`. Data comes from `get_port_infos(false)` which already returns all states.

**Docker context** (when Docker is enabled and port has a Docker owner):
```
  Docker:
    Container:  my-app (abc123def456)
    Image:      myapp:latest
```

### Data collection for detail view

The detail view needs access to:
- Full (non-truncated) command — already in `PortInfo.command`, just not truncated in detail mode
- Working directory — new: read `/proc/{pid}/cwd` (Linux), `proc_pidpath` (macOS) on demand when detail view opens. Not stored in PortInfo (read on demand to avoid cost on every refresh).
- Non-LISTEN connections — call `get_port_infos(false)` and filter by the inspected port. Cache briefly or compute on demand when entering detail view.
- Child list — filter port list by ppid matching the selected PID.
- Docker context — already available in `docker_map`.

## Non-Goals

- No expand/collapse in tree view (all nodes always visible)
- No new subcommand (tree is TUI-only)
- No network byte stats
- No working directory on Windows (no cheap API)
- No tree structure in JSON output (flat array as before, just adds ppid field)
