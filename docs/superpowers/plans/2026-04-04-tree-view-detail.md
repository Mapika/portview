# Process Tree View + Enhanced Detail View — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ppid to PortInfo on all platforms, add a tree-view toggle (`t` key) in the TUI, and enhance the detail view with open connections, child list, full command, and working directory.

**Architecture:** Add `ppid: u32` field to PortInfo. Extract ppid cheaply on each platform (Linux: /proc status, macOS: pbi_ppid, Windows: PROCESSENTRY32W). Tree view is a `tree_mode` bool on App that changes how `sorted_ports()` orders results and prepends tree chars to the PROCESS column. Enhanced detail view reads additional data on-demand when entering detail mode.

**Tech Stack:** Rust, ratatui (TUI), crossterm, platform FFI (libc/libproc/windows-sys).

---

## File Structure

| File | Changes |
|------|---------|
| `src/main.rs` | Add `ppid: u32` to `PortInfo`, add ppid to JSON output, add `get_cwd()` helper (Linux/macOS) |
| `src/linux.rs` | Extract ppid from `/proc/{pid}/status`, add `get_process_cwd()` |
| `src/macos.rs` | Extract `pbi_ppid` from existing task_info |
| `src/windows.rs` | Build ppid map from existing snapshot, pass to PortInfo |
| `src/tui.rs` | Add `tree_mode` to App, tree ordering logic, tree chars in PROCESS column, `t` keybinding, enhanced detail view, footer update |

---

### Task 1: Add ppid field to PortInfo and update Linux extraction

**Files:**
- Modify: `src/main.rs:38-52` — add ppid field to PortInfo
- Modify: `src/linux.rs:188-211` — extract PPid from parse_proc_status
- Modify: `src/linux.rs:291-311` — pass ppid into PortInfo construction
- Modify: `src/main.rs:1005-1018` — add ppid to JSON output

- [ ] **Step 1: Add ppid to PortInfo struct**

In `src/main.rs`, add `ppid: u32` after the `pid` field (line 42):

```rust
pub(crate) struct PortInfo {
    pub(crate) port: u16,
    pub(crate) protocol: String,
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) process_name: String,
    pub(crate) command: String,
    pub(crate) user: String,
    pub(crate) state: TcpState,
    pub(crate) memory_bytes: u64,
    pub(crate) cpu_seconds: f64,
    pub(crate) start_time: Option<SystemTime>,
    pub(crate) children: u32,
    pub(crate) local_addr: IpAddr,
}
```

- [ ] **Step 2: Update Linux parse_proc_status to return ppid**

In `src/linux.rs`, change `parse_proc_status` to return a tuple of 3 values:

```rust
fn parse_proc_status(pid: u32) -> (u32, u32, u64) {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
    let mut uid = 0u32;
    let mut ppid = 0u32;
    let mut rss_bytes = 0u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            rss_bytes = kb * 1024;
        }
    }
    (uid, ppid, rss_bytes)
}
```

- [ ] **Step 3: Update Linux get_port_infos to use ppid**

In `src/linux.rs`, update the caller (line 291) and PortInfo construction:

Change:
```rust
let (uid, rss_bytes) = parse_proc_status(pid);
```
To:
```rust
let (uid, ppid, rss_bytes) = parse_proc_status(pid);
```

Add `ppid,` after `pid,` in the PortInfo construction (around line 301):
```rust
            pid,
            ppid,
            process_name: get_process_name(pid),
```

- [ ] **Step 4: Fix all other PortInfo constructions that now need ppid**

Search the codebase for all `PortInfo {` constructions. Each needs `ppid: 0,` (or the real value) after `pid`. Files to update:

In `src/main.rs`, find all PortInfo constructions (synthesize_docker_entries and test helpers) and add `ppid: 0,` after `pid`.

In `src/doctor.rs` tests, the `make_port` helper needs `ppid: 0,` added.

In `src/tui.rs` tests, the `make_port_info` or `make_test_app` helpers need `ppid: 0,` added.

In `src/windows.rs`, all three PortInfo constructions need `ppid: 0,` (will be updated with real values in Task 3).

In `src/macos.rs`, the PortInfo construction needs `ppid: 0,` (will be updated in Task 2).

- [ ] **Step 5: Add ppid to JSON output**

In `src/main.rs`, update `port_info_json` (line 1005-1018). Add `ppid` after `pid`:

Change the format string from:
```rust
r#"{{"port":{},"protocol":"{}","pid":{},"process":"{}",..."#
```
To:
```rust
r#"{{"port":{},"protocol":"{}","pid":{},"ppid":{},"process":"{}",..."#
```
And add `info.ppid,` as the corresponding argument.

- [ ] **Step 6: Build and test**

Run: `cargo build && cargo test`

Expected: All tests pass. (On Linux, ppid is populated. On other platforms, it's 0 for now.)

- [ ] **Step 7: Commit**

```bash
git add src/main.rs src/linux.rs src/macos.rs src/windows.rs src/doctor.rs src/tui.rs
git commit -m "feat: add ppid field to PortInfo, extract on Linux"
```

---

### Task 2: Add ppid extraction on macOS

**Files:**
- Modify: `src/macos.rs:500-518` — pass pbi_ppid into PortInfo

- [ ] **Step 1: Extract ppid from task_info**

In `src/macos.rs`, in the `get_port_infos` function, after line 500 (`let children = count_children(pid);`), add:

```rust
        let ppid = task_info.as_ref().map(|t| t.pbsd.pbi_ppid).unwrap_or(0);
```

- [ ] **Step 2: Pass ppid into PortInfo construction**

In the `for hit in hits` loop (line 504), change the PortInfo construction to include ppid:

```rust
            infos.push(PortInfo {
                port: hit.local_port,
                protocol: hit.protocol,
                pid: pid as u32,
                ppid,
                process_name: process_name.clone(),
```

- [ ] **Step 3: Build (macOS cross-check)**

Run: `cargo build`

Expected: Compiles. (Can only fully test on macOS, but compilation confirms struct fields match.)

- [ ] **Step 4: Commit**

```bash
git add src/macos.rs
git commit -m "feat: extract ppid on macOS from pbi_ppid"
```

---

### Task 3: Add ppid extraction on Windows

**Files:**
- Modify: `src/windows.rs:394-418` — return ppid map alongside child count map
- Modify: `src/windows.rs:422-549` — pass ppid into PortInfo

- [ ] **Step 1: Change build_child_count_map to also return ppid map**

Rename and change the return type:

```rust
fn build_process_maps() -> (HashMap<u32, u32>, HashMap<u32, u32>) {
    let mut children_count: HashMap<u32, u32> = HashMap::new();
    let mut ppid_map: HashMap<u32, u32> = HashMap::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return (children_count, ppid_map);
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            ppid_map.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            if entry.th32ParentProcessID != 0 {
                *children_count.entry(entry.th32ParentProcessID).or_insert(0) += 1;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    (children_count, ppid_map)
}
```

- [ ] **Step 2: Update get_port_infos caller**

Change line 424 from:
```rust
    let child_map = build_child_count_map();
```
To:
```rust
    let (child_map, ppid_map) = build_process_maps();
```

- [ ] **Step 3: Add ppid to all three PortInfo constructions in windows.rs**

For each PortInfo construction, add `ppid: ppid_map.get(&pid).copied().unwrap_or(0),` after the `pid,` field. There are three: line ~458 (minimal info), line ~480 (limited access), line ~517 (full access).

- [ ] **Step 4: Build**

Run: `cargo build`

Expected: Compiles.

- [ ] **Step 5: Commit**

```bash
git add src/windows.rs
git commit -m "feat: extract ppid on Windows from process snapshot"
```

---

### Task 4: Add tree mode toggle and tree ordering to TUI

**Files:**
- Modify: `src/tui.rs` — add tree_mode to App, tree_ordered_ports method, toggle keybinding, footer update

- [ ] **Step 1: Add tree_mode to App struct**

In `src/tui.rs`, add `tree_mode: bool` to the App struct (after `sort_direction`):

```rust
    sort_column: SortColumn,
    sort_direction: SortDirection,
    tree_mode: bool,
```

Initialize it to `false` in `App::new()` and the test helper `make_test_app`.

- [ ] **Step 2: Add tree_ordered_ports method**

Add this method to `impl App`, after `sorted_ports()`:

```rust
    fn tree_ordered_ports(&self) -> Vec<(&PortInfo, u16, bool)> {
        let filtered = self.filtered_ports();

        // Build set of PIDs that own ports
        let pid_set: std::collections::HashSet<u32> = filtered.iter().map(|p| p.pid).collect();

        // Group children by parent pid (only if parent is in pid_set)
        let mut children_of: std::collections::HashMap<u32, Vec<&PortInfo>> =
            std::collections::HashMap::new();
        let mut roots: Vec<&PortInfo> = Vec::new();

        for p in &filtered {
            if p.ppid != 0 && pid_set.contains(&p.ppid) {
                children_of.entry(p.ppid).or_default().push(p);
            } else {
                roots.push(p);
            }
        }

        // Sort roots by port
        roots.sort_by_key(|p| p.port);
        // Sort children by port
        for children in children_of.values_mut() {
            children.sort_by_key(|p| p.port);
        }

        // Walk depth-first
        let mut result: Vec<(&PortInfo, u16, bool)> = Vec::new();

        fn walk<'a>(
            pid: u32,
            info: &'a PortInfo,
            depth: u16,
            is_last: bool,
            children_of: &std::collections::HashMap<u32, Vec<&'a PortInfo>>,
            result: &mut Vec<(&'a PortInfo, u16, bool)>,
        ) {
            result.push((info, depth, is_last));
            if let Some(children) = children_of.get(&pid) {
                let len = children.len();
                for (i, child) in children.iter().enumerate() {
                    walk(child.pid, child, depth + 1, i == len - 1, children_of, result);
                }
            }
        }

        for root in &roots {
            walk(root.pid, root, 0, true, &children_of, &mut result);
        }

        result
    }
```

The return type is `Vec<(&PortInfo, depth, is_last_sibling)>`.

- [ ] **Step 3: Update selected_port and other methods that call sorted_ports**

Add a helper that returns the display-ordered list regardless of mode:

```rust
    fn display_ports(&self) -> Vec<&PortInfo> {
        if self.tree_mode {
            self.tree_ordered_ports().into_iter().map(|(p, _, _)| p).collect()
        } else {
            self.sorted_ports()
        }
    }
```

Update `selected_port()` to use `display_ports()` instead of `sorted_ports()`. Also update `select_next`, `select_prev`, `select_first`, `select_last` and anywhere else that calls `sorted_ports()` for row count / selection — search for all `sorted_ports()` calls and replace with `display_ports()` where the result is used for display/selection (NOT in `refresh_data` clamp logic).

- [ ] **Step 4: Add `t` keybinding**

In `handle_table_key()`, add before the `_ => {}` catch-all:

```rust
        KeyCode::Char('t') => {
            app.tree_mode = !app.tree_mode;
        }
```

- [ ] **Step 5: Ignore sort keys in tree mode**

Wrap the sort key handlers in a condition:

```rust
        KeyCode::Char('<') | KeyCode::Left if !app.tree_mode => {
            app.sort_column = app.sort_column.prev();
        }
        KeyCode::Char('>') | KeyCode::Right if !app.tree_mode => {
            app.sort_column = app.sort_column.next();
        }
        KeyCode::Char('r') if !app.tree_mode => {
            app.sort_direction = app.sort_direction.toggle();
        }
        KeyCode::Char(c @ '1'..='9') if !app.tree_mode => {
```

- [ ] **Step 6: Update footer**

In `build_footer_line()`, change the sort hint and add tree toggle:

Replace the sort and `a` spans section with:

```rust
        if app.tree_mode {
            spans.push(Span::styled("t", app.theme.footer_key));
            spans.push(Span::styled(" flat  ", app.theme.footer_text));
        } else {
            spans.push(Span::styled("\u{2190}/\u{2192}/r", app.theme.footer_key));
            spans.push(Span::styled(" sort  ", app.theme.footer_text));
            spans.push(Span::styled("t", app.theme.footer_key));
            spans.push(Span::styled(" tree  ", app.theme.footer_text));
        }
```

Keep the `a` (all/listening) toggle after this.

- [ ] **Step 7: Build and test**

Run: `cargo build && cargo test`

Expected: All tests pass. Tree mode is wired up but tree chars aren't rendered yet (next task).

- [ ] **Step 8: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): add tree mode toggle with t key and tree ordering"
```

---

### Task 5: Render tree characters in PROCESS column

**Files:**
- Modify: `src/tui.rs` — update render_table to show tree prefixes

- [ ] **Step 1: Update render_table to handle tree mode**

In `render_table()`, the row-building loop (around line 640-715) iterates over `sorted_ports()`. When in tree mode, we need the depth/is_last info. Restructure the loop:

Before the row-building `let rows: Vec<Row>` block, compute the display data:

```rust
    // Build row data with optional tree info
    let tree_data: Vec<(&PortInfo, u16, bool)> = if app.tree_mode {
        app.tree_ordered_ports()
    } else {
        app.sorted_ports().into_iter().map(|p| (p, 0u16, true)).collect()
    };
```

Then iterate over `tree_data` instead of `sorted_ports()`:

```rust
    let rows: Vec<Row> = tree_data
        .iter()
        .map(|(info, depth, is_last)| {
```

- [ ] **Step 2: Build tree prefix string**

Inside the row mapping closure, before constructing the process_text, build the tree prefix:

```rust
            let tree_prefix = if app.tree_mode && *depth > 0 {
                let mut prefix = String::new();
                // For depths > 1, add vertical line padding for ancestors
                for _ in 0..(*depth - 1) {
                    prefix.push_str("\u{2502}   "); // │ + 3 spaces
                }
                if *is_last {
                    prefix.push_str("\u{2514}\u{2500}\u{2500} "); // └── + space
                } else {
                    prefix.push_str("\u{251c}\u{2500}\u{2500} "); // ├── + space
                }
                prefix
            } else {
                String::new()
            };
```

Then prepend it to process_text:

```rust
            let process_text = if has_docker {
                format!("{}{}*", tree_prefix, info.process_name)
            } else {
                format!("{}{}", tree_prefix, info.process_name)
            };
```

- [ ] **Step 3: Hide sort indicator in tree mode**

In the header construction section (around line 630-650), when building column headers, skip the sort direction indicator if tree_mode is on:

Where the header is built with sort indicator:
```rust
                let is_active = *col == app.sort_column;
```
Change the indicator logic:
```rust
                let is_active = !app.tree_mode && *col == app.sort_column;
```

- [ ] **Step 4: Build and smoke test**

Run: `cargo build && cargo run -- watch`

In the TUI, press `t` to toggle tree mode. Verify tree characters appear for any parent-child port relationships. Press `t` again to return to flat mode.

- [ ] **Step 5: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): render tree characters in PROCESS column"
```

---

### Task 6: Enhanced detail view — full command, cwd, child list

**Files:**
- Modify: `src/main.rs` — add get_process_cwd helper (unix only)
- Modify: `src/linux.rs` — add get_process_cwd function
- Modify: `src/tui.rs` — enhance render_detail

- [ ] **Step 1: Add get_process_cwd on Linux**

In `src/linux.rs`, add after `count_children`:

```rust
pub fn get_process_cwd(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/cwd", pid))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}
```

- [ ] **Step 2: Add get_process_cwd on macOS**

In `src/macos.rs`, add a stub (macOS doesn't have a cheap cwd API without SIP issues):

```rust
pub fn get_process_cwd(_pid: u32) -> String {
    String::new()
}
```

- [ ] **Step 3: Add get_process_cwd on Windows (stub)**

In `src/windows.rs`:

```rust
pub fn get_process_cwd(_pid: u32) -> String {
    String::new()
}
```

- [ ] **Step 4: Enhance render_detail in tui.rs**

In `src/tui.rs`, update `render_detail()` (line 725+). After the existing rows are built but before they're rendered, add new sections.

Replace the existing rows construction for the non-Docker case with:

```rust
    } else {
        // Full command (unwrapped)
        let cmd_display = if info.command.len() > 60 {
            // Wrap long commands
            let mut wrapped = String::new();
            let mut remaining = info.command.as_str();
            let width = 60;
            let mut first = true;
            while !remaining.is_empty() {
                let (chunk, rest) = if remaining.len() > width {
                    (&remaining[..width], &remaining[width..])
                } else {
                    (remaining, "")
                };
                if first {
                    wrapped.push_str(chunk);
                    first = false;
                } else {
                    wrapped.push_str(&format!("\n            {}", chunk));
                }
                remaining = rest;
            }
            wrapped
        } else {
            info.command.clone()
        };

        let mut rows = vec![
            ("Bind:", bind_str),
            ("Command:", cmd_display),
            ("User:", info.user.clone()),
            ("Started:", format!("{} ago", uptime)),
            ("Memory:", format_bytes(info.memory_bytes)),
            ("CPU time:", format!("{:.1}s", info.cpu_seconds)),
            ("State:", info.state.to_string()),
        ];

        // Working directory
        #[cfg(target_os = "linux")]
        {
            let cwd = crate::linux::get_process_cwd(info.pid);
            if !cwd.is_empty() {
                rows.push(("Cwd:", cwd));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let cwd = crate::macos::get_process_cwd(info.pid);
            if !cwd.is_empty() {
                rows.push(("Cwd:", cwd));
            }
        }

        rows
    };
```

- [ ] **Step 5: Add child process list to detail view**

After the rows are rendered into lines, add a child section:

```rust
    // Child processes (port-owning children)
    let child_ports: Vec<&PortInfo> = app
        .ports
        .iter()
        .filter(|p| p.ppid == info.pid && p.pid != info.pid)
        .collect();

    if !child_ports.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("Children ({}):", child_ports.len()),
                label_style,
            ),
        ]));
        let show_count = child_ports.len().min(10);
        for child in &child_ports[..show_count] {
            lines.push(Line::from(vec![
                Span::raw("    PID "),
                Span::styled(child.pid.to_string(), app.styles.pid),
                Span::raw(format!(
                    "  {} on port {}",
                    child.process_name, child.port
                )),
            ]));
        }
        if child_ports.len() > 10 {
            lines.push(Line::from(vec![
                Span::raw(format!("    ... and {} more", child_ports.len() - 10)),
            ]));
        }
    } else if info.children > 0 {
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:<10}", "Children:"), label_style),
            Span::raw(format!("{} (none on ports)", info.children)),
        ]));
    }
```

- [ ] **Step 6: Build and test**

Run: `cargo build && cargo test`

- [ ] **Step 7: Commit**

```bash
git add src/main.rs src/linux.rs src/macos.rs src/windows.rs src/tui.rs
git commit -m "feat(tui): enhanced detail view with full command, cwd, and child list"
```

---

### Task 7: Add open connections to detail view

**Files:**
- Modify: `src/tui.rs` — add connections section to render_detail

- [ ] **Step 1: Collect non-LISTEN connections for the inspected port**

In `render_detail()`, after the child section, add:

```rust
    // Open connections on this port
    let connections: Vec<&PortInfo> = app
        .ports
        .iter()
        .filter(|p| p.port == info.port && p.state != TcpState::Listen && p.pid == info.pid)
        .collect();

    if !connections.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("Connections ({}):", connections.len()),
                label_style,
            ),
        ]));
        let show_count = connections.len().min(10);
        for conn in &connections[..show_count] {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    format!("{:<14}", conn.state.to_string()),
                    match conn.state {
                        TcpState::Established => app.theme.status_ok,
                        TcpState::TimeWait | TcpState::CloseWait => Style::default().fg(Color::Yellow),
                        _ => app.theme.footer_text,
                    },
                ),
                Span::raw(format!("{}:{}", conn.local_addr, conn.port)),
            ]));
        }
        if connections.len() > 10 {
            lines.push(Line::from(vec![
                Span::raw(format!("    ... and {} more", connections.len() - 10)),
            ]));
        }
    }
```

Note: This requires `show_all` data. When the user is in LISTEN-only mode, connections won't be available. That's fine — the section just won't appear.

- [ ] **Step 2: Build and test**

Run: `cargo build && cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): show open connections in detail view"
```

---

### Task 8: Final integration, clippy, and smoke test

**Files:**
- All modified files

- [ ] **Step 1: Run full test suite**

Run: `cargo test`

Expected: All tests pass.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy`

Expected: No warnings.

- [ ] **Step 3: Run fmt**

Run: `cargo fmt`

- [ ] **Step 4: Smoke test tree mode**

Run: `cargo run -- watch`

Test:
- Press `t` — verify tree mode activates, PROCESS column shows tree characters for parent-child relationships
- Press `t` again — verify flat mode returns, sorting works
- Verify sort keys (`<`, `>`, `r`, `1-9`) are ignored in tree mode
- Footer shows `t flat` in tree mode, `t tree` in flat mode

- [ ] **Step 5: Smoke test detail view**

Run: `cargo run -- watch`

Test:
- Select a row, press Enter
- Verify: full command (unwrapped), Cwd (on Linux), Children list (port-owning), Connections (if --all mode and connections exist)
- Press Esc to return

- [ ] **Step 6: Smoke test JSON**

Run: `cargo run -- --json | head -1`

Verify `ppid` field appears in JSON output.

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "feat: complete tree view and enhanced detail view"
```
