//! MCP (Model Context Protocol) server over stdio.
//!
//! Lets an AI agent — Claude Code, Cursor, or any MCP client — query and act on
//! ports directly instead of shelling out to `lsof` and parsing the result.
//!
//! Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout, per the MCP
//! stdio spec. Two invariants matter:
//!
//!   1. **stdout carries only JSON-RPC.** Every diagnostic goes to stderr.
//!      This is why `doctor` is driven through `diagnostics_json_string()`
//!      rather than `run_doctor()`, which prints and may `exit(1)`.
//!   2. **No message may contain a raw newline.** All embedded text is passed
//!      through `json_escape`, which turns `\n` into `\\n`.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use crate::doctor::diagnostics_json_string;
use crate::json::{get, get_bool, get_string, get_u64, object_pairs};
use crate::{
    PortInfo, get_process_cwd, json_escape, kill_process, port_info_json, ports_json_string,
    synthesize_docker_entries,
};

use crate::docker::{DockerPortMap, get_docker_port_map};

#[cfg(target_os = "linux")]
use crate::linux::{get_child_processes, get_port_infos};
#[cfg(target_os = "macos")]
use crate::macos::{get_child_processes, get_port_infos};
#[cfg(target_os = "windows")]
use crate::windows::{get_child_processes, get_port_infos};

/// Newest spec revision we implement.
const LATEST_PROTOCOL: &str = "2025-11-25";

/// Revisions we will echo back if a client asks for one of them. Clients pin
/// different versions; agreeing to an older one we still satisfy is friendlier
/// than forcing every client onto the newest.
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "portview exposes the listening ports on this machine and the processes behind them. \
Use list_ports to see what is running, inspect_port when the user names a specific port, \
find_process to locate a service by name, and doctor to check for conflicts or services \
exposed on 0.0.0.0. diff_ports answers 'what did that change?' — call it once to record a \
baseline, then again after starting or stopping something. kill_port terminates processes — \
confirm with the user before calling it, and call it with dry_run=true first if you want to \
see exactly which PIDs it would signal.";

// ── JSON-RPC error codes ─────────────────────────────────────────────

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;

// ── Entry point ──────────────────────────────────────────────────────

pub(crate) fn run_mcp(read_only: bool) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            // stdin closed or gave us non-UTF-8; the client is gone.
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(response) = handle_message(trimmed, read_only)
            && (writeln!(stdout, "{}", response).is_err() || stdout.flush().is_err())
        {
            // The client closed the pipe.
            break;
        }
    }
}

/// Dispatch one JSON-RPC message. Returns `None` for notifications, which the
/// spec says must not be answered.
fn handle_message(line: &str, read_only: bool) -> Option<String> {
    let pairs = match object_pairs(line) {
        Ok(p) => p,
        // No id is recoverable from an unparseable message, so per JSON-RPC the
        // error carries a null id.
        Err(e) => {
            return Some(error_response(
                "null",
                PARSE_ERROR,
                &format!("parse error: {}", e),
            ));
        }
    };

    // Echo the id back verbatim — it may be a number or a string.
    let id = get(&pairs, "id").map(|s| s.trim().to_string());

    let method = match get_string(&pairs, "method") {
        Some(m) => m,
        None => {
            return id.map(|id| error_response(&id, INVALID_REQUEST, "missing \"method\""));
        }
    };

    // A message without an id is a notification (e.g. notifications/initialized).
    let id = id?;
    let params = get(&pairs, "params").unwrap_or("{}");

    let result = match method.as_str() {
        "initialize" => initialize_result(params),
        "ping" => "{}".to_string(),
        "tools/list" => tools_list_result(read_only),
        "tools/call" => tools_call_result(params, read_only),
        other => {
            return Some(error_response(
                &id,
                METHOD_NOT_FOUND,
                &format!("method not found: {}", other),
            ));
        }
    };

    Some(success_response(&id, &result))
}

// ── Envelopes ────────────────────────────────────────────────────────

fn success_response(id: &str, result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{},"result":{}}}"#, id, result)
}

fn error_response(id: &str, code: i32, message: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":{},"message":"{}"}}}}"#,
        id,
        code,
        json_escape(message)
    )
}

/// A successful tool result. `text` is escaped, so callers pass raw JSON or prose.
fn tool_text(text: &str) -> String {
    format!(
        r#"{{"content":[{{"type":"text","text":"{}"}}],"isError":false}}"#,
        json_escape(text)
    )
}

/// A *tool-level* failure. Deliberately not a JSON-RPC error: the spec routes
/// these back to the model as content so it can read the message and adapt.
fn tool_error(text: &str) -> String {
    format!(
        r#"{{"content":[{{"type":"text","text":"{}"}}],"isError":true}}"#,
        json_escape(text)
    )
}

// ── initialize ───────────────────────────────────────────────────────

fn initialize_result(params: &str) -> String {
    let requested = object_pairs(params)
        .ok()
        .and_then(|p| get_string(&p, "protocolVersion"));

    let version = match requested {
        Some(v) if SUPPORTED_PROTOCOLS.contains(&v.as_str()) => v,
        _ => LATEST_PROTOCOL.to_string(),
    };

    format!(
        r#"{{"protocolVersion":"{}","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"portview","title":"portview","version":"{}"}},"instructions":"{}"}}"#,
        json_escape(&version),
        env!("CARGO_PKG_VERSION"),
        json_escape(INSTRUCTIONS),
    )
}

// ── tools/list ───────────────────────────────────────────────────────

/// Read-only tools, always available.
const SAFE_TOOLS: &[&str] = &[
    r#"{"name":"list_ports","title":"List ports","description":"List listening ports on this machine with the process, user, uptime, memory, and full command behind each one. Set all=true to include established/non-listening connections, docker=true to attribute ports to Docker containers. Returns a JSON array.","inputSchema":{"type":"object","properties":{"all":{"type":"boolean","description":"Include non-listening connections (ESTABLISHED, TIME_WAIT, ...). Default false."},"docker":{"type":"boolean","description":"Attribute ports to Docker containers and include container-only published ports. Default false."}}},"annotations":{"title":"List ports","readOnlyHint":true,"openWorldHint":false}}"#,
    r#"{"name":"inspect_port","title":"Inspect a port","description":"Inspect a single port in detail. Returns every process bound to it, with the working directory of each and its descendant processes in child_processes (pid, ppid, process, depth — flat, so nest by ppid if you need a tree). Use when the user names a specific port, e.g. 'what is on 3000?', or to see what else would be affected by stopping it: a dev server's workers are its children, not separate port owners. child_processes_truncated is true when the walk hit its limit.","inputSchema":{"type":"object","properties":{"port":{"type":"integer","description":"Port number (1-65535)."},"docker":{"type":"boolean","description":"Include Docker container attribution. Default false."}},"required":["port"]},"annotations":{"title":"Inspect a port","readOnlyHint":true,"openWorldHint":false}}"#,
    r#"{"name":"find_process","title":"Find ports by process","description":"Find which ports a process is listening on, matching by process name or command substring (case-insensitive). Use for questions like 'what port is postgres on?'. Returns a JSON array.","inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"Process name or command substring, e.g. 'node', 'postgres'."},"all":{"type":"boolean","description":"Include non-listening connections. Default false."}},"required":["name"]},"annotations":{"title":"Find ports by process","readOnlyHint":true,"openWorldHint":false}}"#,
    r#"{"name":"doctor","title":"Diagnose port problems","description":"Run diagnostics: port conflicts between processes, services exposed on 0.0.0.0 that should be localhost-only, Docker/host port collisions, stale TIME_WAIT and CLOSE_WAIT pileups, and unusually high-memory listeners. Returns a JSON array of findings; an empty array means no problems.","inputSchema":{"type":"object","properties":{}},"annotations":{"title":"Diagnose port problems","readOnlyHint":true,"openWorldHint":false}}"#,
    r#"{"name":"diff_ports","title":"Compare ports against a baseline","description":"Report which ports opened, closed, or changed owner since a baseline. The first call records the baseline and returns no diff; call it again after the change you want to observe. Use this to answer 'what did starting/stopping this actually do to the ports?' without diffing two list_ports results by hand. A port whose PID changed is reported as replaced rather than as a close plus an open, so a restart is distinguishable from a shutdown. Pass reset=true to record a fresh baseline.","inputSchema":{"type":"object","properties":{"all":{"type":"boolean","description":"Track non-listening connections too. Default false. Changing this between calls compares different things."},"reset":{"type":"boolean","description":"Discard the stored baseline and record a new one from the current state. Default false."}}},"annotations":{"title":"Compare ports against a baseline","readOnlyHint":true,"openWorldHint":false}}"#,
];

/// Terminates processes. Withheld entirely when `--read-only` is set.
const KILL_TOOL: &str = r#"{"name":"kill_port","title":"Kill process on a port","description":"Terminate the process(es) listening on a port. Sends SIGTERM by default, or SIGKILL when force=true (on Windows, always a forced terminate). This is destructive and cannot be undone — confirm with the user first. Set dry_run=true to see exactly which PIDs would be signalled without touching them; this resolves the same target list the real call uses, so it is the reliable way to check before acting.","inputSchema":{"type":"object","properties":{"port":{"type":"integer","description":"Port number (1-65535)."},"force":{"type":"boolean","description":"Use SIGKILL instead of SIGTERM. Default false."},"dry_run":{"type":"boolean","description":"Report which processes would be signalled and stop. Nothing is terminated. Default false."}},"required":["port"]},"annotations":{"title":"Kill process on a port","readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}}"#;

fn tools_list_result(read_only: bool) -> String {
    let mut tools: Vec<&str> = SAFE_TOOLS.to_vec();
    if !read_only {
        tools.push(KILL_TOOL);
    }
    format!(r#"{{"tools":[{}]}}"#, tools.join(","))
}

// ── tools/call ───────────────────────────────────────────────────────

fn tools_call_result(params: &str, read_only: bool) -> String {
    let pairs = match object_pairs(params) {
        Ok(p) => p,
        Err(e) => return tool_error(&format!("invalid params: {}", e)),
    };

    let name = match get_string(&pairs, "name") {
        Some(n) => n,
        None => return tool_error("missing tool name"),
    };

    // `arguments` is optional for zero-arg tools, and some clients send null.
    let args = match get(&pairs, "arguments") {
        Some(raw) => object_pairs(raw).unwrap_or_default(),
        None => Vec::new(),
    };

    match name.as_str() {
        "list_ports" => tool_list_ports(&args),
        "inspect_port" => tool_inspect_port(&args),
        "find_process" => tool_find_process(&args),
        "doctor" => tool_text(&diagnostics_json_string()),
        "diff_ports" => tool_diff_ports(&args),
        "kill_port" => {
            // A dry run is read-only in effect, but the tool stays withheld
            // under --read-only regardless: the guarantee that server offers is
            // that nothing destructive is even listed, and a `kill_port` in the
            // list that refuses half its arguments is a worse contract than an
            // absent one. `inspect_port` answers what is on the port.
            if read_only {
                tool_error("kill_port is disabled: this server was started with --read-only")
            } else {
                tool_kill_port(&args)
            }
        }
        other => tool_error(&format!("unknown tool: {}", other)),
    }
}

/// Shared argument parsing for the port number, with range validation.
fn required_port(args: &[(String, String)]) -> Result<u16, String> {
    match get_u64(args, "port") {
        Some(p) if p >= 1 && p <= u16::MAX as u64 => Ok(p as u16),
        Some(p) => Err(format!("port {} is out of range (1-65535)", p)),
        None => Err("missing required argument: port".to_string()),
    }
}

/// Collect ports, optionally folding in Docker attribution and container-only rows.
///
/// Note the inversion: `get_port_infos` takes `filter_listening`, so "give me
/// everything" is `false`.
fn collect(all: bool, docker: bool) -> (Vec<PortInfo>, Option<DockerPortMap>) {
    let mut infos = get_port_infos(!all);
    if !docker {
        return (infos, None);
    }
    let map = get_docker_port_map();
    infos.extend(synthesize_docker_entries(&infos, &map));
    (infos, Some(map))
}

fn tool_list_ports(args: &[(String, String)]) -> String {
    let all = get_bool(args, "all").unwrap_or(false);
    let docker = get_bool(args, "docker").unwrap_or(false);
    let (infos, map) = collect(all, docker);
    tool_text(&ports_json_string(&infos, map.as_ref()))
}

fn tool_inspect_port(args: &[(String, String)]) -> String {
    let port = match required_port(args) {
        Ok(p) => p,
        Err(e) => return tool_error(&e),
    };
    let docker = get_bool(args, "docker").unwrap_or(false);

    // Inspecting a specific port should surface established connections too —
    // "nothing is listening but the port is busy" is exactly the case users hit.
    let (infos, map) = collect(true, docker);
    let matches: Vec<PortInfo> = infos.into_iter().filter(|i| i.port == port).collect();

    if matches.is_empty() {
        return tool_text(&format!(
            r#"{{"port":{},"found":false,"processes":[]}}"#,
            port
        ));
    }

    // Same object shape as list_ports, plus the working directory.
    let mut entries = Vec::with_capacity(matches.len());
    for info in &matches {
        let owners = map
            .as_ref()
            .map(|m| m.get(&info.port).map(|o| o.as_slice()).unwrap_or(&[][..]));
        let mut obj = port_info_json(info, owners);
        obj.pop(); // trailing '}'
        // `children` in the base object is a count; this is the list. Distinct
        // keys because they answer different questions and both are useful.
        let (tree, truncated) = descendant_processes(info.pid);
        obj.push_str(&format!(
            r#","cwd":"{}","child_processes":[{}],"child_processes_truncated":{}}}"#,
            json_escape(&get_process_cwd(info.pid)),
            tree.join(","),
            truncated
        ));
        entries.push(obj);
    }

    tool_text(&format!(
        r#"{{"port":{},"found":true,"processes":[{}]}}"#,
        port,
        entries.join(",")
    ))
}

fn tool_find_process(args: &[(String, String)]) -> String {
    let name = match get_string(args, "name") {
        Some(n) if !n.trim().is_empty() => n,
        Some(_) => return tool_error("argument \"name\" must not be empty"),
        None => return tool_error("missing required argument: name"),
    };
    let all = get_bool(args, "all").unwrap_or(false);
    let needle = name.to_lowercase();

    // Match against the untruncated command — truncation is display-only.
    let (infos, map) = collect(all, false);
    let matches: Vec<PortInfo> = infos
        .into_iter()
        .filter(|i| {
            i.process_name.to_lowercase().contains(&needle)
                || i.command.to_lowercase().contains(&needle)
        })
        .collect();

    tool_text(&ports_json_string(&matches, map.as_ref()))
}

// ── Process tree (inspect_port) ──────────────────────────────────────

/// Bounds on the descendant walk.
///
/// This runs per `inspect_port` call, and a supervisor with hundreds of workers
/// would otherwise dominate the response. The node cap matters most on Windows,
/// which pays a process snapshot per node walked.
const TREE_MAX_DEPTH: usize = 3;
const TREE_MAX_NODES: usize = 64;

/// Descendants of `root`, breadth-first. Returns `(entries, truncated)`.
///
/// Flat rather than nested: every entry carries `ppid` and `depth`, which is
/// the same information a nested structure holds and is far simpler to emit and
/// to consume. Breadth-first so that when the cap truncates, what survives is
/// the shallowest part of the tree — the part the caller is most likely to
/// care about.
fn descendant_processes(root: u32) -> (Vec<String>, bool) {
    walk_descendants(root, get_child_processes)
}

/// The walk itself, with the child lookup injected so the bounds and the cycle
/// guard can be tested without a real process tree.
fn walk_descendants(
    root: u32,
    children_of: impl Fn(u32) -> Vec<(u32, String)>,
) -> (Vec<String>, bool) {
    use std::collections::{HashSet, VecDeque};

    let mut entries = Vec::new();
    let mut queue: VecDeque<(u32, usize)> = VecDeque::from([(root, 0usize)]);
    // Guards against a reparenting race producing a cycle. It costs nothing and
    // the alternative is an unbounded walk.
    let mut seen: HashSet<u32> = HashSet::from([root]);
    let mut truncated = false;

    while let Some((pid, depth)) = queue.pop_front() {
        if depth >= TREE_MAX_DEPTH {
            continue;
        }
        for (child, name) in children_of(pid) {
            if !seen.insert(child) {
                continue;
            }
            if entries.len() >= TREE_MAX_NODES {
                truncated = true;
                break;
            }
            entries.push(format!(
                r#"{{"pid":{},"ppid":{},"process":"{}","depth":{}}}"#,
                child,
                pid,
                json_escape(&name),
                depth + 1
            ));
            queue.push_back((child, depth + 1));
        }
        if truncated {
            break;
        }
    }

    (entries, truncated)
}

// ── Port baseline (diff_ports) ───────────────────────────────────────

/// What was listening when the baseline was taken.
///
/// Keyed by `(port, protocol)` because that is what a caller means by "the same
/// port": a service restarting keeps its key and changes its PID, which is the
/// distinction between *closed and opened* and *replaced*.
struct Baseline {
    taken_at: Instant,
    /// Whether non-listening connections were included. Diffing a snapshot
    /// taken with a different value would report every connection as newly
    /// opened, which looks like a real finding and is not one.
    all: bool,
    ports: HashMap<(u16, String), (u32, String)>,
}

type PortMap = HashMap<(u16, String), (u32, String)>;

/// The server is a single long-lived stdio process, so a baseline can simply
/// live in it. Nothing here touches the machine — this is the server's own
/// memory of a previous look at it.
static BASELINE: LazyLock<Mutex<Option<Baseline>>> = LazyLock::new(|| Mutex::new(None));

fn snapshot_ports(all: bool) -> PortMap {
    get_port_infos(!all)
        .into_iter()
        .map(|i| ((i.port, i.protocol.clone()), (i.pid, i.process_name)))
        .collect()
}

/// The diff itself, with no I/O and no shared state, so it can be tested.
///
/// Returns `(opened, closed, replaced)` as rendered JSON objects, sorted so
/// repeated calls are comparable — `HashMap` iteration order is not stable.
fn compute_diff(baseline: &PortMap, current: &PortMap) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut opened = Vec::new();
    let mut replaced = Vec::new();
    for ((port, proto), (pid, process)) in current {
        match baseline.get(&(*port, proto.clone())) {
            None => opened.push(port_entry_json(*port, proto, *pid, process)),
            // Same key, different owner: a restart, which is a different event
            // from a shutdown followed by an unrelated bind.
            Some((old_pid, old_process)) if old_pid != pid => replaced.push(format!(
                r#"{{"port":{},"protocol":"{}","before":{{"pid":{},"process":"{}"}},"after":{{"pid":{},"process":"{}"}}}}"#,
                port,
                json_escape(proto),
                old_pid,
                json_escape(old_process),
                pid,
                json_escape(process)
            )),
            Some(_) => {}
        }
    }

    let mut closed = Vec::new();
    for ((port, proto), (pid, process)) in baseline {
        if !current.contains_key(&(*port, proto.clone())) {
            closed.push(port_entry_json(*port, proto, *pid, process));
        }
    }

    opened.sort();
    closed.sort();
    replaced.sort();
    (opened, closed, replaced)
}

fn port_entry_json(port: u16, protocol: &str, pid: u32, process: &str) -> String {
    format!(
        r#"{{"port":{},"protocol":"{}","pid":{},"process":"{}"}}"#,
        port,
        json_escape(protocol),
        pid,
        json_escape(process)
    )
}

fn tool_diff_ports(args: &[(String, String)]) -> String {
    let all = get_bool(args, "all").unwrap_or(false);
    let reset = get_bool(args, "reset").unwrap_or(false);
    let current = snapshot_ports(all);

    let mut guard = match BASELINE.lock() {
        Ok(g) => g,
        // Only reachable if a previous call panicked mid-update. Recovering is
        // better than propagating: the baseline is a convenience, not state the
        // caller cannot rebuild.
        Err(poisoned) => poisoned.into_inner(),
    };

    let take_baseline = reset || guard.is_none();
    if take_baseline {
        let count = current.len();
        *guard = Some(Baseline {
            taken_at: Instant::now(),
            all,
            ports: current,
        });
        return tool_text(&format!(
            r#"{{"baseline_taken":true,"port_count":{},"note":"Baseline recorded. Call diff_ports again after the change you want to observe."}}"#,
            count
        ));
    }

    let baseline = guard.as_ref().expect("baseline present");

    // Refuse rather than diff two different views: every connection would show
    // up as newly opened, which reads as a real finding and is an artefact.
    if baseline.all != all {
        return tool_error(&format!(
            "baseline was recorded with all={}, but this call passed all={}. \
             Comparing them would report unrelated rows as opened or closed. \
             Call diff_ports with all={} to match, or reset=true to record a new baseline.",
            baseline.all, all, baseline.all
        ));
    }

    let age = baseline.taken_at.elapsed().as_secs();
    let (opened, closed, replaced) = compute_diff(&baseline.ports, &current);

    tool_text(&format!(
        r#"{{"baseline_age_seconds":{},"opened":[{}],"closed":[{}],"replaced":[{}]}}"#,
        age,
        opened.join(","),
        closed.join(","),
        replaced.join(",")
    ))
}

/// Resolve which processes a kill on this port would signal.
///
/// Shared by the dry run and the real thing deliberately: a preview computed
/// any other way could disagree with what the kill actually targets, which is
/// the one bug a preview must not have.
fn kill_targets(port: u16) -> Vec<(u32, String)> {
    // filter_listening = true: only ever signal an actual listener, never a
    // process that merely holds an ESTABLISHED or TIME_WAIT socket on this port.
    let infos = get_port_infos(true);
    let mut targets: Vec<(u32, String)> = infos
        .iter()
        .filter(|i| i.port == port && i.pid != 0)
        .map(|i| (i.pid, i.process_name.clone()))
        .collect();
    // The same PID appears once per protocol (tcp/tcp6); signal it once.
    targets.sort_by_key(|(pid, _)| *pid);
    targets.dedup_by_key(|(pid, _)| *pid);
    targets
}

fn tool_kill_port(args: &[(String, String)]) -> String {
    let port = match required_port(args) {
        Ok(p) => p,
        Err(e) => return tool_error(&e),
    };
    let force = get_bool(args, "force").unwrap_or(false);
    let dry_run = get_bool(args, "dry_run").unwrap_or(false);

    let targets = kill_targets(port);

    if targets.is_empty() {
        return tool_error(&format!("nothing is listening on port {}", port));
    }

    if dry_run {
        let action = crate::planned_kill_action(force);
        let would: Vec<String> = targets
            .iter()
            .map(|(pid, process)| {
                format!(
                    r#"{{"pid":{},"process":"{}","signal":"{}"}}"#,
                    pid,
                    json_escape(process),
                    action
                )
            })
            .collect();
        return tool_text(&format!(
            r#"{{"port":{},"dry_run":true,"would_kill":[{}]}}"#,
            port,
            would.join(",")
        ));
    }

    let mut killed = Vec::new();
    let mut errors = Vec::new();
    for (pid, process) in &targets {
        match kill_process(*pid, force) {
            Ok(signal) => killed.push(format!(
                r#"{{"pid":{},"process":"{}","signal":"{}"}}"#,
                pid,
                json_escape(process),
                signal
            )),
            Err(e) => errors.push(format!(
                r#"{{"pid":{},"process":"{}","error":"{}"}}"#,
                pid,
                json_escape(process),
                json_escape(&e.to_string())
            )),
        }
    }

    let body = format!(
        r#"{{"port":{},"killed":[{}],"errors":[{}]}}"#,
        port,
        killed.join(","),
        errors.join(",")
    );

    // Every target failing is a real failure; a partial kill is reported as success
    // with the per-PID errors included so the model can decide what to do.
    if killed.is_empty() {
        tool_error(&body)
    } else {
        tool_text(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(line: &str) -> String {
        handle_message(line, false).expect("expected a response")
    }

    #[test]
    fn initialize_echoes_supported_client_version() {
        let r = call(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
        );
        assert!(r.contains(r#""protocolVersion":"2025-06-18""#), "{}", r);
        assert!(r.contains(r#""id":1"#), "{}", r);
    }

    #[test]
    fn initialize_falls_back_for_unknown_version() {
        let r = call(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
        );
        assert!(r.contains(&format!(r#""protocolVersion":"{}""#, LATEST_PROTOCOL)));
    }

    #[test]
    fn string_ids_are_echoed_verbatim() {
        let r = call(r#"{"jsonrpc":"2.0","id":"abc-1","method":"ping"}"#);
        assert!(r.contains(r#""id":"abc-1""#), "{}", r);
    }

    #[test]
    fn notifications_get_no_response() {
        assert!(
            handle_message(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                false
            )
            .is_none()
        );
        assert!(
            handle_message(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#,
                false
            )
            .is_none()
        );
    }

    #[test]
    fn unparseable_input_yields_parse_error_with_null_id() {
        let r = handle_message("not json at all", false).unwrap();
        assert!(r.contains(r#""id":null"#), "{}", r);
        assert!(r.contains(&PARSE_ERROR.to_string()), "{}", r);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let r = call(r#"{"jsonrpc":"2.0","id":9,"method":"resources/list"}"#);
        assert!(r.contains(&METHOD_NOT_FOUND.to_string()), "{}", r);
    }

    #[test]
    fn tools_list_includes_kill_only_when_writable() {
        let writable = tools_list_result(false);
        assert!(writable.contains(r#""name":"kill_port""#));
        assert!(writable.contains(r#""destructiveHint":true"#));

        let ro = tools_list_result(true);
        assert!(!ro.contains(r#""name":"kill_port""#));
        assert!(ro.contains(r#""name":"list_ports""#));
    }

    #[test]
    fn read_only_refuses_kill_even_if_called_directly() {
        let r = tools_call_result(r#"{"name":"kill_port","arguments":{"port":3000}}"#, true);
        assert!(r.contains(r#""isError":true"#), "{}", r);
        assert!(r.contains("read-only"), "{}", r);
    }

    // ── process tree ─────────────────────────────────────────────────

    /// A child lookup over a fixed `parent -> children` table.
    fn tree_of<'a>(edges: &'a [(u32, &'a [u32])]) -> impl Fn(u32) -> Vec<(u32, String)> + 'a {
        move |pid| {
            edges
                .iter()
                .find(|(parent, _)| *parent == pid)
                .map(|(_, kids)| {
                    kids.iter()
                        .map(|k| (*k, format!("proc{}", k)))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        }
    }

    #[test]
    fn descendants_are_reported_with_their_parent_and_depth() {
        let (entries, truncated) =
            walk_descendants(1, tree_of(&[(1, &[2, 3]), (2, &[4]), (4, &[5])]));
        assert!(!truncated);
        assert_eq!(entries.len(), 4, "{:#?}", entries);
        assert!(entries[0].contains(r#""pid":2,"ppid":1"#), "{}", entries[0]);
        assert!(entries[0].contains(r#""depth":1"#), "{}", entries[0]);
        // Breadth-first: both depth-1 nodes precede the depth-2 node.
        assert!(entries[1].contains(r#""depth":1"#), "{}", entries[1]);
        assert!(entries[2].contains(r#""pid":4,"ppid":2"#), "{}", entries[2]);
        assert!(entries[2].contains(r#""depth":2"#), "{}", entries[2]);
    }

    #[test]
    fn the_walk_stops_at_the_depth_limit() {
        // A chain longer than TREE_MAX_DEPTH: only the first three levels below
        // the root are reported.
        let (entries, truncated) = walk_descendants(
            1,
            tree_of(&[(1, &[2]), (2, &[3]), (3, &[4]), (4, &[5]), (5, &[6])]),
        );
        assert!(!truncated, "a depth stop is not a node-cap truncation");
        assert_eq!(entries.len(), TREE_MAX_DEPTH, "{:#?}", entries);
        assert!(entries.last().unwrap().contains(r#""pid":4"#));
    }

    #[test]
    fn the_walk_reports_when_the_node_cap_truncates() {
        // One parent with more children than the cap allows.
        let many: Vec<u32> = (2..200).collect();
        let (entries, truncated) = walk_descendants(1, tree_of(&[(1, &many)]));
        assert!(truncated, "hitting the cap must be reported, not hidden");
        assert_eq!(entries.len(), TREE_MAX_NODES);
    }

    #[test]
    fn a_parent_cycle_does_not_loop_forever() {
        // Reparenting races can in principle produce this; the walk must end.
        let (entries, _) = walk_descendants(1, tree_of(&[(1, &[2]), (2, &[1])]));
        assert_eq!(entries.len(), 1, "{:#?}", entries);
        assert!(entries[0].contains(r#""pid":2"#));
    }

    #[test]
    fn a_process_with_no_children_yields_nothing() {
        let (entries, truncated) = walk_descendants(1, tree_of(&[]));
        assert!(entries.is_empty());
        assert!(!truncated);
    }

    // ── diff_ports ───────────────────────────────────────────────────

    fn snap(entries: &[(u16, &str, u32, &str)]) -> PortMap {
        entries
            .iter()
            .map(|(port, proto, pid, name)| ((*port, proto.to_string()), (*pid, name.to_string())))
            .collect()
    }

    #[test]
    fn a_restart_is_replaced_not_a_close_plus_an_open() {
        // The distinction the whole tool exists for: a service that came back
        // on the same port is a different event from one that went away.
        let before = snap(&[(3000, "TCP", 6, "node")]);
        let after = snap(&[(3000, "TCP", 45, "node")]);
        let (opened, closed, replaced) = compute_diff(&before, &after);

        assert!(opened.is_empty(), "{:?}", opened);
        assert!(closed.is_empty(), "{:?}", closed);
        assert_eq!(replaced.len(), 1, "{:?}", replaced);
        assert!(
            replaced[0].contains(r#""before":{"pid":6"#),
            "{}",
            replaced[0]
        );
        assert!(
            replaced[0].contains(r#""after":{"pid":45"#),
            "{}",
            replaced[0]
        );
    }

    #[test]
    fn opened_and_closed_are_reported_separately() {
        let before = snap(&[(3000, "TCP", 6, "node"), (5432, "TCP", 9, "postgres")]);
        let after = snap(&[(3000, "TCP", 6, "node"), (8080, "TCP", 20, "api")]);
        let (opened, closed, replaced) = compute_diff(&before, &after);

        assert_eq!(opened.len(), 1, "{:?}", opened);
        assert!(opened[0].contains(r#""port":8080"#));
        assert_eq!(closed.len(), 1, "{:?}", closed);
        assert!(closed[0].contains(r#""port":5432"#));
        assert!(replaced.is_empty(), "{:?}", replaced);
    }

    #[test]
    fn the_same_port_on_two_protocols_is_two_entries() {
        // Keyed by (port, protocol): a service dropping its IPv6 listener while
        // keeping IPv4 is a real change, not a no-op.
        let before = snap(&[(3000, "TCP", 6, "node"), (3000, "UDP", 6, "node")]);
        let after = snap(&[(3000, "TCP", 6, "node")]);
        let (opened, closed, _) = compute_diff(&before, &after);

        assert!(opened.is_empty(), "{:?}", opened);
        assert_eq!(closed.len(), 1, "{:?}", closed);
        assert!(closed[0].contains(r#""protocol":"UDP""#), "{}", closed[0]);
    }

    #[test]
    fn an_unchanged_machine_diffs_to_nothing() {
        let s = snap(&[(3000, "TCP", 6, "node"), (5432, "TCP", 9, "postgres")]);
        let (opened, closed, replaced) = compute_diff(&s, &s);
        assert!(opened.is_empty() && closed.is_empty() && replaced.is_empty());
    }

    #[test]
    fn diff_output_is_ordered_so_repeated_calls_are_comparable() {
        // HashMap iteration order is not stable; unsorted output would appear
        // to change between identical calls.
        let before = snap(&[]);
        let after = snap(&[
            (9000, "TCP", 3, "c"),
            (3000, "TCP", 1, "a"),
            (5000, "TCP", 2, "b"),
        ]);
        let (first, _, _) = compute_diff(&before, &after);
        let (second, _, _) = compute_diff(&before, &after);
        assert_eq!(first, second);
        assert!(first[0].contains(r#""port":3000"#), "{:?}", first);
    }

    #[test]
    fn diff_ports_is_offered_by_a_read_only_server() {
        // It only reads the machine; the baseline is the server's own memory.
        assert!(tools_list_result(true).contains(r#""name":"diff_ports""#));
    }

    #[test]
    fn read_only_refuses_a_dry_run_too() {
        // A dry run does not terminate anything, but the --read-only server's
        // contract is that no destructive tool is offered at all.
        let r = tools_call_result(
            r#"{"name":"kill_port","arguments":{"port":3000,"dry_run":true}}"#,
            true,
        );
        assert!(r.contains(r#""isError":true"#), "{}", r);
        assert!(r.contains("read-only"), "{}", r);
    }

    #[test]
    fn a_dry_run_reports_the_action_the_real_call_would_take() {
        // Windows ignores `force` and always terminates hard, so a preview
        // promising SIGTERM there would be a lie.
        if cfg!(windows) {
            assert_eq!(crate::planned_kill_action(false), "TerminateProcess");
            assert_eq!(crate::planned_kill_action(true), "TerminateProcess");
        } else {
            assert_eq!(crate::planned_kill_action(false), "SIGTERM");
            assert_eq!(crate::planned_kill_action(true), "SIGKILL");
        }
    }

    #[test]
    fn a_dry_run_on_an_unused_port_reports_nothing_to_kill() {
        // Port 1 is privileged and unbound in any sane test environment, so the
        // target list is genuinely empty rather than merely unmatched.
        let r = tools_call_result(
            r#"{"name":"kill_port","arguments":{"port":1,"dry_run":true}}"#,
            false,
        );
        assert!(r.contains(r#""isError":true"#), "{}", r);
        assert!(r.contains("nothing is listening"), "{}", r);
    }

    #[test]
    fn the_kill_tool_advertises_the_dry_run() {
        // The description is what the model actually reads; an undiscoverable
        // preview is no safer than none.
        let tools = tools_list_result(false);
        assert!(tools.contains(r#""dry_run""#), "{}", tools);
        assert!(tools.contains("without touching them"), "{}", tools);
    }

    #[test]
    fn unknown_tool_is_a_tool_error_not_a_protocol_error() {
        let r = tools_call_result(r#"{"name":"nope","arguments":{}}"#, false);
        assert!(r.contains(r#""isError":true"#), "{}", r);
        assert!(r.contains("unknown tool"), "{}", r);
    }

    #[test]
    fn port_argument_is_range_checked() {
        let args = object_pairs(r#"{"port":70000}"#).unwrap();
        assert!(required_port(&args).is_err());

        let args = object_pairs(r#"{"port":0}"#).unwrap();
        assert!(required_port(&args).is_err());

        let args = object_pairs(r#"{"port":3000}"#).unwrap();
        assert_eq!(required_port(&args).unwrap(), 3000);

        let args = object_pairs(r#"{}"#).unwrap();
        assert!(required_port(&args).is_err());
    }

    #[test]
    fn missing_required_args_are_reported() {
        assert!(
            tools_call_result(r#"{"name":"inspect_port","arguments":{}}"#, false)
                .contains("missing required argument: port")
        );
        assert!(
            tools_call_result(r#"{"name":"find_process","arguments":{}}"#, false)
                .contains("missing required argument: name")
        );
    }

    #[test]
    fn zero_arg_tool_works_without_arguments_key() {
        // doctor takes no arguments; clients may omit the key entirely.
        let r = tools_call_result(r#"{"name":"doctor"}"#, false);
        assert!(r.contains(r#""isError":false"#), "{}", r);
    }

    #[test]
    fn responses_never_contain_raw_newlines() {
        // stdio framing is newline-delimited, so an embedded newline would
        // desynchronise the client.
        let r = tool_text("line one\nline two\ttabbed");
        assert!(!r.contains('\n'), "{}", r);
        let e = tool_error("bad\nthing");
        assert!(!e.contains('\n'), "{}", e);
    }

    #[test]
    fn tool_text_round_trips_through_the_json_reader() {
        // Escaping is only correct if a reader gets the original bytes back.
        for payload in [
            r#"{"cmd":"sh -c \"x\""}"#,
            "line one\nline two\ttabbed",
            r"C:\Users\mark\app.exe",
            "unicode: ✓ ★",
        ] {
            let r = tool_text(payload);
            assert!(!r.contains('\n'), "raw newline in {}", r);

            let marker = r#""text":"#;
            let start = r.find(marker).unwrap() + marker.len();
            let (decoded, _) = crate::json::read_json_string(&r, start).unwrap();
            assert_eq!(decoded, payload, "round-trip failed for {:?}", payload);
        }
    }

    #[test]
    fn every_tool_definition_is_valid_json() {
        for t in SAFE_TOOLS.iter().chain(std::iter::once(&KILL_TOOL)) {
            let pairs = object_pairs(t).unwrap_or_else(|e| panic!("bad tool JSON: {} — {}", t, e));
            assert!(
                get_string(&pairs, "name").is_some(),
                "tool missing name: {}",
                t
            );
            assert!(
                get_string(&pairs, "description").is_some(),
                "tool missing description: {}",
                t
            );
            assert!(
                get(&pairs, "inputSchema").is_some(),
                "tool missing inputSchema: {}",
                t
            );
        }
    }

    #[test]
    fn initialize_result_is_valid_json() {
        let r = initialize_result(r#"{"protocolVersion":"2025-11-25"}"#);
        let pairs = object_pairs(&r).unwrap();
        assert!(get(&pairs, "capabilities").is_some());
        assert!(get(&pairs, "serverInfo").is_some());
    }
}
