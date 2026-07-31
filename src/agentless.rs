//! Agentless remote collection.
//!
//! `portview ssh host` normally runs `portview --json` on the remote machine,
//! which requires portview to be installed there. That is a real adoption
//! barrier: the machine you most want to inspect is usually one you cannot
//! install software on.
//!
//! This module removes that requirement by shipping a small POSIX shell probe
//! over the existing SSH connection and parsing what comes back. It uses only
//! `ss`, `ps`, and `readlink` — present on effectively every Linux host.
//!
//! The probe emits sections separated by `#MARKER` lines rather than trying to
//! join the data in shell, which keeps the remote side trivial and puts all the
//! parsing here where it can be tested.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::{PortInfo, TcpState};

/// POSIX shell probe run on the remote host.
///
/// Notes on portability:
/// - `ss -H` (suppress header) is too new for some distros, so the header is
///   filtered locally instead.
/// - `readlink` is only run for PIDs that actually own a socket, typically a
///   couple of dozen, rather than every process on the box.
/// - Every command is `|| true`-guarded: a host missing one data source should
///   degrade, not fail outright.
///
/// **Markers are printed as `'#%s\n' TCP`, never written literally.** The probe
/// runs `ps ... args=`, which lists the probe's own shell — whose command line
/// is this entire script. Spelling a marker literally here would emit it inside
/// the process table, so the parser would see a section boundary in the middle
/// of the data. Keeping `#` and the name apart means the script text can appear
/// in its own output harmlessly.
pub(crate) const PROBE: &str = r#"
T=$(ss -tanp 2>/dev/null || true)
U=$(ss -uanp 2>/dev/null || true)
if [ -z "$T" ] && [ -z "$U" ]; then printf '#%s\n' NOSS; exit 0; fi
printf '#%s\n%s\n#%s\n%s\n' TCP "$T" UDP "$U"
printf '#%s\n' PROC
ps -eo pid=,ppid=,user=,rss=,etimes=,times=,args= 2>/dev/null || true
printf '#%s\n' EXE
printf '%s\n%s\n' "$T" "$U" | tr ',' '\n' | sed -n 's/^pid=\([0-9]*\).*/\1/p' | sort -u |
while read p; do
  l=$(readlink "/proc/$p/exe" 2>/dev/null) && printf '%s\t%s\n' "$p" "$l"
done
printf '#%s\n' END
"#;

/// One row from the remote `ps` table.
#[derive(Debug, Clone, Default)]
struct ProcRow {
    ppid: u32,
    user: String,
    rss_kb: u64,
    etimes: u64,
    cpu_seconds: f64,
    args: String,
}

// ── Entry point ──────────────────────────────────────────────────────

pub(crate) fn parse_probe(output: &str) -> Result<Vec<PortInfo>, String> {
    // Line-exact, not a substring search: the process table can legitimately
    // contain a command line that mentions this marker.
    if output.lines().any(|l| l.trim_end() == "#NOSS") {
        return Err(
            "remote host has neither portview nor `ss`. Install portview there, \
             or install iproute2."
                .to_string(),
        );
    }

    let tcp = section(output, "#TCP");
    let udp = section(output, "#UDP");
    let procs = parse_ps(&section(output, "#PROC"));
    let exes = parse_exe(&section(output, "#EXE"));

    // Child counts come from the full remote process table, so the figure
    // matches what a local run would report rather than only counting children
    // that happen to hold sockets.
    let mut child_counts: HashMap<u32, u32> = HashMap::new();
    for row in procs.values() {
        *child_counts.entry(row.ppid).or_insert(0) += 1;
    }

    let now = SystemTime::now();
    let mut infos = Vec::new();

    for (text, is_udp) in [(tcp, false), (udp, true)] {
        for line in text.lines() {
            let Some(sock) = parse_ss_line(line, is_udp) else {
                continue;
            };

            let proc = procs.get(&sock.pid);
            // Prefer the executable, matching local behaviour: `ss` reports the
            // thread name, so a Node server shows up as "MainThread" otherwise.
            let process_name = exes
                .get(&sock.pid)
                .map(|p| basename(p).to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| sock.name.clone())
                .unwrap_or_default();

            infos.push(PortInfo {
                port: sock.port,
                protocol: sock.protocol,
                pid: sock.pid,
                ppid: proc.map(|p| p.ppid).unwrap_or(0),
                process_name,
                command: proc.map(|p| p.args.clone()).unwrap_or_default(),
                user: proc.map(|p| p.user.clone()).unwrap_or_default(),
                state: sock.state,
                memory_bytes: proc.map(|p| p.rss_kb * 1024).unwrap_or(0),
                cpu_seconds: proc.map(|p| p.cpu_seconds).unwrap_or(0.0),
                start_time: proc.and_then(|p| now.checked_sub(Duration::from_secs(p.etimes))),
                children: child_counts.get(&sock.pid).copied().unwrap_or(0),
                local_addr: sock.addr,
            });
        }
    }

    // Match the local pipeline: one row per (port, protocol, pid).
    //
    // LISTEN sorts first within a group so that dedup keeps it. A process
    // usually has both a listening socket and established connections on the
    // same port; if an ESTAB row won, the port would disappear from the default
    // listening-only view entirely.
    let listen_first = |p: &PortInfo| u8::from(p.state != TcpState::Listen);
    infos.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.pid.cmp(&b.pid))
            .then_with(|| listen_first(a).cmp(&listen_first(b)))
    });
    infos.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol && a.pid == b.pid);

    Ok(infos)
}

/// Keep only listening sockets, mirroring `get_port_infos(filter_listening)`.
pub(crate) fn filter_listening(infos: Vec<PortInfo>) -> Vec<PortInfo> {
    infos
        .into_iter()
        .filter(|i| i.state == TcpState::Listen || i.protocol.starts_with("UDP"))
        .collect()
}

// ── Section splitting ────────────────────────────────────────────────

/// Text between `marker` and the next `#MARKER` line.
fn section(output: &str, marker: &str) -> String {
    let mut collecting = false;
    let mut out = String::new();
    for line in output.lines() {
        let trimmed = line.trim_end();
        if trimmed == marker {
            collecting = true;
            continue;
        }
        if collecting {
            if trimmed.starts_with('#')
                && trimmed
                    .trim_start_matches('#')
                    .chars()
                    .all(|c| c.is_ascii_uppercase())
                && !trimmed.is_empty()
            {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

// ── ss ───────────────────────────────────────────────────────────────

struct SockLine {
    protocol: String,
    state: TcpState,
    addr: IpAddr,
    port: u16,
    pid: u32,
    name: Option<String>,
}

/// Map an `ss` state token. `ss` uses its own spellings (`ESTAB`, `TIME-WAIT`),
/// which differ from both the kernel's and portview's own names.
fn state_from_ss(s: &str) -> TcpState {
    match s {
        "LISTEN" => TcpState::Listen,
        "ESTAB" => TcpState::Established,
        "TIME-WAIT" => TcpState::TimeWait,
        "CLOSE-WAIT" => TcpState::CloseWait,
        "FIN-WAIT-1" => TcpState::FinWait1,
        "FIN-WAIT-2" => TcpState::FinWait2,
        "SYN-SENT" => TcpState::SynSent,
        "SYN-RECV" => TcpState::SynRecv,
        "CLOSING" => TcpState::Closing,
        "LAST-ACK" => TcpState::LastAck,
        "CLOSED" | "UNCONN" => TcpState::Close,
        _ => TcpState::Unknown,
    }
}

fn parse_ss_line(line: &str, is_udp: bool) -> Option<SockLine> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return None;
    }
    // Skip the header, which `ss` prints unless -H is supported.
    if fields[0] == "State" || fields[0] == "Netid" {
        return None;
    }

    let (addr, port) = parse_addr_port(fields[3])?;
    if port == 0 {
        return None;
    }

    // UDP has no LISTEN state; portview treats a bound UDP socket as listening.
    let state = if is_udp {
        TcpState::Listen
    } else {
        state_from_ss(fields[0])
    };

    let (pid, name) = parse_users(line);

    Some(SockLine {
        protocol: if is_udp { "UDP" } else { "TCP" }.to_string(),
        state,
        addr,
        port,
        pid,
        name,
    })
}

/// Split an `ss` address column into address and port.
///
/// Handles `127.0.0.1:3000`, `[::1]:8080`, `*:22`, and `0.0.0.0:*`.
fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    let idx = s.rfind(':')?;
    let (addr_part, port_part) = (&s[..idx], &s[idx + 1..]);
    let port: u16 = port_part.parse().ok()?;

    let addr_part = addr_part.trim_start_matches('[').trim_end_matches(']');
    let addr = if addr_part == "*" || addr_part.is_empty() {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else if let Ok(a) = addr_part.parse::<IpAddr>() {
        a
    } else {
        // `ss` may print a %scope suffix on link-local IPv6 addresses.
        addr_part
            .split('%')
            .next()?
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    };

    Some((addr, port))
}

/// Pull pid and process name out of `users:(("node",pid=6,fd=21))`.
fn parse_users(line: &str) -> (u32, Option<String>) {
    let Some(start) = line.find("users:((") else {
        return (0, None);
    };
    let rest = &line[start + "users:((".len()..];

    let name = rest
        .strip_prefix('"')
        .and_then(|r| r.find('"').map(|end| r[..end].to_string()));

    let pid = rest
        .find("pid=")
        .and_then(|i| {
            let digits: String = rest[i + 4..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            digits.parse::<u32>().ok()
        })
        .unwrap_or(0);

    (pid, name)
}

// ── ps / exe ─────────────────────────────────────────────────────────

/// Parse `ps -eo pid=,ppid=,user=,rss=,etimes=,times=,args=`.
///
/// `args` is last precisely because it contains spaces; everything before it is
/// a single token, so a bounded split is safe.
fn parse_ps(text: &str) -> HashMap<u32, ProcRow> {
    let mut map = HashMap::new();

    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() {
            continue;
        }
        // `ps` pads columns, so runs of spaces are common — split on whitespace
        // rather than with splitn, which would yield empty pieces.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 6 {
            continue;
        }
        let Ok(pid) = tokens[0].parse::<u32>() else {
            continue;
        };
        let ppid = tokens[1].parse::<u32>().unwrap_or(0);
        let user = tokens[2].to_string();
        let rss_kb = tokens[3].parse::<u64>().unwrap_or(0);
        let etimes = tokens[4].parse::<u64>().unwrap_or(0);
        let cpu_seconds = parse_cpu_time(tokens[5]);

        // Recover args by skipping the six fixed fields in the original line,
        // preserving whatever internal spacing the command had.
        let args = nth_field_onward(line, 6);

        map.insert(
            pid,
            ProcRow {
                ppid,
                user,
                rss_kb,
                etimes,
                cpu_seconds,
                args,
            },
        );
    }

    map
}

/// Everything from the `n`-th whitespace-separated field to end of line.
fn nth_field_onward(line: &str, n: usize) -> String {
    let mut seen = 0;
    let mut in_field = false;
    for (i, c) in line.char_indices() {
        if c.is_whitespace() {
            if in_field {
                in_field = false;
            }
        } else {
            if !in_field {
                in_field = true;
                if seen == n {
                    return line[i..].to_string();
                }
                seen += 1;
            }
        }
    }
    String::new()
}

/// `ps -o times=` yields plain seconds, but some implementations emit `[DD-]HH:MM:SS`.
fn parse_cpu_time(s: &str) -> f64 {
    if let Ok(v) = s.parse::<f64>() {
        return v;
    }
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<f64>().unwrap_or(0.0), r),
        None => (0.0, s),
    };
    let mut total = days * 86_400.0;
    let mut parts: Vec<f64> = rest
        .split(':')
        .map(|p| p.parse::<f64>().unwrap_or(0.0))
        .collect();
    parts.reverse(); // seconds, minutes, hours
    for (i, v) in parts.iter().enumerate() {
        total += v * 60f64.powi(i as i32);
    }
    total
}

fn parse_exe(text: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let Some((pid, path)) = line.split_once('\t') else {
            continue;
        };
        if let Ok(pid) = pid.trim().parse::<u32>() {
            map.insert(pid, path.trim().to_string());
        }
    }
    map
}

fn basename(path: &str) -> &str {
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
#TCP
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      511    127.0.0.1:3000      0.0.0.0:*    users:((\"MainThread\",pid=6,fd=21))
ESTAB  0      0      127.0.0.1:3000      127.0.0.1:51234 users:((\"MainThread\",pid=6,fd=24))
LISTEN 0      4096   *:22                *:*          users:((\"sshd\",pid=800,fd=3))
#UDP
UNCONN 0      0      0.0.0.0:68          0.0.0.0:*    users:((\"dhclient\",pid=500,fd=6))
#PROC
    6     1 deploy   45123     3600    12 node /srv/app/server.js
  800     1 root      8100   864000     3 /usr/sbin/sshd -D
  500     1 root      4200   864000     0 dhclient
   99     6 deploy    2000      600     0 node /srv/app/worker.js
#EXE
6\t/usr/bin/node
800\t/usr/sbin/sshd
#END
";

    #[test]
    fn parses_ports_processes_and_metrics() {
        let ports = parse_probe(SAMPLE).unwrap();
        let p3000 = ports
            .iter()
            .find(|p| p.port == 3000 && p.state == TcpState::Listen)
            .unwrap();

        assert_eq!(p3000.pid, 6);
        assert_eq!(p3000.ppid, 1);
        assert_eq!(p3000.user, "deploy");
        assert_eq!(p3000.command, "node /srv/app/server.js");
        assert_eq!(p3000.memory_bytes, 45123 * 1024);
        assert_eq!(p3000.cpu_seconds, 12.0);
        assert_eq!(p3000.local_addr.to_string(), "127.0.0.1");
    }

    #[test]
    fn executable_beats_the_thread_name_ss_reports() {
        // ss says "MainThread"; /proc/<pid>/exe says node. Same rule as local.
        let ports = parse_probe(SAMPLE).unwrap();
        let p = ports.iter().find(|p| p.port == 3000).unwrap();
        assert_eq!(p.process_name, "node");
    }

    #[test]
    fn falls_back_to_ss_name_when_exe_is_unreadable() {
        // pid 500 has no #EXE entry (another user's process without root).
        let ports = parse_probe(SAMPLE).unwrap();
        let p = ports.iter().find(|p| p.port == 68).unwrap();
        assert_eq!(p.process_name, "dhclient");
    }

    #[test]
    fn children_come_from_the_full_remote_process_table() {
        // pid 99 has ppid 6 but holds no socket, so it is only visible via ps.
        let ports = parse_probe(SAMPLE).unwrap();
        let p = ports.iter().find(|p| p.port == 3000).unwrap();
        assert_eq!(p.children, 1);
    }

    #[test]
    fn wildcard_and_udp_are_handled() {
        let ports = parse_probe(SAMPLE).unwrap();
        let ssh = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh.local_addr.to_string(), "0.0.0.0");

        let udp = ports.iter().find(|p| p.port == 68).unwrap();
        assert_eq!(udp.protocol, "UDP");
        assert_eq!(udp.state, TcpState::Listen); // bound UDP counts as listening
    }

    #[test]
    fn header_line_is_skipped() {
        let ports = parse_probe(SAMPLE).unwrap();
        assert!(ports.iter().all(|p| p.port != 0));
        // The header row must not become a phantom entry.
        assert!(ports.iter().all(|p| p.process_name != "State"));
    }

    #[test]
    fn dedup_keeps_the_listening_row() {
        // pid 6 has both LISTEN and ESTAB on 3000. They collapse to one row, and
        // it must be the listener — otherwise the port vanishes from the default
        // view. Feed ESTAB first to prove order does not decide it.
        let reordered = SAMPLE.replace(
            "LISTEN 0      511    127.0.0.1:3000      0.0.0.0:*    users:((\"MainThread\",pid=6,fd=21))\nESTAB  0      0      127.0.0.1:3000      127.0.0.1:51234 users:((\"MainThread\",pid=6,fd=24))",
            "ESTAB  0      0      127.0.0.1:3000      127.0.0.1:51234 users:((\"MainThread\",pid=6,fd=24))\nLISTEN 0      511    127.0.0.1:3000      0.0.0.0:*    users:((\"MainThread\",pid=6,fd=21))",
        );
        assert_ne!(reordered, SAMPLE, "test fixture substitution failed");

        for input in [SAMPLE, reordered.as_str()] {
            let ports = parse_probe(input).unwrap();
            let rows: Vec<_> = ports.iter().filter(|p| p.port == 3000).collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].state, TcpState::Listen);
        }
    }

    #[test]
    fn listening_filter_keeps_listeners_and_udp() {
        let all = parse_probe(SAMPLE).unwrap();
        let listening = filter_listening(all);
        assert!(listening.iter().all(|p| p.state == TcpState::Listen));
        assert!(listening.iter().any(|p| p.port == 68));
        // The ESTAB row on 3000 is gone; the LISTEN row remains.
        assert_eq!(listening.iter().filter(|p| p.port == 3000).count(), 1);
    }

    /// Verbatim probe output from a real host (paths generalised), including
    /// quirks a handwritten fixture misses: the header runs "Port" and
    /// "Process" together, rows carry trailing padding, and the UDP section can
    /// contain nothing but a header.
    const REAL: &str = "\
#TCP
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      511        127.0.0.1:3000      0.0.0.0:*    users:((\"MainThread\",pid=6,fd=21))
LISTEN 0      5          127.0.0.1:5000      0.0.0.0:*    users:((\"python3\",pid=8,fd=3))
LISTEN 0      511        127.0.0.1:8081      0.0.0.0:*    users:((\"MainThread\",pid=22,fd=21))
#UDP
State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
#PROC
    1     0 root      1760       3        0 /bin/sh
    6     1 root     45552     120        4 node /opt/app/web.js
    8     1 root     18720     120        1 python3 /opt/app/worker.py
   22     7 root     45852      90        0 node /opt/app/api.js
#EXE
22\t/usr/local/bin/node
6\t/usr/local/bin/node
8\t/usr/bin/python3.12
#END
";

    #[test]
    fn parses_verbatim_output_from_a_real_host() {
        let ports = parse_probe(REAL).unwrap();
        assert_eq!(ports.len(), 3, "{:#?}", ports);

        let web = ports.iter().find(|p| p.port == 3000).unwrap();
        assert_eq!(web.process_name, "node"); // not "MainThread"
        assert_eq!(web.user, "root");
        assert_eq!(web.command, "node /opt/app/web.js");
        assert_eq!(web.memory_bytes, 45552 * 1024);
        assert_eq!(web.cpu_seconds, 4.0);

        let py = ports.iter().find(|p| p.port == 5000).unwrap();
        assert_eq!(py.process_name, "python3.12");

        // The header line must not survive as a row, and no phantom ports.
        assert!(ports.iter().all(|p| p.port != 0));
    }

    #[test]
    fn header_only_udp_section_yields_nothing() {
        let ports = parse_probe(REAL).unwrap();
        assert!(ports.iter().all(|p| p.protocol != "UDP"));
    }

    #[test]
    fn probe_source_never_contains_a_literal_marker() {
        // The probe's own command line shows up in its `ps` output. If a marker
        // were spelled literally in the script, it would appear mid-data and be
        // read as a section boundary.
        for marker in ["#TCP", "#UDP", "#PROC", "#EXE", "#END", "#NOSS"] {
            assert!(
                !PROBE.contains(marker),
                "PROBE contains the literal marker {} — print it as '#%s' instead",
                marker
            );
        }
    }

    #[test]
    fn the_probes_own_command_line_does_not_corrupt_parsing() {
        // Regression: the shell running the probe appears in the process table
        // with the whole script as its args, markers and all.
        let mut input = String::from(
            "#TCP\nLISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=6,fd=21))\n#UDP\n#PROC\n",
        );
        input.push_str("    6     1 root 45552 120 4 node /opt/app/web.js\n");
        // The probe's own shell, args inlined exactly as ps would report them.
        input.push_str("   99     1 root  1760   3 0 sh -c ");
        input.push_str(&PROBE.replace('\n', " "));
        input.push('\n');
        input.push_str("#EXE\n6\t/usr/bin/node\n#END\n");

        let ports = parse_probe(&input).expect("probe output must still parse");
        assert_eq!(ports.len(), 1, "{:#?}", ports);
        assert_eq!(ports[0].port, 3000);
        assert_eq!(ports[0].process_name, "node");
    }

    #[test]
    fn missing_ss_is_a_clear_error() {
        let err = parse_probe("#NOSS\n").unwrap_err();
        assert!(err.contains("iproute2"), "{}", err);
    }

    #[test]
    fn ipv6_addresses_parse() {
        assert_eq!(parse_addr_port("[::1]:8080").unwrap().0.to_string(), "::1");
        assert_eq!(parse_addr_port("[::]:443").unwrap().1, 443);
        // Link-local with a scope suffix.
        assert!(parse_addr_port("[fe80::1%eth0]:53").is_some());
    }

    #[test]
    fn peer_wildcard_port_is_rejected() {
        assert!(parse_addr_port("0.0.0.0:*").is_none());
    }

    #[test]
    fn cpu_time_accepts_seconds_and_clock_format() {
        assert_eq!(parse_cpu_time("12"), 12.0);
        assert_eq!(parse_cpu_time("00:02:00"), 120.0);
        assert_eq!(parse_cpu_time("1-00:00:00"), 86_400.0);
    }

    #[test]
    fn commands_with_many_spaces_survive() {
        let text =
            "  42     1 root      100     50     0 /usr/bin/env  python3   -m  http.server\n";
        let procs = parse_ps(text);
        assert_eq!(
            procs.get(&42).unwrap().args,
            "/usr/bin/env  python3   -m  http.server"
        );
    }

    #[test]
    fn rows_without_a_process_still_appear() {
        // TIME_WAIT sockets have no users:(()) field at all.
        let text = "#TCP\nTIME-WAIT 0 0 127.0.0.1:7200 127.0.0.1:44322\n#PROC\n#EXE\n#END\n";
        let ports = parse_probe(text).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].pid, 0);
        assert_eq!(ports[0].state, TcpState::TimeWait);
    }
}
