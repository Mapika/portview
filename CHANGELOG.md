# Changelog

## Unreleased

### Fixed

**Ports whose owner could not be resolved were hidden entirely.** This is the
worst failure mode for a port viewer: it reported a port as free when something
was listening on it. On a normal Linux user account, `ss -tlnH` showed a
root-owned listener on `:53` while `portview` reported no TCP listeners at all.

Such sockets are now listed with `-` in the columns that cannot be filled, on
Linux and Windows. Two causes, previously indistinguishable because both were
silently dropped: the socket belongs to another user and `/proc/<pid>/fd` is
unreadable without `sudo`, or nothing owns it at all (`TIME_WAIT` outlives the
process that opened it).

macOS is unchanged here — it enumerates sockets per process, so a process that
cannot be opened contributes nothing to enumerate in the first place.

**`--all` collapsed connections, contradicting `doctor`.** Non-listening rows
were deduplicated by `(port, protocol, pid)`, so sixty `TIME_WAIT` sockets on
one port rendered as a single row. `doctor` would report a connection leak that
`--all` then appeared to disprove. Connections are now one row each; listeners
are still deduplicated, since a process bound to both v4 and v6 is one listener.

## 2.0.2

No functional changes. Corrects the MCP Registry namespace, which is
case-sensitive and follows the GitHub account's own casing:
`io.github.Mapika/portview`, not `io.github.mapika/portview`. The registry
rejected 2.0.1 with a 403 on that mismatch.

Because the ownership token lives in the crate README on crates.io and published
versions are immutable, the corrected token needs a new version to travel on.

## 2.0.1

No functional changes. This release exists so portview can be listed in the
[MCP Registry](https://registry.modelcontextprotocol.io), which verifies
ownership by looking for an `mcp-name:` token in the crate's README on
crates.io — and 2.0.0's README predates it. crates.io versions are immutable,
so the token cannot be added retroactively.

- Listed in the official MCP Registry as `io.github.mapika/portview`
- Release workflow now publishes to the MCP Registry, and checks the tag against
  `Cargo.toml`, `flake.nix`, and `server.json` together

## 2.0.0

### Breaking

**The `PROCESS` column and the `process` field in `--json` now report the
executable, not the thread name.** On Linux this came from `/proc/<pid>/comm`,
which is the *thread* name — and runtimes overwrite it. A Node dev server
reported as `MainThread`, exactly as it still does under `ps`, `ss`, and `lsof`.
macOS and Windows already read the executable; Linux was the odd one out.

Values change accordingly:

| Before | After |
|--------|-------|
| `MainThread` | `node` |
| `python3` | `python3.12` |

`comm` is also truncated to 15 bytes, so previously-clipped names now appear in
full. If you script against `--json`, check anything that matches on `process`.

`portview ssh <host>` no longer fails when portview is missing on the remote —
it falls back to agentless collection instead. If you relied on that error,
note that it is now a warning on stderr.

### Added

- **`portview mcp`** — an MCP server over stdio, so Claude Code, Cursor, and
  other MCP clients can query and act on ports directly. Five tools;
  `kill_port` is marked destructive and is withheld entirely under
  `--read-only`. Adds no dependencies and about 29 KB of binary.
- **Agentless SSH** — `portview ssh <host>` works without portview installed on
  the remote, collecting over the same connection with `ss` and `ps`. Automatic,
  or forced with `--agentless`. Covers scans, port inspection, and process
  search; `watch` and `doctor` still need portview on the far end.
- **GitHub Action** — `uses: mapika/portview@v2` runs `doctor` in CI, annotates
  findings inline, and can fail the job on errors or warnings.
- `--json` now includes `start_time_unix`, so remote scans report uptime.

### Fixed

- **`doctor`'s stale-connection check could never fire.** Both branches were
  unreachable for three independent reasons: sockets with no owning process were
  discarded (which is every `TIME_WAIT` socket), and deduplication collapsed many
  `CLOSE_WAIT` sockets on one port into a single row, so counts never exceeded 1.
  Counts now come from the raw socket table. Verified against 60 real
  `TIME_WAIT` and 16 real `CLOSE_WAIT` sockets.
- `portview ssh <host>` reported `-` for `UPTIME` whenever the remote had
  portview installed.
- Dependabot auto-merge failed on every pull request, because GitHub's
  auto-merge requires a protected branch.

### Changed

- The README demo recordings are regenerable via `demo/record.sh` and run inside
  an isolated namespace, so nothing about the machine that produced them leaks.
