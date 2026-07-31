# Changelog

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
