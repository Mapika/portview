# Contributing to portview

Thanks for your interest in contributing! Here's how to get started.

## Development setup

```bash
git clone https://github.com/Mapika/portview.git
cd portview
cargo build
cargo test
```

Requires Rust 1.85+ (edition 2024).

## Running locally

```bash
# Run directly
cargo run

# Run the TUI
cargo run -- watch

# Run with Docker support
cargo run -- watch --docker
```

## Code structure

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI parsing, output formatting, entry point |
| `src/cli.rs` | Clap CLI definitions (shared with build.rs) |
| `src/tui.rs` | Interactive TUI (watch mode) |
| `src/linux.rs` | Linux `/proc` filesystem parsing |
| `src/macos.rs` | macOS `libproc` FFI |
| `src/windows.rs` | Windows `iphlpapi`/`kernel32` FFI |
| `src/docker.rs` | Docker container detection and actions |

## Guidelines

- Run `cargo fmt` and `cargo clippy` before submitting
- Add tests for new functionality
- Keep platform-specific code in the respective platform module
- `--json` output must work in all display modes

Only Linux can be run here, but the other two platforms can still be
type-checked — do this before touching `macos.rs`, `windows.rs`, or anything
they share:

```bash
cargo check --target aarch64-apple-darwin
cargo check --target x86_64-pc-windows-msvc
```

## Submitting changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure `cargo test`, `cargo fmt --check`, and `cargo clippy` pass
4. Open a pull request

## Releasing

1. Bump the version in `Cargo.toml`, `flake.nix`, and `server.json` (both the
   top-level `version` and `packages[0].version`), and add a `CHANGELOG.md`
   entry. The release workflow checks all of them against the tag and fails on
   any mismatch, so a missed file turns into a red release rather than a wrong
   publish.
2. Push a full version tag, e.g. `v2.1.0`. That triggers the release workflow:
   cross-platform builds, checksums, a GitHub release, and the Homebrew formula
   update. The tag pattern is `v*.*.*`, so partial tags do not fire it.
3. Move the major tag so `uses: mapika/portview@v2` keeps resolving:

   ```bash
   git tag -f v2 && git push -f origin v2
   ```

   Users pin the GitHub Action to the major tag; without this step that
   reference breaks. This deliberately does not trigger a release.
4. `cargo publish` is manual and not run by CI.

## Reporting bugs

Use the [bug report template](https://github.com/Mapika/portview/issues/new?template=bug_report.yml) or open a plain issue with:
- Your OS and version
- portview version (`portview --version`)
- What you expected vs what happened
- Steps to reproduce
