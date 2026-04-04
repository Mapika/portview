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

## Submitting changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure `cargo test`, `cargo fmt --check`, and `cargo clippy` pass
4. Open a pull request

## Reporting bugs

Use the [bug report template](https://github.com/Mapika/portview/issues/new?template=bug_report.yml) or open a plain issue with:
- Your OS and version
- portview version (`portview --version`)
- What you expected vs what happened
- Steps to reproduce
