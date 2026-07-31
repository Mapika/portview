#!/usr/bin/env bash
# Regenerate the README demo GIFs.
#
#   ./demo/record.sh
#
# The recording runs inside an isolated user + network + PID + mount + UTS
# namespace. That is a privacy control, not a convenience: a terminal recording
# published to a public README would otherwise bake in your username, hostname,
# real filesystem paths, and every service you happen to have listening. Inside
# the namespace the user maps to root, the hostname is fixed, and the network
# stack is empty — so the only ports that can possibly appear are the demo
# services this script starts.
#
# Requires: asciinema, agg, tmux, node, python3, unshare (util-linux).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

missing=()
for tool in asciinema agg tmux node python3 unshare; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "error: missing required tools: ${missing[*]}" >&2
    echo "  asciinema: https://github.com/asciinema/asciinema/releases" >&2
    echo "  agg:       https://github.com/asciinema/agg/releases" >&2
    exit 1
fi

if [ ! -x "$REPO_ROOT/target/release/portview" ]; then
    echo "error: build first — cargo build --release" >&2
    exit 1
fi

# Verify unprivileged namespaces actually work before we get halfway in.
if ! unshare -Urn --fork true 2>/dev/null; then
    echo "error: unprivileged user namespaces are unavailable on this kernel." >&2
    echo "       Refusing to record on the host: it would leak your real" >&2
    echo "       username, hostname, paths, and listening services." >&2
    exit 1
fi

# Passed through so stage.sh can scan the finished recordings for these strings
# and refuse to publish anything that leaked host identity.
LEAK_USER="$(id -un)"
LEAK_HOME="$HOME"
LEAK_HOST="$(hostname)"
export LEAK_USER LEAK_HOME LEAK_HOST

echo "==> recording in an isolated namespace"
exec unshare --user --map-root-user --net --pid --mount --uts --fork --mount-proc \
    "$REPO_ROOT/demo/stage.sh"
