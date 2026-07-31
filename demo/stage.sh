#!/usr/bin/env bash
# Runs INSIDE the isolated namespace created by record.sh.
#
# Sets up a neutral stage, starts the demo services, then drives a tmux session
# with asciinema recording it. Nothing here may reference the host's real paths,
# user, or hostname — that is the whole point of the isolation.
set -euo pipefail

: "${REPO_ROOT:?must be set by record.sh}"
OUT_DIR="$REPO_ROOT/demo"

# ── Neutral stage ────────────────────────────────────────────────────
hostname devbox
ip link set lo up

# tmpfs over /opt gives the COMMAND column neutral paths like /opt/app/web.js
# instead of anything under the real home directory.
mount -t tmpfs tmpfs /opt
mkdir -p /opt/app /opt/bin
cp "$REPO_ROOT/target/release/portview" /opt/bin/portview
cp "$REPO_ROOT"/demo/services/* /opt/app/
export PATH="/opt/bin:$PATH"
export HOME=/root
cd /opt/app

# ── Demo services ────────────────────────────────────────────────────
echo "==> starting demo services"
node /opt/app/web.js &
node /opt/app/api.js &
node /opt/app/ingest.js &
python3 /opt/app/worker.py &
node /opt/app/cache.js &

# cache.js allocates and touches 1.2 GB and ingest.js leaks 16 CLOSE_WAIT
# sockets, but neither is instant. Wait for doctor to actually report both,
# rather than sleeping a guessed interval and hoping — a short recording that
# races the allocation shows "All clear" and silently misrepresents the tool.
echo "==> waiting for demo conditions to materialise"
for _ in $(seq 1 60); do
    findings=$(portview doctor --json 2>/dev/null || true)
    case "$findings" in
        *resource_hogs*stale_connections* | *stale_connections*resource_hogs*)
            echo "==> both findings present"
            break
            ;;
    esac
    sleep 0.5
done

echo "==> ports visible in namespace:"
portview --no-color || true

# ── Record ───────────────────────────────────────────────────────────
record() {
    local name="$1" driver="$2" cols="${3:-100}" rows="${4:-28}"
    local session="pv_$name"

    rm -f "$OUT_DIR/$name.cast"
    tmux kill-session -t "$session" 2>/dev/null || true

    # Drive the session from the background; it waits for tmux to come up.
    "$driver" "$session" &
    local driver_pid=$!

    # --window-size is what actually sets the recorded geometry on asciinema 3.
    # Without it the pty stays at the default 80x24, tmux gets clamped to that
    # regardless of -x/-y, and portview's table wraps into unreadable fragments.
    # Do not add `|| true` here: a silent failure produced exactly that bug.
    asciinema rec --quiet --overwrite \
        --window-size "${cols}x${rows}" \
        --command "tmux new-session -s $session -x $cols -y $rows" \
        "$OUT_DIR/$name.cast"

    wait "$driver_pid" 2>/dev/null || true
    tmux kill-session -t "$session" 2>/dev/null || true

    assert_geometry "$OUT_DIR/$name.cast" "$cols" "$rows"
    assert_no_leaks "$OUT_DIR/$name.cast"

    echo "==> rendering $name.gif"
    agg --font-size 16 --line-height 1.4 --theme asciinema \
        "$OUT_DIR/$name.cast" "$OUT_DIR/$name.gif"
}

# The recorded geometry must match what we asked for. portview sizes its table
# to the terminal, so a recording that silently fell back to 80x24 renders the
# scan view as wrapped fragments — which is what shipped before this check.
assert_geometry() {
    local cast="$1" want_cols="$2" want_rows="$3"
    local got
    got=$(head -1 "$cast" | tr ',' '\n' | grep -o '"cols":[0-9]*' | head -1 | cut -d: -f2)

    if [ "$got" != "$want_cols" ]; then
        echo "error: $cast recorded at ${got:-unknown} columns, expected ${want_cols}." >&2
        echo "       portview's table needs ~105 columns; anything narrower wraps." >&2
        exit 1
    fi
    echo "==> $cast geometry ok (${want_cols}x${want_rows})"
}

# Refuse to render anything that captured host identity. The namespace prevents
# most leaks, but not all: anything that embeds an absolute interpreter path
# (Node's fork() uses process.execPath, which under nvm lives in $HOME) shows up
# in the COMMAND column. These GIFs go into a public README, so this is a hard
# failure rather than a warning.
assert_no_leaks() {
    local cast="$1" found=0 pattern

    for pattern in "$LEAK_USER" "$LEAK_HOME" "$LEAK_HOST" "/home/" "/Users/"; do
        [ -n "$pattern" ] || continue
        if grep -qF -- "$pattern" "$cast"; then
            echo "error: recording $cast leaked host identity: '$pattern'" >&2
            grep -oF -m 3 -- "$pattern" "$cast" | head -3 >&2
            found=1
        fi
    done

    if [ "$found" -ne 0 ]; then
        echo "error: refusing to render a GIF containing host details." >&2
        exit 1
    fi
    echo "==> $cast passed the leak scan"
}

# 120 columns: portview's table needs ~105, and anything narrower wraps.
record demo "$REPO_ROOT/demo/drive-demo.sh" 120 30
record mcp  "$REPO_ROOT/demo/drive-mcp.sh"  120 24

echo "==> done:"
ls -la "$OUT_DIR"/*.gif
