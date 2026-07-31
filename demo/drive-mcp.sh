#!/usr/bin/env bash
# Choreographs the MCP demo: a real JSON-RPC exchange over stdio, the same one
# an AI agent makes. Argument: the tmux session name.
#
# See drive-demo.sh for why ";" must never be sent to tmux send-keys.
set -uo pipefail

SESSION="$1"

for _ in $(seq 1 100); do
    tmux has-session -t "$SESSION" 2>/dev/null && break
    sleep 0.1
done
sleep 1

tmux set-option -t "$SESSION" -g status off 2>/dev/null || true
tmux send-keys -t "$SESSION" "PS1='\[\033[38;5;213m\]❯\[\033[0m\] '" Enter
sleep 0.4
tmux send-keys -t "$SESSION" C-l
sleep 0.6

type_cmd() {
    local cmd="$1"
    local i
    for ((i = 0; i < ${#cmd}; i++)); do
        tmux send-keys -t "$SESSION" -l -- "${cmd:i:1}"
        sleep 0.03
    done
    sleep 0.35
    tmux send-keys -t "$SESSION" Enter
}

clear_screen() {
    tmux send-keys -t "$SESSION" C-l
    sleep 0.7
}

# Ask the server what it can do — the grep keeps it to the tool names so the
# recording stays legible instead of dumping the full schema.
type_cmd "echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}' | portview mcp | grep -o '\"name\":\"[a-z_]*\"'"
sleep 5
clear_screen

# Then make a real tool call, the way an agent would.
type_cmd "echo '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"find_process\",\"arguments\":{\"name\":\"cache\"}}}' | portview mcp"
sleep 5.5

clear_screen
tmux send-keys -t "$SESSION" "exit" Enter
