#!/usr/bin/env bash
# Choreographs the main demo by sending keys to the recorded tmux session.
# Argument: the tmux session name.
#
# Note: never send a literal ";" to tmux send-keys — tmux parses it as a command
# separator, silently mangling the command. Screens are cleared with C-l, which
# also keeps a stray "clear" out of the recording.
set -uo pipefail

SESSION="$1"

for _ in $(seq 1 100); do
    tmux has-session -t "$SESSION" 2>/dev/null && break
    sleep 0.1
done
sleep 1

tmux set-option -t "$SESSION" -g status off 2>/dev/null || true
# A neutral prompt — no user, no host, no path.
tmux send-keys -t "$SESSION" "PS1='\[\033[38;5;213m\]❯\[\033[0m\] '" Enter
sleep 0.4
tmux send-keys -t "$SESSION" C-l
sleep 0.6

# Type a command a character at a time so the recording reads like real typing.
type_cmd() {
    local cmd="$1"
    local i
    for ((i = 0; i < ${#cmd}; i++)); do
        tmux send-keys -t "$SESSION" -l -- "${cmd:i:1}"
        sleep 0.045
    done
    sleep 0.35
    tmux send-keys -t "$SESSION" Enter
}

clear_screen() {
    tmux send-keys -t "$SESSION" C-l
    sleep 0.7
}

# 1. The core view.
type_cmd "portview"
sleep 4.5
clear_screen

# 2. Inspect one port. This view ends with an interactive "Kill process N? [y/N]"
#    prompt, so the recording must answer it — anything but "y" declines, which
#    also shows off the safe default.
type_cmd "portview 8080"
sleep 4.5
tmux send-keys -t "$SESSION" Enter
sleep 1.2
clear_screen

# 3. Diagnostics — real findings from real conditions the demo services create.
type_cmd "portview doctor"
sleep 5
clear_screen

# 4. The interactive TUI.
type_cmd "portview watch"
sleep 3.5
tmux send-keys -t "$SESSION" "t" # tree mode: workers group under the primary
sleep 4
tmux send-keys -t "$SESSION" "j"
sleep 0.8
tmux send-keys -t "$SESSION" "j"
sleep 0.8
tmux send-keys -t "$SESSION" "j"
sleep 1.4
tmux send-keys -t "$SESSION" Enter # detail view
sleep 4
tmux send-keys -t "$SESSION" Escape
sleep 1.2
tmux send-keys -t "$SESSION" "q"
sleep 1.5

clear_screen
tmux send-keys -t "$SESSION" "exit" Enter
