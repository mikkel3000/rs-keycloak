#!/usr/bin/env bash
# Status line: the shell prompt, the sandbox's status where it has one,
# then the goal loop's state.
dir="$HOME/.claude/goal-loop"
input=$(cat)

# Prompt from the PS1 in ~/.bashrc: bold cyan user@host, bold blue working dir.
cwd=$(printf '%s' "$input" | jq -r '.workspace.current_dir // .cwd // empty' 2>/dev/null)
cwd=${cwd:-$PWD}
line=$(printf '\033[1;36m%s@%s\033[0m:\033[1;34m%s\033[0m' "$(whoami)" "${HOSTNAME%%.*}" "${cwd/#$HOME/\~}")
if [[ -x /usr/local/bin/sbx-claude-hook ]]; then
  sandbox=$(printf '%s' "$input" | /usr/local/bin/sbx-claude-hook claude-status 2>/dev/null)
  line+="${sandbox:+ | }$sandbox"
fi

latest=$(ls -1d "$dir"/runs/*/ 2>/dev/null | tail -1)
count=$(ls -1d "$dir"/runs/*/ 2>/dev/null | wc -l)
if [[ -e "$dir/QUESTION" ]]; then
  loop="loop: question waiting"
elif [[ -s "$dir/RUNNING" ]] && kill -0 "$(cat "$dir/RUNNING")" 2>/dev/null; then
  started=$(stat -c %Y "$latest")
  minutes=$(( ($(date +%s) - started) / 60 ))
  goal=$(head -c 40 "$latest/goal.txt")
  loop="loop: run $count, ${minutes}m: $goal…"
elif [[ -s "$dir/NEXT_GOAL" ]]; then
  loop="loop: $count done, next ready"
else
  loop="loop: idle, $count done"
fi
printf '%s | %s' "$line" "$loop"
