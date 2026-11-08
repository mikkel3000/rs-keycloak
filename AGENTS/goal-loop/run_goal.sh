#!/usr/bin/env bash
# Runs the goal in NEXT_GOAL in a fresh claude session in this checkout.
# The session writes the following goal into NEXT_GOAL, or a blocking
# question into QUESTION. Each run's goal and logs are kept under runs/.
# With --resume, continues the latest run's session with the same goal,
# for a run stopped by a usage limit or an API error.
set -euo pipefail

dir="$HOME/.claude/goal-loop"
workspace="$(cd "$(dirname "$0")/../.." && pwd)"
[[ ! -e "$dir/QUESTION" ]] || { echo "open question in $dir/QUESTION" >&2; exit 3; }

resume=()
if [[ "${1:-}" == --resume ]]; then
  run=$(ls -1d "$dir"/runs/*/ | tail -1)
  run=${run%/}
  session=$(grep -m1 -o '"session_id":"[^"]*"' "$run/log.jsonl" | cut -d'"' -f4)
  [[ -n "$session" ]] || { echo "no session in $run" >&2; exit 2; }
  resume=(--resume "$session")
  attempt=$(ls "$run"/log*.jsonl | wc -l)
  log="$run/log-$attempt.jsonl"
else
  [[ -s "$dir/NEXT_GOAL" ]] || { echo "no goal in $dir/NEXT_GOAL" >&2; exit 2; }
  run="$dir/runs/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$run"
  mv "$dir/NEXT_GOAL" "$run/goal.txt"
  log="$run/log.jsonl"
fi
# A session may copy the runner's added instructions into NEXT_GOAL.
goal=$(sed 's/ Also write the next goal.s text, without the \/goal prefix, into .*$//' "$run/goal.txt")
goal+=" Also write the next goal's text, without the /goal prefix, into $dir/NEXT_GOAL. If a decision only the user can make blocks this goal, write the question into $dir/QUESTION and stop instead."

echo $$ > "$dir/RUNNING"
trap 'rm -f "$dir/RUNNING"' EXIT
cd "$workspace"
claude -p --dangerously-skip-permissions --output-format stream-json --verbose "${resume[@]}" "/goal $goal" > "$log" 2>> "$run/stderr.txt"
echo "run finished: $run"
