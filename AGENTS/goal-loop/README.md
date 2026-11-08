# Goal loop

Bounded goals run one per fresh `claude -p` session; an interactive session is the manager. Each goal ends by writing the next bounded goal.

State lives in `~/.claude/goal-loop/`: `NEXT_GOAL` (the goal text, without `/goal`), `QUESTION` (a decision only the user can make), `RUNNING` (the runner's PID while a run is going) and `runs/<time>/` (goal, stream-json logs and stderr of each run).

## Manager steps

1. Check `NEXT_GOAL` holds the goal and `QUESTION` does not exist.
2. Start one run in the background: `AGENTS/goal-loop/run_goal.sh`. It moves the goal to `runs/<time>/goal.txt`, and the child writes the following goal into `NEXT_GOAL`.
3. When the run ends, review it: a recording and an implementation commit per feature as `AGENTS/workflow.md` describes, the fast suite passing with no test over 500 ms, and the next goal written.
4. If the log's last line has `"api_error":"usage_limit_reached"`, wait for the reset time in its `result`, then run `AGENTS/goal-loop/run_goal.sh --resume`, which resumes the same session.
5. If `QUESTION` exists or a run fails for another reason, stop and tell the user.
6. Otherwise start the next run.

Stop a run by killing the PID in `RUNNING` and the PID from `pgrep -f "claude -p"`; `pkill -f` with such a pattern also matches the shell running it.

## Status line

`statusline.sh` shows the shell prompt and the loop's state. Set it in `~/.claude/settings.json` with the checkout's absolute path:

```json
"statusLine": {"type": "command", "command": "/path/to/rs-keycloak/AGENTS/goal-loop/statusline.sh"}
```
