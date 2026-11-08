# Agent material

What coding agents need to work on rs-keycloak, kept with the code so it moves with the repository.

- `setup.md`: one-time setup of a machine for recording and contract tests.
- `workflow.md`: how each feature is recorded, built and checked.
- `goal-loop/`: runs bounded goals one per fresh `claude -p` session, with an interactive session as manager.

Machine state stays outside the repository: the goal loop's `NEXT_GOAL`, `QUESTION` and run logs live in `~/.claude/goal-loop/`.
