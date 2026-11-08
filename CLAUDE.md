Never add co-author to commits.

Always push after a commit. Never force push.

Install skills from agents/skills.

Do not write long answers, use one sentence until i ask you to expand, then you can use at most 1 short paragraph. Say the thing and stop. Don't restate the question, don't summarize what you just said, don't append a closing offer unless there's a specific next step worth naming.

Do not use uncommon or long words, use domain-specific words.

Do not use emphasis and phrases like "X is real", "the real question", "the actual issue", "genuinely", "importantly", "worth noting", "it's worth pointing out".

Never refer to previous parts of your text, always be explicit. No "the middle one", "the latter", "the former", "as above", "that one", "the second case". Repeat yourself instead.

When you read a file to answer a question, judge it, don't just extract from it. If what you read cannot work as written for the purpose I'm pursuing, say so. Being asked about one aspect of a file is not permission to ignore a defect in another.

Keep the choices I made. Don't swap a name, version, region, path or option I gave for one you think is better; ask. Config and environment changes are additive and idempotent, and don't install or upgrade anything the task doesn't need.

Never write credentials into files, logs or commits.

Test through the public entry point (CLI, API, pipeline, plan) before internals, and don't write tests that only mirror the implementation.

Never use plan mode or the question tool, ask questions in the chat reply instead and keep it as a conversation

Never solve any problems without trying the idiomatic way first, if you cant you shall state it.

Follow googles rust styleguide: https://google.github.io/styleguide/rustguide.html

Always use versionedcommits: https://github.com/mikkel3000/versionedcommits

Every commit body explains its decisions in plain prose, without a "Decision:" label: what was chosen, why, and the reference evidence. Only commits that change the server's behaviour for its users carry a `@major`, `@minor` or `@patch` hint; commits to agent setup, CLAUDE.md, AGENTS/ or the goal loop carry no hint.

## Keycloak compatibility work

Read Keycloak's source at the revision pinned in compatibility/reference.lock before recording or implementing a rule; decompile jars only if the source can't be fetched, and say so. Recordings check those rules and set the expected values.

Edit files with the Edit tool, not inline scripts.

Contract tests must not skip silently: a test that needs a setting fails when the setting is missing.

Each feature follows `AGENTS/workflow.md`. A new machine is set up with `AGENTS/setup.md`; the GitHub release link for the archive may return 504, and the same file comes from the API asset URL `https://api.github.com/repos/keycloak/keycloak/releases/assets/636464250` with `Accept: application/octet-stream`, checked against the same sha256.

## Goal loop

The interactive session is the manager. Goals run one per fresh `claude -p` session through `AGENTS/goal-loop/run_goal.sh`, as `AGENTS/goal-loop/README.md` describes; do the goals' work only through the loop. The loop's state is in `~/.claude/goal-loop/`.

Between runs, review the run: `git log` shows a recording commit (no hint) and an implementation commit (`@minor`) per feature, each body explaining its decisions and with no co-author trailer, all pushed; the fast suite passes with no test over 500 ms; `NEXT_GOAL` holds the next goal. Then start the next run. Before starting a run, stop and tell the user if its goal needs a sign-off the loop cannot give: an independent security review, load, soak or failover tests on production-like hardware, supply-chain or release approval, or any `PLAN.md` step 6 production gate. If `QUESTION` exists or a run fails for a reason other than a usage limit, stop and tell the user.

Start a run with the test environment set, since a shell started before `~/.bashrc` changed lacks it:

```bash
RS_KEYCLOAK_LOCAL_DEV=true RS_KEYCLOAK_DATABASE_URL='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable' RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR="$HOME/console" AGENTS/goal-loop/run_goal.sh
```
