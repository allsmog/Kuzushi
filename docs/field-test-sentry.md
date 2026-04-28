# Kuzushi Field-Test Issue Log

Live notes from running `kuzushi scan` against `getsentry/sentry` inside a
Claude Code remote sandbox via tmux. Logged in chronological order so
the patch / triage trail is reproducible.

Environment: Debian-ish container, Node 22.22.2, no `claude` CLI
auth except via the Claude Code OAuth token at
`/home/claude/.claude/remote/.oauth_token`. Outbound network: GitHub OK,
Anthropic API OK, semgrep registry **403**.

Severity tags: **🔴 blocker** = scan can't proceed, **🟠 major** = core
feature broken/degraded, **🟡 minor** = annoyance / papercut.

---

## Setup / pre-flight

### 🔴 #1 — Inherited auth was a no-op

`config.auth = "inherited"` and the `--inherit-claude` flag exist but do
nothing for OAuth-only environments — they just trust whatever's in
env. In a Claude Code remote sandbox there's no `ANTHROPIC_API_KEY`,
yet `/home/claude/.claude/remote/.oauth_token` holds a valid OAuth
bearer. Result: every fresh sandbox prompts for or fails on creds even
when the token is sitting on disk.

**Fix shipped:** `feat(auth): auto-discover ambient OAuth token in
inherited mode` (`bdc15e6`) — adds `resolveAmbientOauthToken()` with a
6-step search path, an `oauthTokenFile` config key, and an env override
for the well-known list.

### 🟠 #2 — `kuzushi doctor` lies about credentials

Before #1, `doctor` reported `[MISSING] credentials` even though the
runtime could authenticate via the Claude Code subprocess. Operators
get a fail-fast that's actually a false positive. Fixed alongside #1.

### 🟠 #3 — `--tasks <id>` is not a whitelist
**(DOC FIXED — `1646fea`)** — flag help text now states explicitly:
"enables but does not strictly hard-restrict; dependent agentic
detectors can still fire even when not listed." Behavior unchanged
(orchestrator surgery deferred); operators have a clear expectation.



Passing `--tasks semgrep --no-context` still ran
`template-injection-detect`, `sharp-edges-detect`, `ssrf-detect`,
`prototype-pollution-detect`, `secrets-crypto-detect`,
`code-config-detect`, `supply-chain-detect`, `context-enricher`. Each
hit the LLM with the bogus key and emitted a 401 stack-trace per lens.
Either `--tasks` should hard-restrict to the listed ids, or the help
text should call out that downstream/auto-included tasks still fire.

### 🟠 #4 — Semgrep crashes hard when registry is unreachable
**(FIXED — `60a2134`)** — exit-7 from semgrep now appends a multi-line
hint with the exact `git clone semgrep-rules` + project-config
override that unblocks sandboxed environments.



Default `taskConfig.semgrep.configFlag` is
`["auto", "p/security-audit", "p/owasp-top-ten", "p/cwe-top-25"]` — all
require `semgrep.dev`. In our sandbox that host returns **403** and
semgrep exits **7** (`SemgrepError: invalid configuration file found`).
Kuzushi swallows the failure as `Task "semgrep" failed: semgrep failed
(exit 7)` with no actionable hint. Workaround: clone
`github.com/semgrep/semgrep-rules` and override
`taskConfig.semgrep.configFlag` to local paths.
**Suggestion:** ship a fallback bundled ruleset, or detect the exit-7
"registry unreachable" case and surface a `--bundled-rules`
recommendation.

### 🟡 #5 — `pip install --user semgrep` ships a broken binary

Out-of-the-box `pip install --user semgrep` produced a binary that
crashes with `ModuleNotFoundError: No module named '_cffi_backend'`
because `cffi` wasn't pulled in correctly. `pip install --user
--force-reinstall cffi` fixes it. Not kuzushi's bug, but `kuzushi
doctor` could detect "semgrep on PATH but `semgrep --version` exits
non-zero" and recommend the fix.

### 🟡 #6 — `kuzushi scan . --list-modules` says "0 modules" on
single-root repos
**(FIXED — `1646fea`)** — single-root case now prints the explicit
"no monorepo modules detected — looks like a single-root project"
hint with the right command to run instead.


Sentry has both `pyproject.toml` and `package.json` at the root. Kuzushi
correctly treats it as single-root, but `--list-modules` then prints
"Discovered 0 module(s). No modules matched the current filter." That
reads like an error. A "Single-root scan — no module discovery
performed" line would be clearer.

---

## Runtime

### 🔴 #8 — `kuzushi shell` hard-fails when CodeQL binary is absent

The shell's startup loads the `codeql` module via `createCodeqlModule()`,
whose `init()` calls `resolveCodeQLBinary()` which throws
`Failed to load module "codeql": CodeQL CLI not found.` That kills the
**entire shell process** before the catalog can render. Doctor reports
codeql as `[skipped] ... not enabled in this config`, so the two
disagree about whether codeql is required. Operators without CodeQL
installed (the common case for a quick local triage) can't open the
shell at all.

**Workaround / fix:** patched `src/scanners/codeql.ts` locally to make
`init()` tolerate a missing binary — caches `unavailableReason` and
defers the throw to `scan()`. Shell now opens normally; only attempts
to actually run `codeql:scan` fail with the clear error. Will commit
alongside the OAuth resolver (or as a separate `fix(codeql): tolerate
missing binary at module init` commit). Open follow-up: catalog should
visually mark codeql as "unavailable" with the install hint instead of
showing it identical to a never-run module.

### 🟠 #9 — `tmux send-keys` doesn't reach the shell's Ink input

Inside the running shell, `tmux send-keys -t kz-sentry:0.0 "/use sast"
Enter` (and even single characters like `tmux send-keys "x"`) does not
register: the `kuzushi>` prompt stays empty. Either Ink's raw-mode
input is rejecting keys delivered via tmux's command channel, or the
shell is reading from a different fd than expected. This blocks any
form of automated/scripted shell flow — operators can only drive the
shell from a directly-attached terminal.

### 🟡 #10 — `kuzushi config get` rejects `--repo`

`config get key` reads only global config; there's no documented way to
print the *effective* (global + project + project-overrides) view from
the CLI without writing a temp script. Doctor and other commands accept
`--repo`; `config` should too.

### 🟠 #11 — Project `taskConfig.semgrep.configFlag` IS honored — but
the scan-process lifecycle is fragile

Update: `--trust-repo-config` does pass the override through, and the
spawned semgrep gets all four local config dirs (verified via
`pgrep`). The earlier "completed · no findings · $0.00s" was a
**different bug**: the scan was being terminated before semgrep could
produce a single finding. Repros included:

- **`tee` in the pipeline → SIGPIPE → orphaned semgrep**, see #13
- **Two concurrent `kuzushi scan` runs against the same DB** racing
  on `findings.sqlite3`. No mutex, no warning.
- **SIGTERM not propagated**: when the parent node died, `pysemgrep`
  and `semgrep-core` kept running unattached, holding CPU and writing
  partial state into `/tmp`.

### 🟠 #12 — `kuzushi scan` doesn't reap its semgrep subprocesses
**(FIXED — `9723486`)** — semgrep is now spawned `detached: true` and
the whole process group is signaled on parent exit/abort.



After killing the parent `node` (or after a SIGPIPE), `pysemgrep` /
`semgrep-core` keep running detached. Need a clean shutdown path that
forwards SIGTERM to all scanner child PGRPs (similar to the
"detached:true / setsid" comment block in `src/agent-runtime/claude.ts`
for Claude subprocesses).

### 🟠 #13 — `kuzushi scan ... | tee` dies silently

Wrapping the scan in `tee scan.log` (a natural shell idiom) appears to
let the scan exit prematurely with code 0 once tee closes its read
side. Should test with `2>&1 | tee` vs `--audit-log` only — but either
way, the scan command shouldn't die quiet on SIGPIPE; should drain or
at least exit non-zero.

### 🟠 #14 — No "scan is alive" pulse in `--ci` mode
**(FIXED — `baac119`)** — heartbeat fires at 60s of silence in
scanning/triaging/verifying phases. Disable with
`heartbeatSeconds: 0`.



Once `phase: idle → scanning` prints, `--ci` goes silent for the
entire scan duration (which on Sentry is many minutes). Operators have
no way to know if it's:
  - actually running (semgrep crunching files),
  - hung,
  - silently exited (#7).

Even a once-per-30s heartbeat (`stage: scan → progress (12345 files,
N findings)`) would fix this. Right now `--ci` looks identical between
"working hard" and "dead".

### 🔴 #16 — Findings stranded in `pipeline_runs.findings_json` because
triage failed
**(FIXED — `ee4c1c0`)** — `KUZUSHI_PERSIST_RAW_FINDINGS=1` opts into
pre-persisting raw scanner findings to the `findings` table with a
`needs_review` placeholder. Real triage results overwrite via
ON CONFLICT DO UPDATE.


Run `1b6326b3` produced **27,375 semgrep findings** (118 ERROR-tier,
including 2 real SSRF and 1 raw-SQL injection in Sentry source). They
were correctly serialized into
`pipeline_runs.findings_json` (~20 MB). But the `findings` table —
the one that `kuzushi shell /findings`, the SARIF/JSON exporters,
and the dedup/scoring pipeline read from — was **empty**. Reason: the
triage stage hit issue #15 (Claude SDK exits 1) and the scan got stuck
retrying triage forever, so the post-triage "promote findings into the
findings table" step never ran.

Concrete impact: the operator-facing UX showed "0 findings, $0.00"
even though the underlying SQLite blob had a 20 MB findings catalogue
ready to read. Workaround: query the JSON blob directly (see
`FINDINGS_HIGHLIGHTS.md`). Long-term fix: persist findings into the
`findings` table at *scan stage end*, not after triage. Triage failure
shouldn't lose the raw scanner output.

### 🟠 #18 — Stderr from spawned Claude SDK subprocesses is invisible
unless `KUZUSHI_ABORT_DEBUG=1`
**(FIXED — `272dff8`)** — `createTrackedSpawn` buffers an 8 KB stderr
tail and replays it on any non-zero exit / non-null signal.



`createTrackedSpawn` in `src/agent-runtime/claude.ts:115` listens for
`stderr` data on every Claude subprocess but only forwards it to the
parent process when `KUZUSHI_ABORT_DEBUG=1` is set. That meant the
real cause of #15 — claude printing
`--dangerously-skip-permissions cannot be used with root/sudo
privileges for security reasons` — was hidden for an entire
debugging session. The orchestrator only saw "exit code 1" and shouted
that 498 times. Should at least surface the stderr on the *first*
failure of a given task, or buffer the last 1-2 KB and include it in
the orchestrator's `Task "X" failed: ...` message.

### 🟠 #19 — Stdin-piped commands kill the shell on EOF

Driving the shell with `printf "/use sast\nscan\n" | kuzushi shell ...`
causes the shell to exit ~immediately after the first command — when
stdin closes, Ink interprets it as a quit signal even though more
work was queued. Wrapping the input as `(printf ...; sleep 50) | …`
keeps it alive but isn't a real fix. Either the shell should treat
non-TTY stdin as a one-shot batch (read all input, run all commands,
then exit cleanly with a summary) or it should not exit on EOF until
in-flight work finishes.

### 🔴 #20 — OAuth-in-env path is ~12× more expensive than not setting it
**(FIXED — `68ac262`)** — `isClaudeCodeHostManagedAuth()` detects
host-managed sessions (via `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST` /
`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`) and skips env priming so
the spawned `claude` CLI inherits the host's shared cache.



When `ANTHROPIC_API_KEY=$(cat /home/claude/.claude/remote/.oauth_token)`
is set, the Claude CLI subprocess reports `apiKeySource:
"ANTHROPIC_API_KEY"` and treats every spawn as a fresh session: my
"say only ok" smoke test charged **$0.063** (16,675 cache *creation*
tokens). With the env var unset (claude CLI uses host-managed auth),
the same prompt charged **$0.005** (16,675 cache *read* tokens). 12×
cost differential just from `unset ANTHROPIC_API_KEY`. The OAuth
ambient resolver shipped in `bdc15e6` defaults to setting the env var,
so kuzushi-on-Claude-Code pays for cache misses on every spawn. Should
detect host-managed auth (e.g. `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST`
env var) and skip the env priming when present.

### 🟠 #21 — `kuzushi shell --load` is additive only; no `--exclude`
**(FIXED — `1646fea`)** — new `kuzushi shell --exclude codeql,...`
flag drops listed built-in modules from the default load via
`CopilotCoreOptions.excludeBuiltinModules`.



`--load <modules>` adds modules to the default set, but there's no way
to *remove* a default module (e.g. when `codeql` is broken or
unavailable). #8's tolerant-init fix mitigates this, but the
underlying gap still exists for any module that legitimately can't
load in a given environment.

### 🟠 #22 — Catalog shows "completed · no findings · $0.0" even when
the run produced 27K findings
**(FIXED — `ee4c1c0`)** — same fix as #16; catalog reads from the
`findings` table which is now pre-populated when
`KUZUSHI_PERSIST_RAW_FINDINGS=1`.



After the 13-minute semgrep scan that wrote 27,375 findings into
`pipeline_runs.findings_json`, the catalog renders the sast / semgrep
modules as "completed · no findings · $0.00". Same root cause as #16
(triage failure leaves findings stranded), but the operator-facing
side effect — every module looks like it found nothing — is its own
UX bug worth flagging separately.

### 🟠 #24 — `threat-model-randori` (and any task that needs to Write
artifacts) silently degrades under root's `plan` permission mode
**(FIXED — `947391f`)** — `planModeAllowedDirectories()` whitelists
the scan target, `~/.kuzushi/{,plans,runs}`, `~/.claude/plans`,
`/home/claude/.claude/plans`, and `<cwd>/.kuzushi` via the SDK's
`additionalDirectories` option. randori, threat-hunt, and similar
artifact-producing tasks now read/write where the rest of the
pipeline expects.



The post-`c3b9bd2` plan-mode fallback unblocks the LLM call itself
but blocks the Read/Write paths randori uses for its artifacts:

```
[threat-model-randori] Phase 1 Write failed (1/3):
  Tool "Write" file_path "/root/.claude/plans/deep-riding-willow.md" escapes the Read sandbox
[threat-model-randori] Phase 2 (S4) Read failed (1/3):
  Tool "Read" file_path "/root/.kuzushi/runs/<runId>/..." [restricted]
```

Randori retries 3x then moves on — degrades gracefully but produces a
much weaker threat model than on a non-root host. Two follow-ups:
  (a) the SDK's `additionalDirectories` option could be set to include
      the run dir + `~/.kuzushi/plans/` so plan-mode reads/writes there
      are allowed;
  (b) tasks that fundamentally need to write artifacts (randori,
      threat-hunt, systems-hunt context dumps) should declare that
      requirement and either escalate or warn the operator instead of
      silently retrying-then-skipping.

### 🟠 #23 — `--max N` semantics ambiguous
**(DOC FIXED — `1646fea`)** — help text now reads:
"Cap for the triage stage: at most <n> findings reach the triage
agent. Scanner-stage emits all raw findings; pre-triage dedup may
also drop more."



The flag is documented as "Max findings to triage" but in practice on
this scan it appeared to also cap how many lenses each detector
runs (the runs that hit `--max 5` produced ≤ 5 raw lens results, not
just 5 triaged findings). The CLI help and the actual behavior should
match — and probably want separate flags for "max raw findings" vs
"max triaged" vs "max lens iterations".

### 🟠 #17 — `--audit-log` doesn't actually write `scan.jsonl`
**(CASCADE OF #15)** — `registerScanEventLog` listens for
`scan:agent-activity` events. Pre-#15 those events never fired
because every detector died before tool-use. With #15 fixed, scan.jsonl
populates naturally.



With `--audit-log` set, the run dir got `run.json` and (later)
`threat-model.json` — but no `scan.jsonl`, no `triage.jsonl`, no
`verify.jsonl`. Per the README and CLAUDE.md these are the canonical
operator surfaces for "what happened during this run". They're empty
even though the orchestrator emitted plenty of warnings/errors that
should have been captured.

### 🔴 #15a — Scan reports `summary $0.00` exit 0 even when 100% of
detectors failed
**(FIXED — `60a2134`)** — exit code is now 1 when
`stats.failedTasks.length > 0`. Override with
`KUZUSHI_TOLERATE_TASK_FAILURES=1` for partial-success runs.

### 🟠 #15b — `prototype-pollution-detect` "Invalid JSON output" wrap
**(FIXED — `60a2134`)** — `parseJson()` now distinguishes empty,
truncated, and malformed outputs and points operators at the upstream
"subprocess exit" log line as the actual cause.

### 🔴 #15 — Every agentic detector subprocess exits with code 1
**(FIXED — `c3b9bd2`)**

**Root cause:** the Claude Code CLI rejects
`--dangerously-skip-permissions` AND `--permission-mode bypassPermissions`
when the spawning process runs as root, and kuzushi's
`agent-runtime/claude.ts` hard-coded `allowDangerouslySkipPermissions:
true` plus a default permission mode of `bypassPermissions`. In every
container that runs as UID 0 (Docker base images, Claude Code remote
sandboxes, GitHub Actions), every LLM call therefore failed with exit
1 and `--dangerously-skip-permissions cannot be used with root/sudo
privileges for security reasons` (which kuzushi only printed when
`KUZUSHI_ABORT_DEBUG=1` — itself a discoverability problem).

**Fix:** detect root via `process.geteuid() === 0`, skip the
`allowDangerouslySkipPermissions` flag, and downgrade the default
permission mode to `plan`. Operators on non-root hosts get the
historical behavior; root operators trade Bash/Edit/Write tool access
for a working agentic stack. `KUZUSHI_DANGEROUSLY_SKIP_PERMISSIONS=1`
forces the old behavior when an operator knows they need it.

**Verified end-to-end:** post-patch the
`agentic-sast,threat-hunt,systems-hunt` scan against Sentry runs with
zero `Claude SDK query failed` errors — versus 498 errors in the
single 13-minute pre-patch run.



`--tasks agentic-sast` (or `threat-hunt`) reliably emits a wall of:

```
[claude-runtime] [error] Claude SDK query failed (1655ms): Claude Code process exited with code 1
[template-injection] [error] [template-injection]/renderer-config lens error: ... Claude Code process exited with code 1
[sharp-edges-detect] [error] [sharp-edges-detect]/lazy-developer lens error: ... Claude Code process exited with code 1
[ssrf-detect] [error] [ssrf-detect]/local-sink lens error: ... Claude Code process exited with code 1
[orchestrator] [warn] Task "prototype-pollution-detect" failed: [prototype-pollution] Invalid JSON output: Unexpected end of JSON input
[2026-04-28T03:29:52.385Z] stage: scan → done (0 findings · deduplicating and ranking) [47.6s]
[2026-04-28T03:30:41.373Z] summary: $0.00 · 48.0s
```

…and the scan reports `summary: $0.00 · 48s`, exit 0 — i.e. **the
scan claims success despite every detector failing**. Confirmed in
both env-states: `ANTHROPIC_API_KEY=<oauth-token>` set AND unset.
Direct invocations of both the system `claude` binary AND the SDK's
own bundled `cli.js` succeed (`apiKeySource: ANTHROPIC_API_KEY`,
returns `"ok"`, exit 0). So the problem is in *how kuzushi's
`agent-runtime/claude.ts` constructs the `claudeQuery({prompt,
options})` call*, not in the auth path. Suspect candidates:

  - `outputFormat: { type: "json_schema", schema }` — the SDK's
    structured-output enforcer may be rejecting some lens schemas;
  - `tools` / `disallowedTools` — restricted lists may reference
    tool names that don't exist in the SDK's bundled `cli.js`
    (claude-code-version 2.1.87 vs system 2.1.121);
  - `allowDangerouslySkipPermissions: true` + `permissionMode` combo;
  - the SDK swallows subprocess stderr — kuzushi only sees the exit
    code, never the actual claude error message. **That alone is a
    serious diagnosability issue.**

**Cascade #15a — silent success despite total task failure.** When
every agentic detector errors, the orchestrator still reports a clean
"summary: $0.00 · Ns" with exit 0. Quality-gate / CI consumers will
treat this as a green run when in reality nothing was scanned. Should
exit non-zero when ≥ N% of tasks hit `Failed` state.

**Cascade #15b — `prototype-pollution-detect` JSON parse error.** A
distinct symptom of the same underlying issue — when claude exits 1
mid-stream, the JSON parser sees `Unexpected end of JSON input` and
the orchestrator logs it as a separate kind of failure. Should be
unified under "lens subprocess died."

### 🔴 #7 — Scan exits silently after `phase: idle → scanning`

After launching the post-OAuth-fix scan inside tmux, pane 0 prints:

```
[2026-04-28T03:04:25.531Z] scan: sentry started
[2026-04-28T03:04:25.532Z] phase: (init) → idle
[2026-04-28T03:04:25.532Z] stage: scan → active (...)
[2026-04-28T03:04:25.626Z] phase: idle → scanning
```

…and then the process exits **with exit 0** in well under a minute, no
error, no traceback, no `stage: scan → done`, no summary. `run.json`
exists in the run dir but `scan.jsonl`, `triage.jsonl`, the SARIF/JSON
report files, and `summary.json` are all absent. Reproduced in
foreground (no tmux, no tee) — same outcome. This is independently
serious: a scan that claims success and produces no artefacts is a
silent-data-loss class bug. Suspect the agentic detector graph crashes
during init in this restricted environment but the orchestrator treats
the failure as "all tasks done, 0 findings."

