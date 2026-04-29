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
`additionalDirectories` option. randori, carlini-threat-hunt, and similar
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
      carlini-threat-hunt, systems-hunt context dumps) should declare that
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
`agentic-sast,carlini-threat-hunt,systems-hunt` scan against Sentry runs with
zero `Claude SDK query failed` errors — versus 498 errors in the
single 13-minute pre-patch run.



`--tasks agentic-sast` (or `carlini-threat-hunt`) reliably emits a wall of:

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

---

## Issues observed during the post-fix run (5-task agentic scan, 1h 34m)

These are NEW issues that surfaced after the OAuth + permission-mode +
plan-mode patches landed and the scan actually started doing real work.
Most are about long-run reliability and operator visibility — none of
them existed in earlier runs because earlier runs died too fast to
exercise these code paths.

### 🔴 #25 — Scan exits silently with no exit code, summary, or error

The fix-enabled 5-task run lived 1h 34m, emitted 94 heartbeats, then
**vanished** — no `pipeline:error`, no `summary:` line, no `exit:`
line, no SARIF/JSON written. SQLite `pipeline_runs.status` still
shows `triaging` because completion was never recorded. Likely
unhandled rejection in the triage path or OOM-killed by the kernel,
but kuzushi can't tell us which. Should install a
`process.on('SIGTERM')` + `process.on('beforeExit')` that writes a
final `pipeline:abort` event with whatever partial state is in
memory before the process tears down.

### 🔴 #26 — Triage stage makes zero observable progress

After SQLite flipped to `status: 'triaging'`, all 27,440 findings sat
on `verdict='needs_review'` for 30+ minutes — no flips to `tp`/`fp`,
no `triage:result` events landing in the store, no per-finding
`finding:` lines in the `--ci` stream. The orchestrator clearly
*thinks* it's triaging (the status update fired) but no findings
ever got promoted out of placeholder. Either the LLM call is
silently 429'd, deadlocked on a semaphore, or the
`upsertQueue.flush()` on `triage:complete` never fires. Operators
need a `triage: progress N/M flushed` heartbeat or a
`triage: stalled — last event Xs ago` warning.

### 🟠 #27 — `--ci` heartbeat caption is stale across phase transitions

Heartbeat kept printing `heartbeat: scanning alive · idle 60s (scan)`
for 30+ minutes after `pipeline_runs.status` had already moved to
`triaging`. The CI stream reads `state.phase` from the UIStore and
the UIStore phase never advances when the orchestrator transitions
internally — the visible `phase: idle → scanning` event is the only
time `phase` is updated. Need orchestrator → UIStore phase syncs at
each stage boundary so the heartbeat caption matches reality.

### 🟠 #28 — Every triage attempt logs "Batch API failed, falling back
to sequential" warning under OAuth

```
[batch-fallback] [warn] Batch API failed, falling back to sequential:
  Batch API requires an API key — not available in OAuth mode
```

`agent-runtime/claude.ts:391-395` already throws this synchronously,
so the orchestrator could detect OAuth-mode at session-init and skip
the Batch path silently. As-is the warning fires *per triage batch*,
adding noise to every long-running OAuth scan.

### 🔴 #29 — `additionalDirectories` fix (`947391f`) is incomplete

After the fix, randori still complained:
```
[threat-model-randori] Phase 2 (S4) Write failed (1/3):
  Tool "Write" file_path "/root/.claude/plans/starry-stargazing-map.md"
  escapes the Read sandbox
```

`/root/.claude/plans` should have been whitelisted via the
`os.homedir() = /root` + `.claude/plans` join. Likely cause: the SDK
requires whitelisted dirs to *exist on disk*; an entry pointing at a
non-existent path is dropped. Fix: `mkdirSync(p, {recursive: true,
mode: 0o700})` for each whitelisted plans/runs dir before passing to
the SDK.

### 🟠 #30 — Randori passes a directory path to the `Read` tool

```
[threat-model-randori] Phase 1 Read failed (1/3):
  EISDIR: illegal operation on a directory, read '/root/bounty-targets/sentry'
```

Randori is calling `Read(target_root)` first thing in Phase 1 instead
of `Glob`/`LS`. The retry-3-then-skip masks the bug. Fix in the
randori prompt template: emit `Glob('**/*.py')` / `LS .` first, then
Read individual files.

### 🟠 #31 — Randori chokes on Sentry-sized files

```
[threat-model-randori] Phase 2 (S4) Read failed (1/3):
  File content (36668 tokens) exceeds maximum allowed tokens (25000).
  Use offset and limit parameters
```

The 25k-token Read cap is reasonable, but randori doesn't fall back
to chunked reads. Either the prompt should teach
`Read(file, offset=0, limit=20000)` then continue, or the runtime
should retry the failed Read with `limit: 20000` automatically.

### 🟠 #32 — Triage in OAuth mode is single-threaded

When Batch API is rejected (#28), kuzushi falls back to sequential
queries — *truly* sequential, one claude subprocess at a time. With
27,440 raw findings, even at 5s/triage that's 38 hours. Sequential is
required for cost-deterministic batches but the OAuth fallback should
parallelize K claude subprocesses (configurable, default 4) since
each one is its own session anyway.

### 🟠 #33 — Memory grows unbounded during long scans

Scan node RSS over the run: 130 MB at start → 190 MB at 18 min →
347 MB at 30 min → 405 MB at 1h. No findings were being added to the
in-memory queue (they're SQLite-backed); presumably the
`state.scanFindings` array holds all 27K and grows the agent context
per turn. Risk on smaller hosts; should swap
`state.scanFindings: Finding[]` for an iterator over the SQLite
findings table.

### 🟠 #34 — `--max <N>` is honored only at the triage gate, not the
scanner stage

Even with `--max 5`, scanners produced 27,440 raw findings. The flag
caps how many findings reach the triage agent, but every detector
runs to completion. Doc fix in `1646fea` covers the wording, but
operators frequently want a "stop scanning after N total findings"
flag. Add `--max-raw-findings <N>` that aborts running detectors
once the threshold is hit.

### 🔴 #35 — No incremental report writing

`--sarif` / `--json` / `--jsonl` only land on `pipeline:complete`. If
the scan dies before that — silent exit (#25), Ctrl+C, OOM — none of
the export flags produce any artefact, even though findings are
already in SQLite. The export workers should subscribe to
`stage:complete` and write incremental partial reports
(`out.partial.sarif` etc.) so a killed scan still leaves something
on disk. (Mitigation: I shipped a manual SQLite → JSON exporter for
this run, but that's a workaround — `findings-bounty.json` and
`FINDINGS_AGENTIC.md` were generated from raw SQL, not the report
worker.)

### 🟠 #36 — No "resume triage only" mode

If triage dies (#26), there's no command to drive triage against just
the `needs_review` rows already in SQLite. `--resume` resumes from
checkpoints that may not have been written. Add
`kuzushi triage --run-id <id>` that runs the triage stage against
existing findings. Equivalent need for `kuzushi report --run-id <id>`
to regenerate exports without re-scanning.

### 🟠 #37 — Stage transitions go quiet after the first one

`stage:` lines in `--ci`: only `stage: scan → active`,
`stage: triage → pending`, `stage: report → pending`. Never
`stage: scan → done` or `stage: triage → active`. Either the
orchestrator stops emitting `stage:active`/`stage:done` events after
init, or the UIStore stage map only updates once. With long scans
this leaves operators blind to which stage is even running.

### 🟠 #38 — Rate-limit detection / backoff banner not visible

CLAUDE.md mentions a "rate-limit banner" wired to `state.throttle`
(Phase B.4). Across the 1h 34m run we hit 0 visible throttle banners
and 0 cost prints, despite almost certainly brushing API rate
limits (the 5-hour OAuth quota or per-minute concurrent-request
caps). Either the throttle detection isn't plumbed through the OAuth
path, or the banner only renders in Ink mode (not `--ci`).

### 🟠 #39 — No progressive cost in `--ci` mode

The heartbeat doesn't include `$X.XX so far`; the `summary:` line is
the first cost an operator ever sees. For 1h+ runs that's painful —
no way to abort early when you see costs spike. Plumb
`state.runningCostUsd` into the heartbeat formatter.

### 🟠 #40 — `kuzushi scan` lacks `--exclude` (`1646fea` only added
shell)

The `--exclude codeql` flag I shipped only applies to `kuzushi
shell`. `kuzushi scan` should accept the same flag for symmetry —
operators in environments missing a binary need it on both surfaces.
Currently scan-mode lights up the codeql failure even with the
tolerant init from `2e8a3b8`.

### 🟡 #41 — Heartbeat fires from a `setInterval` that doesn't survive
process death gracefully

The heartbeat timer is `.unref()`'d, so it won't block exit. But the
heartbeat *cadence* during the silent exit (#25) showed the timer
kept firing right up to the moment the process vanished — meaning
there was no shutdown drain that could have surfaced the impending
crash. Even a 1-line "preparing exit / X findings buffered" before
process tear-down would help operators tell graceful-quit apart from
crash.

### 🟢 What worked surprisingly well

For balance — these previously-broken behaviors held up after the
patches:
  - **OAuth auto-discovery** (`bdc15e6`) — `kuzushi doctor` now
    reports `inherited OAuth (file:/home/claude/.claude/remote/.oauth_token)`.
    Zero auth issues across the run.
  - **Root-safe permission mode** (`c3b9bd2`) — 0 SDK errors during
    1h 34m of agentic work, vs 498 errors per scan pre-patch.
  - **Raw-finding pre-persist** (`ee4c1c0`) — survived the silent
    exit. Without this, all 27,440 findings would have been lost.
  - **`--ci` heartbeat** (`baac119`) — 94 heartbeats fired
    correctly; gave us proof of life across 1.5 hours.
  - **codeql tolerant init** (`2e8a3b8`) — the missing codeql binary
    no longer takes down the shell startup.

---

## Round 2 fix log (#25-#58)

After the field-test surfaced #25-#58, the user requested all of
them be fixed. Below is the closing tag for each. Architectural
items genuinely needing their own design pass are tagged
**DEFERRED** with a one-paragraph design sketch.

### Tier 1 — quick wins (5 commits)

| # | Title | Commit |
| - | ----- | ------ |
| 27 | Stale heartbeat caption | `0e9f391` |
| 37 | Stage transitions silence | `0e9f391` |
| 39 / 45 | Heartbeat finding count + cost | `0e9f391` |
| 40 | `kuzushi scan --exclude` | `691103b` |
| 49 | `kuzushi scan --inherit-claude` | `691103b` |
| 55 | `--target` validation | `691103b` |
| 56 | `scripts/kuzushi-dev` shim | `691103b` |
| 42 | `KUZUSHI_PERSIST_RAW_FINDINGS` default-on | `bfc88a9` |
| 28 | Silent batch-API early-out under OAuth | `faa8f99` |
| 47 | Triage retry final-failure log line | `faa8f99` |
| 30 / 31 | Randori prompt: Glob/LS first + chunked Read | `86d0034` |

### Tier 4 — CI hygiene (1 commit)

| # | Title | Commit |
| - | ----- | ------ |
| 52 | `.github/workflows/secret-scan.yml` | `d558d5e` |
| 58 | `kuzushi scan --show-plan` | `d558d5e` |

### Tier 2 — medium fixes

| # | Title | Commit |
| - | ----- | ------ |
| 25 | `summary.partial.json` on abort | `bf26f73` |
| 41 | Shutdown-drain heartbeat line | `bf26f73` |
| 29 | `additionalDirectories` mkdir-before-pass | `2c077c9` |
| 38 | Rate-limit / throttle line in `--ci` | `2c077c9` |
| 53 | Pre-commit `pnpm codegen:check` | `2c077c9` |
| 43 | `kuzushi inspect` subcommand | `54a3c8f` |
| 34 | `--max-raw-findings <N>` soft cap | `f793580` |
| 50 | `kuzushi triage <run-id>` (partial #36/#48) | `181ac70` |
| 35 | `<jsonOutput>.partial` on triage:complete | `506f076` |
| 26 / 46 | Triage progress + ETA in heartbeat | `8b2eb50` |

### Tier 3 — architectural (2 shipped, 3 deferred)

| # | Title | Status |
| - | ----- | ------ |
| 44 | Schema migration: `branch` + `pr_number` columns | `1144a09` |
| 51 | `--diff-base <ref>` for general detectors | `01a44fb` |
| 36 / 48 | `kuzushi report --run-id`, `kuzushi verify --run-id` | partial via `181ac70`; full version DEFERRED |
| 57 | `scripts/sync-pr-description.sh` | `f793580` |

### DEFERRED — architectural follow-ups

These three are genuinely big enough to warrant their own design
discussions and PRs. Sketched here so the work is unblocked when
someone picks them up.

#### #32 — Parallelize triage subprocesses under OAuth

Today the OAuth fallback path (`agent-runtime/execution.ts:386`)
runs requests strictly sequentially. With 27,440 raw findings and
~5s/finding LLM latency that's 38 hours.

**Sketch:** add `--triage-concurrency <N>` (default 4) that
forks N concurrent `claude` subprocess sessions in OAuth mode. Each
subprocess is its own Claude Code session anyway; correctness
constraint is that they share neither tool state nor working dir,
which is already true in the spawn shape we use. Cost guard: each
subprocess is independently rate-limited by the Anthropic API, so N
parallel sessions don't bypass the limit, they just keep more of
the budget hot. Implementation lands mostly in
`runStructuredAgentBatch()` and the dispatcher's
`waitForCapacity()`.

#### #33 — SQLite-backed iterator for `state.scanFindings`

The orchestrator holds `state.scanFindings: Finding[]` in memory
the entire run. Sentry-sized agentic runs grew from 130 MB → 405 MB
across 1h. Findings are ALSO already in SQLite (the
`pipeline_runs.findings_json` blob and, post-`bfc88a9`, the
`findings` table itself).

**Sketch:** introduce a `FindingCursor` interface that wraps a
prepared SELECT and exposes `next()` / `close()` semantics.
Replace `state.scanFindings.push(...)` with cursor inserts; replace
`state.scanFindings[i]` reads with cursor seeks. The
`run:findings-checkpoint` event becomes a no-op (data is already
durable). Bigger blast radius — every place that touches
`state.scanFindings` needs migration — so warrants its own PR with
careful test coverage of the orchestrator state machine.

#### #54 — e2e harness `triage:assertions` foreign-key bug

Per the comment in `.github/workflows/ci.yml`, the e2e job is
`continue-on-error: true` because of a known FK violation:
`pipeline_runs` row not present when the assertion worker fires.
Tracked as tech debt.

**Sketch:** fix the harness sequence so `pipeline_runs.runId` is
inserted before any `triage:assertions` event publishes. The
ordering currently depends on a race between `pipeline:start`'s
DB-write hook and the worker's first event read; pinning the
write to a synchronous `INSERT ... RETURNING` and gating the worker
subscriptions on its completion would close the gap. Once green,
flip `continue-on-error` off so the job actually blocks merges.
