# Kuzushi authentication and recovery systemic audit

Date: 2026-08-21

Baseline: `a3b0193e69` plus the uncommitted OpenAI OAuth recovery fix in this
working tree

Trigger: an `openai:*` model reached Setup with only an API-key choice even
though Kuzushi already had a reusable OpenAI OAuth connection under the
OAuth-backed OpenAI transport namespace.

Scope: model/provider parsing, credential-method selection, OAuth store
resolution and refreshability, runtime preflight, scan/run/shell parity, TUI
recovery and continuation, `doctor`, `auth ping`, bridge request construction,
login-process settlement, user-facing recovery instructions, and regression
guardrails.

Audience: Kuzushi runtime/auth owners, CLI owners, and TUI application owners.

## Executive verdict

The reported Start Map flow is fixed, but codebase-wide recurrence
prevention is **NOT SOLVED**.

The current patch correctly distinguishes `openai:*` API-key models from
OAuth-backed OpenAI models, offers an explicit OAuth model switch, reuses a
refreshable stored connection, and preserves a paused Scan plan. Targeted
regressions cover stored-connection retarget/resume, a new login resuming the
exact committed plan, step-scoped model binding, stale-model refusal, API-key
effect ordering, and rejected-OAuth replacement at
`crates/kuzushi-tui/src/app/tests.rs:20594-21238`.

The wider auth contract is still duplicated across the Rust runtime, TUI
Setup, TUI health/auth views, CLI `doctor`, CLI `auth ping`, and the Node
bridge. Those copies already disagree. The most serious result is a P0 in
`auth ping`: a provider/model/config mismatch can forward the value of
`OPENAI_API_KEY` as the API key for an Anthropic request. Other paths can
declare OAuth ready while runtime rejects it, flatten typed authentication
failures into generic strings, reuse credentials that a provider just
rejected, certify the wrong credential, or recommend a CLI command that does
not exist.

The durable fix is not another picker branch. Kuzushi needs one typed,
provider-bound authentication contract used by every execution and diagnostic
surface, plus a cross-mode conformance matrix that makes divergence a failing
test.

## Method

Review was partitioned into three file-disjoint lenses, followed by director
spot-checking of every promoted citation:

1. **Lens A, provider/model/auth transport.** Scope:
   `crates/kuzushi-core/src/config/**`, `crates/kuzushi-core/src/runtime/**`,
   `crates/kuzushi-core/src/modules/runtime_requirements.rs`,
   `crates/kuzushi-openai/src/**`, `crates/kuzushi-cli/src/**`, and the
   LangGraph model/login bridge plus `scripts/check-public-identity.mjs`.
   Anti-scope: `crates/kuzushi-tui/**`.
2. **Lens B, recovery state machine.** Scope:
   `crates/kuzushi-tui/src/app/{workers,tool_runner,jobs,background_events}/**`
   plus `app/onboarding/runner.rs`, `app/state_transitions/picker_keys.rs`,
   `app/effects.rs`, `app/view_state/engagement.rs`,
   `app/settings/handle_model_command/auth_login.rs`,
   `app/settings/handle_model_command/model_command/application.rs`,
   `app/settings/normalize_thinking_level/auth_process.rs`, and
   `app/session_state.rs` plus `app/scan/start_scan/**`. Anti-scope: shared
   runtime readiness and renderer/presentation code.
3. **Lens C, readiness and presentation truth.** Scope:
   `crates/kuzushi-tui/src/app/settings/normalize_thinking_level/oauth_status.rs`,
   `app/shell_lifecycle/onboarding_open.rs`, `app/onboarding/auth_rows.rs`,
   `app/settings/auth_provider.rs`, `app/settings/model_choices.rs`,
   `crates/kuzushi-tui/src/ui_view_models/**`,
   `crates/kuzushi-tui/src/renderer/**`, `boundary_lints.rs`,
   `scripts/check-env-discipline.mjs`, and
   `scripts/artifact-manifest-contract.mjs`. Anti-scope: worker execution and
   shared runtime.

Searches covered provider/model aliases, credential env reads, OAuth path
resolvers, expiry/refresh handling, bridge envelopes, child exit status,
runtime failure metadata, all TUI job event families, recovery copy, and the
tests adjacent to those surfaces.

### Severity rubric

- **P0:** a feasible path can disclose a credential across a provider trust
  boundary. Likelihood does not lower a cross-provider secret disclosure.
- **P1:** a supported execution path can use the wrong credential method,
  reject a valid method, reuse a provider-rejected credential, lose required
  recovery identity, or give an unusable recovery action.
- **P2:** a current diagnostic or presentation surface materially contradicts
  execution without itself sending a credential or changing execution.
- **P3:** latent drift or audit-quality defects with no current execution
  failure.

## Findings

### P0: `auth ping` can forward a secret to the wrong provider

Lens: A, provider/model/auth transport.

**Evidence:**

- `crates/kuzushi-cli/src/adapters/auth_ping.rs:47-55` resolves the positional
  provider and the model independently, then constructs a bridge request.
- `crates/kuzushi-cli/src/adapters/auth_bridge.rs:15-30` reads the value of
  whatever `runtime.api_key_env` names and places it in the request as
  `apiKey`; it does not bind that value to the model provider first.
- `scripts/langgraph-bridge/model.mjs:25-29,49-54,99-103,121-128` prioritizes
  a non-empty request `apiKey` and constructs `ChatAnthropic` with that value.
- `scripts/langgraph-bridge.mjs:299-305` invokes the constructed model for the
  ping request, which is the network-send sink.
- `crates/kuzushi-core/src/runtime/policy/no_silent_fallback.rs:21-27,92-100`
  rejects that provider/env mismatch on the normal runtime path.

**Failure scenario:** an operator has the default
`runtime.api_key_env=OPENAI_API_KEY`, a real OpenAI key, valid Anthropic OAuth,
and runs `kuzushi auth ping anthropic --model anthropic:...`. The diagnostic
places the OpenAI key in an Anthropic model request. The normal runtime rejects
this provider/env mismatch, but `auth ping` bypasses that production safety
boundary.

**Required correction:** construct ping through the same typed runtime
preflight and credential resolver as scan/run. The provider argument must
either be derived from the model or fail when it does not match. Add a sentinel
secret test proving a credential can never cross a provider boundary.

### P1: valid Anthropic OAuth can be blocked by an unrelated API-key setting

Lens: director synthesis of A, provider/model/auth transport; B, model-picker
mutation; and C, Setup readiness.

**Evidence:**

- `crates/kuzushi-core/src/config/config_model.rs:301-312` defaults
  `runtime.api_key_env` to `OPENAI_API_KEY`.
- `crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:450-469` and
  `crates/kuzushi-tui/src/app/settings/handle_model_command/model_command/application.rs:55-76`
  change the model and thinking level, but not the credential binding.
- `crates/kuzushi-tui/src/ui_view_models/setup.rs:183-212` can truthfully mark
  the selected Anthropic model OAuth-ready.
- `crates/kuzushi-core/src/runtime/policy/no_silent_fallback.rs:21-27,92-100`
  requires the configured API-key env to match the model provider even when
  OAuth is the intended method.
- `crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs:286-301` calls
  that API-key binding before it checks stored Anthropic OAuth.

**Failure scenario:** from a default config, the operator selects an
`anthropic:*` model and completes OAuth. Setup reports OAuth ready, but runtime
preflight fails because `runtime.api_key_env` still names `OPENAI_API_KEY`.
The failure is a plain configuration error rather than typed authentication
metadata, so the recovery reducer cannot reliably recognize it.

**Required correction:** the resolved auth method must own its requirements.
An OAuth selection must not require an API-key env binding. Keep the
no-silent-provider-switch rule, but apply it only when the selected transport
is an API key.

### P1: a stale Anthropic API key can shadow a valid OAuth connection

Lens: director synthesis of A, provider/model/auth transport, and B, picker
recovery.

**Evidence:**

- `crates/kuzushi-openai/src/langgraph_runtime/bridge_payloads.rs:83-96`
  carries an API key and OAuth store information but no explicit selected auth
  method.
- `scripts/langgraph-bridge/model.mjs:99-103,127-128` chooses Anthropic OAuth
  only when no API key is present.
- The repaired picker explicitly clears the Anthropic API-key transport at
  `crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:752-776` and
  `crates/kuzushi-tui/src/app/settings/handle_model_command/auth_login.rs:151-175`.
- Direct shell login has no picker continuation and returns before that clear
  at `crates/kuzushi-tui/src/app/settings/handle_model_command/auth_login.rs:103-125`;
  startup also loads a non-empty configured env credential at
  `crates/kuzushi-openai/src/langgraph_runtime/runtime_config.rs:90-107`.

**Failure scenario:** outside the repaired picker continuation, such as direct
shell `auth login anthropic` or startup with an existing OAuth bag, an old or
rejected `ANTHROPIC_API_KEY` can remain present. Calls then prefer the stale
API key even though OAuth is usable. The picker exception proves transport
selection can be explicit, but that policy is not shared by all entry points.

**Required correction:** send an explicit transport choice in the bridge
envelope. OAuth selection must suppress API-key material; API-key selection
must not silently fall through to OAuth. Rejected credential identity must be
part of the retry contract.

### P1: typed authentication recovery exists for only one TUI event family

Lens: B, recovery state machine.

**Evidence:**

- `crates/kuzushi-tui/src/app/workers/background_tool_worker.rs:12-39`
  gives `ToolEvent` a dedicated `AuthenticationFailed` variant.
- The same file at `:43-51,143-167` gives Agent, Plan, and Threat failures only
  a `String`.
- `crates/kuzushi-tui/src/app/workers/parse_threat_patch_json.rs:17-30`
  converts scan errors to strings.
- `crates/kuzushi-tui/src/app/workers/tool_run_status.rs:47-56,1068-1081` and
  `crates/kuzushi-tui/src/app/workers/threat_regen_worker.rs:168-180` flatten
  agent, planner, and threat errors before UI reduction.
- `crates/kuzushi-tui/src/app/scan/start_scan/scan_failure_events.rs:4-24`
  applies scanner-specific generic remediation to every scan failure.
- `crates/kuzushi-tui/src/app/jobs/event.rs:82-106` treats all of these generic
  failures as terminal.

**Failure scenario:** stored OAuth passes local readiness but the provider
returns 401 during raw Scan, Ask, Plan, or threat regeneration. Provider,
model, rejected transport, and `RuntimeFailureClass::Authentication` are no
longer available when the event reaches the reducer, so the shared Setup/Auth
recovery and exact continuation cannot run.

**Required correction:** every model-backed worker must carry a typed failure
envelope containing failure metadata, model binding, provider, selected
transport, invocation identity, and resumable work. All event families should
enter one recovery reducer.

### P1: standalone tool failures can immediately reuse the rejected credential

Lens: B, recovery state machine.

**Evidence:**

- `crates/kuzushi-tui/src/app/tool_runner/run_tool/events_and_results.rs:470-505`
  creates a reconnect/replacement continuation only when the failed tool is a
  running planning step; standalone failures terminate without rejected
  credential identity.
- `crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:659-675,709-715`
  accepts an already-present API key or OAuth connection unless a pending
  continuation says replacement/reconnect is required.

**Failure scenario:** a direct model-backed tool receives 401 from an existing
API key or OAuth connection. The operator follows the instruction to update
credentials, selects the existing method, and Kuzushi reports it reusable,
causing the next retry to use the credential the provider just rejected.

**Required correction:** rejected credential revision belongs in shared auth
state, not only in a Scan-plan continuation. Any provider rejection must make
reuse impossible until the credential changes or a different explicit method
is selected.

### P1: `auth ping anthropic` ignores the default OAuth store

Lens: A, provider/model/auth transport.

**Evidence:**

- `crates/kuzushi-cli/src/adapters/auth_ping.rs:175-188` probes OAuth only when
  `runtime.anthropic_oauth` is explicitly present.
- `crates/kuzushi-openai/src/langgraph_runtime/runtime_config.rs:90-107`
  resolves the default OAuth config and store even when that optional config
  section is absent.

**Failure scenario:** shell login writes the default Anthropic OAuth bag while
`runtime.anthropic_oauth` remains unset. Scan/run can use it, but `auth ping
anthropic` reports the same credential missing.

**Required correction:** ping must consume the runtime's resolved auth state,
not infer whether the default applies from optional config presence.

### P1: `auth ping` can report success after bridge process failure

Lens: A, provider/model/auth transport.

**Evidence:** `crates/kuzushi-cli/src/adapters/auth_bridge.rs:55-59` parses and
returns stdout without checking `output.status.success()`.

**Failure scenario:** a bridge emits a valid `{"ok":true}` object and then
exits nonzero because cleanup, persistence, or a late transport step failed.
`auth ping` reports success despite failed process settlement.

**Required correction:** require both a valid success envelope and a zero child
exit status, and add the inverse-order settlement regression.

### P1: recovery errors recommend a CLI command that does not exist

Lens: A, provider/model/auth transport.

**Evidence:**

- `crates/kuzushi-cli/src/command/subcommands.rs:375-385` exposes only
  `kuzushi auth ping`; login is a shell command.
- `crates/kuzushi-cli/src/command.rs:230-235` correctly says to enter
  `kuzushi shell` and then run `auth login ...`.
- `crates/kuzushi-core/src/runtime/domain/failure.rs:8-9`,
  `crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs:321-330`, and
  `crates/kuzushi-cli/src/doctor/checks.rs:425-433` instead instruct operators
  to run `kuzushi auth login openai`.
- `scripts/check-public-identity.mjs:135-145` actively requires the invalid
  instruction.

**Failure scenario:** a headless scan/run or Doctor failure gives the operator
a concrete recovery command; Clap rejects it, so the documented recovery path
never reaches the existing shell OAuth flow.

**Required correction:** recovery instructions should be generated from
registered command metadata or tested by the real parser. A source check must
not freeze hand-written command text.

### P1: credential-question routing is neither provider-bound nor resumable

Lens: B, recovery state machine.

**Evidence:**

- `crates/kuzushi-tui/src/app/workers/tool_run_status.rs:605-635` returns an
  error tool result immediately after routing a credential question.
- `crates/kuzushi-tui/src/app/jobs/event.rs:27-30` retains only request and run
  IDs.
- `crates/kuzushi-tui/src/app/background_events/drain_background_events/runtime_event_drains.rs:722-740`
  opens auth through `reduce_auth_status`.
- `crates/kuzushi-tui/src/app/settings/handle_model_command/auth_login.rs:9-23`
  chooses the configured model's provider, not the credential provider the
  tool requested.

**Failure scenario:** an agent asks for a GitHub credential while the selected
model is OpenAI. Setup opens OpenAI auth, the tool call has already failed with
`CREDENTIALS_REQUIRED`, and a later GitHub login cannot resume it.

The system prompt tells agents not to request credentials at
`crates/kuzushi-tui/src/app/workers/tool_run_status.rs:86-89,973-978`, which
lowers likelihood but does not make the runtime contract safe.

**Required correction:** credential questions must carry a provider-bound
requirement and resumable tool-call identity, or be rejected without claiming
that Setup can resume them.

### P2: TUI Doctor can certify the wrong credential

Lens: C, readiness and presentation truth.

**Evidence:**

- `crates/kuzushi-tui/src/ui_view_models/health.rs:173-190` describes an
  OAuth-backed OpenAI model as using `OPENAI_API_KEY`.
- `crates/kuzushi-tui/src/ui_view_models/health.rs:201-239` converts typed
  `CredentialReadiness::Missing` to `None`, then allows a cached generic
  `checks.credential_set` bit to produce PASS.

**Failure scenario:** an OAuth-backed OpenAI model is selected, stored OAuth is missing,
and `OPENAI_API_KEY` is non-empty. Setup/runtime correctly require OAuth, while
Doctor reports `credentials PASS` and says to run tools normally.

**Required correction:** health views must render the canonical model-specific
auth resolution directly. Generic cached env presence must never override a
typed missing result.

### P2: CLI Doctor has an independent, divergent readiness implementation

Lens: A, provider/model/auth transport.

**Evidence:**

- `crates/kuzushi-cli/src/doctor/checks.rs:325-367` checks Anthropic API-key
  presence only and treats an empty/whitespace env value as set.
- `crates/kuzushi-cli/src/doctor/checks.rs:415-505` reimplements OpenAI OAuth
  parsing and hardcodes the home-default store instead of using the configured
  OAuth path.
- `crates/kuzushi-cli/src/adapters/auth_oauth.rs:94-99` likewise treats blank
  env values as present.

**Failure scenarios:** Doctor reports a working Anthropic OAuth setup missing,
reports a custom OpenAI OAuth store missing, or certifies a blank placeholder
that runtime rejects.

**Required correction:** delete local readiness parsers and render the shared
model-specific auth resolution, including the configured store path.

### P2: `/auth` can contradict Setup for a working OpenAI API-key model

Lens: C, readiness and presentation truth.

**Evidence:**

- `crates/kuzushi-tui/src/ui_view_models/auth.rs:38-44,98-140` puts API-key
  readiness in a generic `LangGraph` row while the public `openai` row reflects
  only OAuth-backed OpenAI readiness.
- `crates/kuzushi-tui/src/renderer/views/system/auth_provider_rows.rs:49-57`
  renders the latter as a red failure.

**Failure scenario:** `openai:gpt-5.5` has a valid `OPENAI_API_KEY` and no
OAuth. Setup says the selected model is ready, but `/auth` shows `openai
missing · oauth missing`.

**Required correction:** provider rows must show method-specific capability,
not collapse the OpenAI API and subscription transports into one ambiguous
provider label.

### P3: current source guardrails do not enforce auth conformance

Lens: C, readiness and presentation truth.

**Evidence:**

- `crates/kuzushi-tui/src/boundary_lints.rs:138-173` restricts the locations of
  direct env reads but does not require consumers to use model-specific typed
  readiness.
- `scripts/check-env-discipline.mjs:7-28` checks four selected implementation
  files and has no cross-surface readiness assertion.
- `scripts/artifact-manifest-contract.mjs:876-890,2132-2141` accepts OAuth path
  consumers based on helper-name tokens; it does not prove that login, status,
  Doctor, and runtime resolve the same effective store.

**Failure scenario:** a new status or health projection can let a generic env
bit override OAuth or can probe the default store instead of the configured
store. The current checks stay green, as demonstrated by the present TUI
Doctor and CLI Doctor contradictions.

**Required correction:** retain location lints, then add behavioral conformance
tests that feed one typed auth fixture through every consumer and compare the
result.

### P3: OAuth recovery consent depends on catalog order while copy is hardcoded

Lens: C, readiness and presentation truth.

**Evidence:**

- `crates/kuzushi-tui/src/app/settings/model_choices.rs:68-82` chooses the
  first catalog model whose provider matches the OAuth namespace.
- `crates/kuzushi-tui/src/renderer/views/onboarding/auth_method_picker.rs:373-407`
  hardcodes `openai-oauth:gpt-5.4` in the consent copy.

**Failure scenario:** a future model is inserted ahead of GPT-5.4 or the
catalog is reordered. The actual recovery target changes implicitly while the
UI still tells the operator that GPT-5.4 will be selected, violating explicit
model-switch consent.

**Required correction:** mark exactly one OAuth recovery target explicitly in
catalog metadata and derive both behavior and copy from that typed selection.

### P3: routed credential questions create duplicate transcript records

Lens: B, recovery state machine.

**Evidence:**

- `crates/kuzushi-tui/src/app/workers/tool_run_status.rs:615-624` sends
  `OperatorQuestionCompleted` before `CredentialQuestionRouted`.
- `crates/kuzushi-tui/src/app/background_events/drain_background_events/runtime_event_drains.rs:657-680`
  records an operator answer before discovering that no question card exists.
- The same file at `:743-758` records another credential question/answer pair.

**Failure scenario:** one rejected credential request leaves three transcript
records, confusing replay and audit consumers about what the operator
actually answered.

## Surface verdicts

### Lens verdicts

| Lens | Verdict | Highest-impact result |
| --- | --- | --- |
| A · provider/model/auth transport | FAIL | `auth ping` can cross-bind a secret to the wrong provider; Anthropic OAuth and diagnostics diverge from runtime. |
| B · recovery state machine | FAIL | Scan/Ask/Plan/Threat lose typed auth identity; standalone failures lose replacement state. |
| C · readiness and presentation truth | PARTIAL | The repaired Setup path is coherent, but TUI Doctor and `/auth` can contradict it and current lints permit the drift. |

### Surface details

| Surface | Verdict | Reason |
| --- | --- | --- |
| OpenAI API vs OAuth runtime namespace | PASS | `crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs:286-318` requires an API key for API-backed OpenAI models and stored OAuth for OAuth-backed OpenAI models. |
| OAuth store parsing/refreshability | PASS | `crates/kuzushi-tui/src/app/settings/normalize_thinking_level/oauth_status.rs:29-56,157-208` types readiness against the configured path. |
| OAuth login settlement | PASS | `crates/kuzushi-tui/src/app/settings/handle_model_command/auth_login.rs:398-485` requires child success, usable credentials, and replacement; `scripts/langgraph-bridge/model.mjs:306-313` writes atomically with mode `0600`. |
| TUI Setup / Start Map recovery | PASS for the reported OpenAI path | Targeted regressions at `crates/kuzushi-tui/src/app/tests.rs:20594-21238` cover explicit switch and exact continuation. |
| Anthropic method selection | FAIL | OAuth is coupled to API-key env configuration and can be shadowed by a stale key. |
| Standalone tool recovery | FAIL | Rejected credential identity and continuation are not preserved. |
| Scan / Ask / Plan / Threat recovery | FAIL | Typed auth failure metadata is flattened to strings. |
| CLI `auth ping` | FAIL | It bypasses provider binding, can cross-send a secret, and ignores child exit status. |
| CLI `doctor` | FAIL | Readiness and store path differ from runtime. |
| TUI Doctor and `/auth` | FAIL | They can certify or condemn the wrong method. |
| User-facing recovery commands | FAIL | Several errors name an unavailable direct-login command. |
| Current source guardrails | FAIL | They permit all of the present contradictions. |

## Immediate containment

Owner: CLI/runtime authentication boundary.

1. Prevent `auth ping` from constructing or sending any bridge envelope until
   the model provider, public provider argument, and resolved credential method
   agree.
2. Remove the positional provider/model independence, or fail mismatches before
   reading any secret value.
3. Add a fake-bridge sentinel test for every cross-provider pair and a
   success-JSON/nonzero-exit test.

These changes contain the P0 without waiting for the broader auth-domain
migration below.

## Top five structural fixes

1. **Create one typed `ModelAuthResolution` in shared Rust.** It should bind
   canonical model provider, accepted methods, explicitly selected method,
   API-key env when applicable, OAuth provider/store path, readiness,
   refreshability, and rejected credential revision. TUI, runtime, Doctor, and
   ping consume this value; they do not re-derive it.

2. **Route `auth ping` through the production runtime boundary.** Remove its
   custom secret-bearing envelope construction, require provider/model
   agreement, and require a successful child exit. Add a sentinel non-leak
   test for every provider pair.

3. **Carry typed failures and resumable work through every TUI worker.** Scan,
   standalone Tool, Ask, Plan, and Threat should all retain
   `RuntimeFailureMetadata`, exact model binding, selected transport, target,
   invocation input, and safe continuation. One reducer owns auth recovery.

4. **Make auth transport explicit and rejection-aware.** Selecting OAuth must
   suppress an API key for that attempt; selecting API key must be explicit;
   any 401 marks that credential revision unusable everywhere until it changes.

5. **Install a cross-mode auth conformance gate.** For each supported model
   family, run the same cases through runtime preflight, Setup, Doctor,
   `/auth`, `auth ping`, scan, run, and failure recovery. Fail CI on any
   readiness, method, path, recovery action, or command-text disagreement.

## Required regression matrix

The minimum matrix is the Cartesian product of these meaningful dimensions:

- model family: OpenAI API, OpenAI OAuth, `anthropic:*`, and
  `vertex-anthropic:*`;
- credential state: missing, blank, ready, invalid, expired-refreshable,
  expired-unrefreshable, provider-rejected, and multiple methods present;
- store: default path and configured custom path;
- entry point: Setup, Start Map, standalone tool, raw scan, Ask, Plan, Threat,
  `run`, `doctor`, and `auth ping`;
- settlement: bridge success, structured auth failure, malformed output,
  successful JSON with nonzero child exit, cancellation, and credential
  replacement.

Every row should assert:

1. the same ready/not-ready result on every applicable surface;
2. the same selected credential method reaches the bridge;
3. no credential value can reach a different provider;
4. rejected credentials cannot be reused;
5. interactive work resumes exactly once with the same target, model binding,
   input, and queue position;
6. headless work fails with a parser-valid recovery instruction and never
   silently switches provider, model, or transport.

## Guardrails needed

- Make direct OAuth parsing and credential env reads outside the shared auth
  adapter a source-check violation. Existing allowlists only police where
  `env::var` appears; they do not prove semantic agreement.
- Make worker failure events accept a typed failure envelope rather than a
  `String`, so dropping auth identity becomes a compile-time error.
- Generate diagnostic and recovery copy from typed auth resolution and command
  metadata. Test each emitted command with the real Clap/shell parser.
- Add an invariant that exactly one catalog entry is the explicit OAuth
  recovery target per namespace, with renderer copy derived from it.
- Add black-box parity tests using a fake bridge that records only credential
  source metadata and sentinel hashes, never real secrets.
- Keep the existing no-silent-fallback check, but extend it to auth transport:
  no implicit API-key/OAuth substitution after execution begins.

## Meaningful negative evidence

- Shared scan and run dispatch use the same runtime construction and registry
  preparation boundary at `crates/kuzushi-cli/src/application/scan.rs:508-518`
  and `crates/kuzushi-cli/src/application/run_tool_prepare.rs:335-349`, then
  construct `LangGraphRuntime::from_config` at
  `crates/kuzushi-cli/src/application/scan.rs:1056-1068` and
  `crates/kuzushi-cli/src/application/run_tool.rs:257-277`.
- OpenAI API models do not consume stored OpenAI OAuth, and OAuth-backed models do not
  accept an API key as a substitute
  (`crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs:286-310`).
- Expired OAuth with a refresh token is consistently considered refreshable in
  the canonical runtime probe
  (`crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs:314-318`).
- The TUI/runtime use the configured OAuth path in the repaired flow.
  `crates/kuzushi-tui/src/app/settings/normalize_thinking_level/oauth_status.rs:29-56,157-180`
  checks that contract directly.
- The OAuth login script validates non-empty access at
  `scripts/langgraph-bridge/oauth-login.mjs:120-127`, returns nonzero on failure
  at `:328-340`, calls the shared credential writer at `:175-183`, and that
  writer uses atomic rename with restrictive permissions at
  `scripts/langgraph-bridge/model.mjs:306-313`.
- Project-local configuration rejects model, runtime, API-key-env, and OAuth
  steering at
  `crates/kuzushi-core/src/config/load_config_for_target.rs:334-381`.

## Verification and missing coverage

Commands rerun on 2026-08-21 against the stated working tree:

- `git rev-parse --short HEAD` returned `a3b0193e69` with exit 0.
- `cargo test -p kuzushi-tui --lib oauth -- --test-threads=1` exited 0:
  37 passed, 0 failed, 2,851 filtered out.
- `cargo test -p kuzushi-cli auth_ping -- --nocapture` exited 0: six matching
  unit tests and one matching cutover integration test passed.
- `node --test scripts/langgraph-bridge/model.test.mjs
  scripts/langgraph-bridge/oauth-login.test.mjs` exited 0: 32 passed, 0 failed.
- `node scripts/check-model-safety.mjs`,
  `node scripts/check-env-discipline.mjs`,
  `node scripts/artifact-manifest-contract.mjs`, and
  `node scripts/check-doc-command-drift.mjs` each exited 0.
- `git diff --no-index --check /dev/null
  docs/audits/2026-08-21/AUTH_RECOVERY_SYSTEMIC_AUDIT.md` emitted no whitespace
  diagnostics; its exit 1 is the expected no-index “files differ” status for
  this new, untracked memo.

Their success is evidence of missing contract coverage, not evidence that the
surfaces agree. In particular, there is no provider/model/credential
cross-binding test, no nonzero-child-with-success-JSON test, no all-worker
typed-auth-recovery test, and no model-specific Doctor-vs-Setup-vs-runtime
conformance test.

## Not covered

- live browser/provider OAuth against real accounts;
- network-time token revocation and refresh races;
- third-party dynamic modules that implement their own credential protocols;
- OS/keychain integrations not present in this repository;
- migration design for existing operator config once auth method becomes an
  explicit persisted concept.

Author/process declaration: this audit turn added only this memo. Product-code
changes already present in the working tree belong to the preceding OpenAI
OAuth recovery implementation. Remediation should be a separate hardening pass
so the P0 is fixed first and every accepted change is reviewed against this
matrix.
