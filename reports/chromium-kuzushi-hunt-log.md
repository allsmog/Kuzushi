# Chromium Kuzushi Hunt Log

Date: 2026-05-12

Objective: use Rust Kuzushi with inherited OpenAI Codex auth to find a Chromium
VRP-grade candidate, patch Kuzushi blockers as needed, and avoid speculative
submissions.

## Kuzushi Runtime Fixes

Patched Kuzushi so the Rust CLI can drive the current `pi-agent-core` bridge
with inherited local OpenAI/Codex auth:

- `scripts/pi-agent-core-bridge.mjs`
  - Reads `CODEX_HOME/auth.json` or `~/.codex/auth.json` for inherited
    `openai-codex` / `openai` auth.
  - Accepts `OPENAI_AUTH_TOKEN` / `OPENAI_OAUTH_TOKEN`.
  - Extracts text from newer `pi-agent-core` result object shapes.
  - Fails explicitly on empty model output, including provider/model/auth state.
- `crates/kuzushi-openai/src/pi_agent_core/bridge_process.rs`
  - Tolerates `BrokenPipe` when a bridge exits after writing a complete JSON
    response before reading stdin; success/failure is still decided by child
    exit status and parseable stdout.
- Updated `@mariozechner/pi-ai` and `@mariozechner/pi-agent-core` from
  `0.68.0` to `0.73.1`, which makes the full `gpt-5.5` Codex/OpenAI models
  usable through the bridge:
  - Strong OpenAI/Codex choices use `gpt-5.5`.
  - Mini choices remain `gpt-5.4-mini` because `gpt-5.5-mini` still resolves as
    missing/stub and returns empty output.

Validation:

- `git fetch origin main` confirmed `main` and `FETCH_HEAD` both at
  `55ab9ee08bdf6798ab7d7c73a8fd7a92cf6ff068`.
- `node --check scripts/pi-agent-core-bridge.mjs` passed.
- `corepack pnpm exec biome check scripts/pi-agent-core-bridge.mjs` passed.
- Direct bridge probe with inherited auth returned `ok` using
  `openai-codex:gpt-5.5`.
- Rust CLI probe with `openai-codex:gpt-5.5` completed:
  `agentic-sast:scan` over `/workspaces/targets/chromium-src/url/android`,
  run ID `539ad882-7857-4f9f-8c22-7e7d025cdb59`.
- Current final focused gates passed:
  - `cargo test -p kuzushi-core capabilities::agentic_sast::tests`: 7 tests.
  - `cargo test -p kuzushi-openai`: 38 tests; 3 live OAuth experiments ignored.
  - `cargo test -p kuzushi-cli cli_tool_run_preserves_artifact_manifest_across_finish_and_failure`.
  - `cargo test -p kuzushi-cli runs_trace_output_covers_plain_and_json`.
  - `cargo build --release -p kuzushi-cli`.
  - `cargo fmt --check`.
  - `git diff --check`.

Artifact fix:

- `crates/kuzushi-cli/src/tool_run_artifacts.rs` previously wrote
  `input.json` at run start but replaced the final `summary.json` with only
  `result.json` on successful completion. Failed runs could also lose the input
  artifact in the manifest.
- Patched completion/failure paths to preserve existing artifacts and added a
  CLI test covering successful and failed tool runs.
- Repaired existing Chromium target run summaries where `input.json` existed on
  disk but was missing from `summary.json`.
- Current validation gate: if a run reports 0 findings, parse `summary.json`,
  `input.json`, `result.json`, and any `trace.jsonl`; confirm files present on
  disk are listed in `summary.json`; inspect `result.json` for hidden failure or
  malformed no-finding payloads before treating the run as clean.
- Rebuilt `target/release/kuzushi` and confirmed a fresh `findings:list` run,
  `run-1778547900-88290a33d145`, records both `input` and `result` artifacts.

## Candidate 1: WebTransport Null Session CHECK Race

Status: killed as VRP-grade. Keep only as a possible ordinary Chromium DoS bug
until a repro shows impact beyond a clean Network Service/browser crash.

Hypothesis:

An attacker-controlled page establishes WebTransport to an attacker-controlled
HTTP/3 server, the server closes the session, and the page keeps issuing
renderer-reachable Mojo calls while `DedicatedWebTransportHttp3Client` has
cleared `web_transport_session_` but before `network::WebTransport::TearDown()`
resets its receiver. The likely crash sink is a release `CHECK()` on a null
session.

Supporting code evidence:

- `/workspaces/targets/chromium-src/services/network/web_transport.cc:701`
  binds the renderer-facing `mojom::WebTransport` remote only after connection
  establishment.
- `/workspaces/targets/chromium-src/services/network/web_transport.cc:465`
  `SendDatagram()` accepts renderer input and hits `CHECK(transport_->session())`
  at line 471.
- `/workspaces/targets/chromium-src/services/network/web_transport.cc:475`
  `CreateStream()` hits `CHECK(session)` at line 489.
- `/workspaces/targets/chromium-src/services/network/web_transport.cc:565`
  `SetOutgoingDatagramExpirationDuration()` hits `CHECK(transport_->session())`
  at line 571.
- `/workspaces/targets/chromium-src/net/quic/dedicated_web_transport_http3_client.cc:783`
  `OnConnectStreamDeleted()` clears `web_transport_session_` at line 786.
- `/workspaces/targets/chromium-src/net/quic/dedicated_web_transport_http3_client.cc:931`
  `OnSessionClosed()` posts the close transition asynchronously at lines 935-938.
- `/workspaces/targets/chromium-src/services/network/web_transport.cc:891`
  `TearDown()` only resets the Mojo receiver at line 893 after `OnClosed()` or
  `OnError()` runs.

Counterevidence / why not submit as VRP:

- The observed primitive is a null-session release `CHECK`, not memory
  corruption, controlled read/write, sandbox escape, or credential/data exposure.
- Chromium already has a related null-session cleanup test:
  `/workspaces/targets/chromium-src/services/network/web_transport_unittest.cc:929`
  `DisposeWithNullSession`. That test only covers early handshake disposal, not
  post-establishment renderer calls, so the bug may still be real as DoS.
- Chrome security reporting guidance says ordinary DoS/null-pointer crashes are
  generally not treated as security vulnerabilities. The current evidence does
  not clear that bar.

Minimal repro direction if filing as a normal bug:

1. Serve a WebTransport endpoint that accepts `/echo` then immediately sends a
   session close or tears down the connect stream.
2. Page PoC:

   ```js
   const wt = new WebTransport("https://localhost:<port>/echo");
   await wt.ready;
   const writer = wt.datagrams.writable.getWriter();
   for (;;) writer.write(new Uint8Array([0x41])).catch(() => {});
   ```

3. Instrument `OnConnectStreamDeleted()`, `OnSessionClosed()`,
   `TransitionToState(CLOSED)`, `WebTransport::SendDatagram()`, and
   `WebTransport::TearDown()` to prove the ordering.

## Candidate 2: Android Origin FromJavaObject Dangling Pointer

Status: killed as false positive.

Kuzushi run:

- Tool: `agentic-sast:scan`
- Target: `/workspaces/targets/chromium-src/url`
- Run ID: `7908f274-baf1-40c8-821d-3462f9593f78`
- Finding: `c3d8e30c0180777a`

Finding claim:

`Origin::FromJavaObject()` passes the address of a stack `Origin` to Java:
`/workspaces/targets/chromium-src/url/android/origin_android.cc:40-43`.

Kill reason:

The Java method does not store the native pointer. It immediately calls native
`OriginJni.assignNativeOrigin(...)` with the pointer as a transient argument:
`/workspaces/targets/chromium-src/url/android/java/src/org/chromium/url/Origin.java:148-158`.
The native callback writes into the stack `Origin` before `FromJavaObject()`
returns:
`/workspaces/targets/chromium-src/url/android/origin_android.cc:58-75`.
There is no retained dangling native pointer.

## Candidate 3: Extension Platform App Optional Host Permission CORS/ORB Relaxation

Status: killed as VRP-grade.

Hypothesis:

`extensions/browser/url_loader_factory_manager.cc` grants content-script
URLLoaderFactories with relaxed CORS/ORB behavior to Chrome Platform Apps when
their optional permissions cover HTTP(S), even before those optional permissions
are granted.

Supporting clue:

- `/workspaces/targets/chromium-src/extensions/browser/url_loader_factory_manager.cc:62-72`
  explicitly treats optional HTTP(S) permissions as a reason to return true.
- `/workspaces/targets/chromium-src/extensions/browser/url_loader_factory_manager.cc:90-100`
  relaxes only platform-app content-script factories.
- `/workspaces/targets/chromium-src/extensions/browser/url_loader_factory_manager.cc:125-135`
  disables ORB and allows `isolated_world_origin` to participate in CORS checks.

Kill reason:

The actual CORS bypass path still depends on `OriginAccessList`.
`services/network/cors/cors_url_loader.cc:1203-1211` only treats a destination as
special-access when `origin_access_list_->CheckAccessState(request_)` is allowed.
That check uses the content script's `isolated_world_origin` as the source
origin:
`services/network/public/cpp/cors/origin_access_list.cc:96-116`.
The extension allow list is populated from effective/granted host permissions,
not ungranted optional permissions:
`extensions/common/cors_util.cc:72-82`.

Disabling ORB for the factory may still be legacy cleanup debt, but without a
matching `OriginAccessList` allow entry it does not provide script-readable
cross-origin response bytes.

## Clean Kuzushi Runs

- `chrome-rce:scan` over `/workspaces/targets/chromium-src`: 0 findings.
  Run ID: `chrome-rce-e90c08e5-cd46-45ac-9d90-f0f2b98dc3a0`.
- `systems-hunt:systems-hunt` over `/workspaces/targets/chromium-src/net`:
  0 findings. Run ID: `f7014a19-f1a7-4a67-9ef2-fcf4ceb13730`.
- `agentic-sast:scan` over
  `/workspaces/targets/chromium-src/services/network`: 0 findings.
  Run ID: `a9bd8a4e-6dae-429a-b2e4-6923ca4b81c1`.
- `agentic-sast:scan` over
  `/workspaces/targets/chromium-src/content/browser/renderer_host`: 0 findings.
  Run ID: `a9fc0b7e-4c89-4561-81cf-6f31bdbced82`.
- `systems-hunt:systems-hunt` over
  `/workspaces/targets/chromium-src/third_party/blink/renderer/core/fetch`:
  0 findings. Run ID: `64900f2b-e1dd-447c-9982-803a616aaf88`.
- `agentic-sast:scan` over
  `/workspaces/targets/chromium-src/extensions/browser/api/messaging`:
  0 findings. Run ID: `f8ceb6e9-5e40-4c47-9533-82b765bd5ee8`.
- `agentic-sast:scan` over
  `/workspaces/targets/chromium-src/extensions/browser/api/scripting`:
  0 findings. Run ID: `4a308fea-f4c9-4e91-91f9-de134b5bba11`.
- `systems-hunt:systems-hunt` over
  `/workspaces/targets/chromium-src/extensions/browser/api/management`:
  0 findings. Run ID: `200d7a4a-70d7-4875-89a4-9eb7b29d5db7`.
- `systems-hunt:systems-hunt` over
  `/workspaces/targets/chromium-src/content/browser/renderer_host`:
  0 findings. Run ID: `11656afa-aa30-4ccf-8fb4-6fe0d3d8188a`.
- `systems-hunt:systems-hunt` over
  `/workspaces/targets/chromium-src/services/network/cors` using
  `openai-codex:gpt-5.5`: 0 findings.
  Run ID: `8d8b3528-a2af-4204-9b13-2b91c7b9348f`.
- `systems-hunt:systems-hunt` over
  `/workspaces/targets/chromium-src/extensions/browser/guest_view/web_view`
  using `openai-codex:gpt-5.5`: 0 findings.
  Run ID: `630dd368-214b-4a05-b8a7-27d6bca6d916`.
- `agentic-sast:scan` over `/workspaces/targets/chromium-src/url/android`
  using `openai-codex:gpt-5.5`: 0 findings.
  Run ID: `539ad882-7857-4f9f-8c22-7e7d025cdb59`.
- `agentic-sast:scan` over
  `/workspaces/targets/chromium-src/extensions/browser` using
  `openai-codex:gpt-5.5`: 0 findings.
  Run ID: `71cf6fe0-3c93-4849-9ec6-883e869d9770`.
- `systems-hunt:systems-hunt` over
  `/workspaces/targets/chromium-src/services/network` focused on URLLoader/CORS
  using `openai-codex:gpt-5.5`: 0 findings.
  Run ID: `9f78998e-d345-4980-a761-ae34b95de148`.
- `systems-hunt:systems-hunt` over
  `/workspaces/targets/chromium-src/third_party/blink/renderer/platform/loader`
  using `openai-codex:gpt-5.5`: 0 findings.
  Run ID: `72387fc2-144c-4932-a753-8e260897320a`.

## 2026-05-12 Critical-CVE-Shaped Hunt

Recent Chrome release notes pushed the hunt toward WebML/WebNN, WebGL/GPU, and
Canvas:

- WebML/WebNN: April 2026 desktop/ChromeOS notes list critical WebML heap
  buffer overflow and integer overflow fixes with $43k rewards.
- WebGL/GPU/ANGLE: March 2026 desktop notes list critical WebGL OOB memory
  access/read-write and critical ANGLE integer overflow; March/April notes also
  list high GPU/WebGL heap overflow/UAF bugs.
- Canvas: late-April 2026 desktop notes list a critical Canvas UAF.

Source release pages:

- https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop.html
- https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
- https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_22.html
- https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_28.html
- https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_31.html
- https://chromereleases.googleblog.com/2026/05/stable-channel-update-for-desktop.html

Sparse checkout expansion:

- Added `services/webnn`, `third_party/blink/renderer/modules/ml`,
  `third_party/blink/renderer/modules/webgl`, `gpu/command_buffer`,
  `third_party/blink/renderer/modules/canvas`,
  `third_party/blink/renderer/core/html/canvas`, and Blink platform graphics
  paths needed for the focused runs.

Kuzushi patches made during this hunt:

- `agentic-sast` now honors `focus` / `huntFocus` input and injects it into the
  prompt. Before this, the high-critical Chromium focus text was silently
  ignored.
- `agentic-sast` review-pass merge now deduplicates semantically identical
  findings by tool/rule/path/start/end instead of fingerprint only. This fixed
  duplicate WebNN artifacts where two passes reported the same bug with
  different messages/fingerprints.
- `agentic-sast` now accepts bounded `maxInventoryFiles` and `maxBytesPerFile`
  inputs. Defaults remain 80 and 2048, caps are 500 and 8192.

Validation:

- `cargo test -p kuzushi-core capabilities::agentic_sast::tests` passed after
  each patch. Current focused suite: 7 tests.
- `cargo build --release -p kuzushi-cli` passed after the patches. The
  pre-existing `kuzushi-tui` warnings remain noisy but non-blocking.

### Killed As VRP-Ready: WebNN Shared-Lock Count Race

Status: real-looking correctness/data-race lead, but killed as VRP-ready for
now. Current evidence shows renderer-reachable concurrent mutation of WebNN
tensor backing memory during backend inference, but not a concrete OOB/UAF or
controlled memory access primitive.

Clean Kuzushi run after dedupe patch:

- Tool: `agentic-sast:scan`
- Model: `openai-codex:gpt-5.5`
- Run artifact ID: `run-1778551962-8c7b49d25d69`
- Persisted findings DB run ID: `26d952bf-37c9-47de-9a17-8ac2ec68dee1`
- Cost: `0.480255`
- Findings: 1 high, `webnn-shared-lock-count-race`

Evidence to investigate:

- `/workspaces/targets/chromium-src/services/webnn/queueable_resource_state_base.cc:11`
  allows additional shared locks while `state_ == kLockedShared`.
- `/workspaces/targets/chromium-src/services/webnn/queueable_resource_state_base.cc:23`
  unconditionally sets the resource state to unlocked on any unlock; there is
  no shared-reader count.
- `/workspaces/targets/chromium-src/services/webnn/resource_task.cc:91` unlocks
  all task resources, then immediately checks waiting tasks. The first completed
  shared task can therefore let a waiting exclusive task run while another
  shared task is still active.
- TFLite dispatch takes shared locks on input tensors and exclusive locks on
  output tensors plus compute resources:
  `/workspaces/targets/chromium-src/services/webnn/tflite/graph_impl_tflite.cc:592`.
- TFLite/LiteRT dispatch collects raw references to `BufferContent` and posts
  backend work to the thread pool:
  `/workspaces/targets/chromium-src/services/webnn/tflite/graph_impl_tflite.cc:626`
  and
  `/workspaces/targets/chromium-src/services/webnn/tflite/graph_impl_litert.cc:291`.
- `BufferContent::AsSpan()` returns mutable span access over the backing buffer:
  `/workspaces/targets/chromium-src/services/webnn/tflite/buffer_content_tflite.cc:44`.

Likely trigger shape:

1. Web page creates a WebNN tensor usable for read/write and dispatch input.
2. Queue a long-running `Dispatch()` using that tensor as a shared input.
3. Queue `ReadTensor()` on the same tensor; it also takes a shared lock and can
   complete quickly.
4. Queue `WriteTensor()` on the same tensor. When the read completes first, the
   resource state becomes unlocked even though dispatch still has a shared
   reference. The write can take the exclusive lock and mutate the input buffer
   while backend inference is still reading it.

Current risk call:

- This is more promising than the earlier renderer-only null-deref/QDQ finding,
  but still not enough for a paid Chrome VRP submission.
- Manual follow-up found that TFLite gather/scatter indices are sanitized by a
  generated clamp/where subgraph before the gather/scatter operation:
  `/workspaces/targets/chromium-src/services/webnn/tflite/graph_builder_tflite.cc:5272`.
  That weakens the obvious "mutate indices after validation" path.
- A focused exploitability scan returned no VRP-grade consequence:
  `run-1778552982-70cba679873d`, 0 findings, cost `0.15714`. Verified
  `summary.json`, `input.json`, `result.json`, and `trace.jsonl`; trace replay
  works.
- Keep this only as a possible Chromium correctness/TSAN bug until a backend
  behavior turns it into OOB/UAF/controlled memory access.

### Zero-Finding Runs Verified

- Keepalive/user-script isolated-world CSP focused run:
  `run-1778550759-e7ff99231a58`, 0 findings, cost `0.2522`. Verified
  `summary.json`, `input.json`, `result.json`, and `trace.jsonl`; trace replay
  works.
- WebGL/GPU command decoder focused run:
  `run-1778552414-c158933884e4`, 0 findings, cost `0.2271`. Verified
  `summary.json`, `input.json`, `result.json`, and `trace.jsonl`; trace replay
  works.
- Canvas UAF/lifetime focused run:
  `run-1778552555-88416015cd66`, 0 findings, cost `0.268015`. Verified
  `summary.json`, `input.json`, `result.json`, and `trace.jsonl`; trace replay
  works.
- WebNN shared-lock exploitability focused run:
  `run-1778552982-70cba679873d`, 0 findings, cost `0.15714`. Verified
  `summary.json`, `input.json`, `result.json`, and `trace.jsonl`; trace replay
  works.
- WebML/WebNN graph validation and backend conversion focused run:
  `run-1778553093-a68380c8d003`, 0 findings, cost `0.298655`. Verified
  `summary.json`, `input.json`, `result.json`, and `trace.jsonl`; trace replay
  works.
- Focused Chromium-side WebGL/GPU command-buffer run:
  `run-1778553301-b89b1932d4e2`, 0 findings, cost `0.1989`. Verified
  `summary.json`, `input.json`, `result.json`, and `trace.jsonl`; trace replay
  works. Note: ANGLE is a gitlink (`third_party/angle`) and was not present in
  this sparse checkout, so this does not cover ANGLE internals.

## Ranked Next Targets

1. WebML/WebNN manual review of exact Chrome patches/CVE-adjacent commits if
   available. The current broad validation/backend-conversion scan returned
   clean, but WebML remains high value because recent critical CVEs landed there.
2. ANGLE checkout or targeted sync, then scan ANGLE WebGL/GPU CVE-adjacent
   code. The Chromium-side command-buffer runs returned clean, but ANGLE source
   was not present.
3. Canvas worker/offscreen/resource lifetime manual audit. Broad Kuzushi pass
   returned clean, but the recent critical UAF means async callback/lifetime
   paths are still worth manual slicing.
4. WebNN shared-lock race TSAN/browser-test proof. Treat as correctness/backlog
   until an actual memory-safety primitive appears.
5. Keepalive isolated-world CSP redirect mismatch. Treat as policy-bug backup,
   not high-critical money path, unless a PoC demonstrates script-readable
   cross-origin data or sandbox/permission bypass.

## Submission Gate

Do not submit anything from this log as a Chrome VRP report yet. A submission
candidate still needs:

- A minimized PoC attached as files, not a hosted link.
- Exact Chrome version/channel and OS.
- Symbolized stack trace or stronger exploit evidence.
- A security consequence beyond ordinary DoS, or a controlled read/write proof.

## 2026-05-12 ANGLE/WebGL Continuation And Final No-Submit State

Status: no Chrome VRP-ready high/critical candidate found. The continuation did
complete the missing ANGLE/WebGL/GPU pass that the earlier sparse checkout could
not cover, patched a Kuzushi inventory blocker, and produced verified
zero-finding artifacts for each exact CVE-adjacent slice.

### Target Preparation

- Chromium target: `/workspaces/targets/chromium-src`.
- ANGLE gitlink was initialized at the Chromium-pinned revision
  `ea31231a60bae8985770cf9e4102bfe944b8ec77` with
  `git submodule update --init --depth 1 third_party/angle`.
- Patch mapping used recent Chrome stable security releases and direct
  Chromium/ANGLE Gitiles commits:
  - Chrome stable desktop release notes:
    `https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_31.html`,
    `https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop.html`,
    `https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html`,
    `https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_22.html`,
    `https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_28.html`,
    and
    `https://chromereleases.googleblog.com/2026/05/stable-channel-update-for-desktop.html`.

### Exact Patch Map Used

- ANGLE Vulkan integer overflow, bug `485622239`: ANGLE commit
  `2d051d9cef02bca69a97749a995b138e3dec0e1f`, touching
  `src/libANGLE/renderer/vulkan/TextureVk.cpp`.
- ANGLE D3D11 line-loop/triangle-fan overflow, bug `487977696`: ANGLE commit
  `e05753c6d05b17b23d514038957469c70b75475c`, touching
  `src/libANGLE/renderer/d3d/d3d11/Renderer11.cpp`.
- ANGLE WebGL/IMG uniform-block compile-time validation, bug `475877320`:
  ANGLE commit `05459080c9a323e89a52209efb799d6dc5b68a86`, touching translator
  and GL validation paths.
- ANGLE D3D streaming vertex-buffer overflows, bug `489791424`: ANGLE commit
  `949bb97ac07572f7f8ae44e38541cc6e8ca95f93`, touching `mathutil.h`,
  `RendererD3D`, `VertexBuffer`, `VertexDataManager`, and D3D9/D3D11 variants.
- ANGLE Metal buffer shadow-size mismatch, bug `489494022`: ANGLE commit
  `1ca27145c44e618dcbff83babd6b6542ce82e5ad`, touching `BufferMtl.mm`.
- ANGLE Metal 16-byte buffer-size rounding, bug `489585044`: ANGLE commit
  `3afa9f7ef657f16f648e2aef166917bc55323458`, touching `BufferMtl.mm`.
- ANGLE Metal heap overflow around `TextureMtl::mFormat`, bug `493256564`:
  ANGLE commit `7cde4ef59f6c434ea78cc3ec43be699a9acbab49`, touching
  `TextureMtl.h`, `TextureMtl.mm`, and `TextureTest.cpp`.
- ANGLE D3D11 TransformFeedback stale/deleted-buffer tracking, bug
  `489791425`: ANGLE commit `dbeb8c9415e1531858e09da1537e682bb509b9fc`,
  touching `TransformFeedback11.cpp`.
- ANGLE GL internal `ReadPixels` pack-state heap overflow, bug `490170083`:
  ANGLE commit `cbc4f074126e6f1acf72ad620a28cd4a8dd86f2a`, touching
  `src/libANGLE/renderer/gl/BlitGL.cpp` and `CopyTextureTest.cpp`.
- Blink WebGL stale-object context-generation bug `485935305`: Chromium commit
  `c1433740f3ea902fd6b15d63c4865ad60a3761f9`, touching
  `webgl_context_object_support.cc/.h`, `webgl_object.cc/.h`, and
  `webgl_rendering_context_base.h`.

### Kuzushi Blocker Fixed

The first ANGLE Metal pass was invalid because `agentic-sast` inventory only
considered a narrow source-file extension set. Focused include patterns for
ANGLE `.mm` and `.h` files produced a near-empty prompt and a misleading low
cost.

Fix:

- `crates/kuzushi-core/src/capabilities/agentic_sast/application/collect_repo_inventory.rs`
  now treats C/C++ headers and Objective-C/Objective-C++ files as agentic
  context files: `h`, `hh`, `hpp`, `hxx`, `m`, `mm`.
- `crates/kuzushi-core/src/capabilities/agentic_sast/tests.rs` adds
  `inventory_includes_cpp_headers_and_objective_cpp_sources`, using ANGLE-style
  `TextureMtl.mm` and `TextureMtl.h` paths.

Validation:

- `cargo test -p kuzushi-core capabilities::agentic_sast::tests` passed.
- `cargo fmt --check` passed.
- `cargo build --release -p kuzushi-cli` passed. Existing `kuzushi-tui`
  warnings remain noisy but did not block the build.

### Verified Zero-Finding ANGLE/WebGL Runs

Each zero-finding run was audited through `summary.json`, `input.json`,
`result.json`, `trace.jsonl`, persisted `scan_runs` DB state, `runs show`, and
`runs trace`.

- ANGLE GL pack-state/readback heap-overflow adjacency, bug `490170083`:
  run artifact `run-1778590558-ae31fbe66a0f`, persisted DB scan
  `7b4942ae-bb99-4cde-95ad-eafb07368677`, 0 findings, cost
  `0.06201000000000001`.
- ANGLE D3D integer-overflow adjacency, bugs `487977696` and `489791424`:
  run artifact `run-1778590698-731fea86d68a`, persisted DB scan
  `f1d1ca0e-832e-4cc7-a980-8f9b6ef271cf`, 0 findings, cost `0.06028`.
- ANGLE Metal first run, bugs `493256564`, `489494022`, and `489585044`:
  run artifact `run-1778590775-aab6de2f1e8d`, persisted DB scan
  `a7e7b99e-ef5d-46bf-9602-3c345a7ea22b`, 0 findings, cost `0.00588`.
  This run is marked invalid because the inventory blocker excluded `.mm` and
  `.h` context.
- ANGLE Metal corrected rerun after the inventory fix:
  run artifact `run-1778591143-fc78cffe413f`, persisted DB scan
  `60d462fc-da4f-4610-95fe-4af6fc84e603`, 0 findings, cost `0.11745`.
- ANGLE Vulkan texture/allocation overflow adjacency, bug `485622239` and
  related allocation-cap bugs `486972661`/`487208468`: run artifact
  `run-1778591229-40162ffb8900`, persisted DB scan
  `42e6d588-a8e9-4d3a-99b9-99976d486b09`, 0 findings, cost `0.1083`.
- Blink WebGL stale-object/context-generation adjacency, bug `485935305`:
  run artifact `run-1778591532-bbe8832dcaa7`, persisted DB scan
  `4bc2dcfe-1bda-430a-a903-f135e0a815e2`, 0 findings, cost
  `0.07078500000000001`.

### Ranked Killed Candidates

1. WebNN shared-lock count race: kept as the best correctness lead, but killed
   as VRP-ready because the current evidence does not produce a concrete
   OOB/UAF/controlled memory-access primitive.
2. WebTransport null-session CHECK race: killed as ordinary renderer-process
   DoS/null CHECK, not a high/critical VRP candidate.
3. Android origin-from-Java-object dangling-pointer lead: killed as a false
   positive after manual source review.
4. Extension platform-app optional-host permission CORS/ORB relaxation: killed
   because manual review did not show an `OriginAccessList` bypass or
   script-readable cross-origin data path.
5. ANGLE GL, D3D, Metal, Vulkan, and Blink WebGL exact CVE-adjacent passes:
   killed for this round because corrected focused Kuzushi runs returned zero
   findings and the audited artifacts confirmed the scans covered the intended
   files.
6. ANGLE Metal first pass: killed as an invalid run caused by Kuzushi inventory
   filtering, then replaced by the corrected rerun above.

### Next Exact Target

Next best file/function target is the recent Blink Canvas 2D invalid-size
context-loss restoration UAF pattern:

- Bug: `494352590` with branch bug `503210447`.
- Original Chromium commit:
  `https://chromium.googlesource.com/chromium/src/+/4d94eaa23143776dd5b66e9a79b50dd5be3c5773`.
- Patch title: `Don't honor transient canvas size restoration`.
- Primary files:
  `third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc`,
  `third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.h`,
  and the invalid-size context-loss WPT under
  `third_party/blink/web_tests/wpt_internal/html/canvas/context-lost/2d-invalid-size-context-lost.html`.
- Primary functions:
  `BaseRenderingContext2D::DispatchContextLostEvent` and
  `BaseRenderingContext2D::TryRestoreContextEvent`.
- Variant shape to test next: OffscreenCanvas with a placeholder, rapid
  `good => bad => good => bad` or event-handler-driven size transitions, and
  context-restoration timers that can push a frame while the canvas is invalid
  and the `CanvasResourceDispatcher` is being destroyed.

Updated submission gate: do not submit any candidate from this hunt. The
current endpoint is a ranked no-submit report plus the exact Canvas target
above for the next continuation.

## Continuation: Systems-Hunt Unblock And Canvas Kill

### Systems-Hunt Fixes

The required full `systems-hunt:systems-hunt` pass initially failed with
`empty_model_output` on `openai-codex:gpt-5.5`. Direct bridge probes succeeded,
so the blocker was the systems-hunt prompt shape: production ranking was being
crowded by test/fixture-like sources and high-surface prompts were too large.

Fix:

- `systems_hunt::collect_inventory` now excludes non-production test sources
  for production hunts (`*_test*`, `*_unittest*`, `*_browsertest*`,
  `*_perftest*`, `*_fuzzer*`, `test_*`, and `test`/`tests`/`testing`
  directory components).
- Systems-hunt prompt context is compact JSON instead of full pretty JSON,
  while still preserving all selected surfaces. Per-surface hardening/evidence
  lists and surface-pack site lists are capped for prompt use.
- Stored hardening signals are capped at 12 per ranked surface.

Validation:

- `cargo fmt --check` passed.
- `cargo test -p kuzushi-core capabilities::systems_hunt::tests` passed.
- `cargo build --release -p kuzushi-cli` passed. Existing `kuzushi-tui`
  warnings remain noisy but did not block the build.

### Required Systems-Hunt Pass

Command shape:

- Tool: `systems-hunt:systems-hunt`.
- Target: `/workspaces/targets/chromium-src`.
- Model: `openai-codex:gpt-5.5`.
- Limits: `maxFindings=20`, `maxSurfaces=120`,
  `maxTriggerHypothesesPerSurface=4`, `maxFiles=12000`,
  `headBytes=24576`.

Result:

- Run artifact: `run-1778601398-0952e61c6db0`.
- Persisted DB scan: `72ff354c-1452-4f10-9e86-92b57800c040`.
- Findings: 0.
- Cost: `1.8888250000000002`.

Zero-finding audit:

- `summary.json` showed `status=complete`, tool `systems-hunt:systems-hunt`,
  0 findings, and input/result artifacts.
- `input.json` preserved the required GPT-5.5/high-limit input.
- `result.json` showed `data.count=0`, `data.findings=[]`, and the persisted
  findings DB path.
- `trace.jsonl` contained `started` and `complete` events with the recorded
  cost.
- Persisted SQLite `scan_runs` row for
  `72ff354c-1452-4f10-9e86-92b57800c040` was `completed` with
  `findings_count=0`; the matching `findings` count was 0.
- `runs show run-1778601398-0952e61c6db0` and
  `runs trace run-1778601398-0952e61c6db0` both matched the filesystem
  artifacts.

### Focused Canvas Agentic-SAST Pass

Second-stage `agentic-sast:scan` used the exact Blink Canvas files and
functions from Chromium commit `4d94eaa23143776dd5b66e9a79b50dd5be3c5773`,
focused on `BaseRenderingContext2D::DispatchContextLostEvent`,
`TryRestoreContextEvent`, invalid-size restoration, OffscreenCanvas
placeholders, `CanvasResourceDispatcher`, and rapid
`good => bad => good => bad` size transitions from event handlers.

Included files:

- `third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc`
- `third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.h`
- `third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.cc`
- `third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.h`
- `third_party/blink/renderer/core/html/canvas/html_canvas_element.cc`
- `third_party/blink/renderer/core/html/canvas/html_canvas_element.h`
- `third_party/blink/renderer/core/html/canvas/canvas_rendering_context.cc`
- `third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h`
- `third_party/blink/renderer/core/html/canvas/canvas_rendering_context_host.cc`
- `third_party/blink/renderer/core/html/canvas/canvas_rendering_context_host.h`
- `third_party/blink/renderer/platform/graphics/offscreen_canvas_placeholder.cc`
- `third_party/blink/renderer/platform/graphics/offscreen_canvas_placeholder.h`
- `third_party/blink/renderer/platform/graphics/canvas_resource_dispatcher.cc`
- `third_party/blink/renderer/platform/graphics/canvas_resource_dispatcher.h`

Result:

- Run artifact: `run-1778601939-130e10d3700e`.
- Persisted DB scan: `ba4e1c1c-a035-4139-bfbf-a588294fc884`.
- Findings: 0.
- Cost: `0.1249`.

Zero-finding audit:

- `summary.json`, `input.json`, `result.json`, and `trace.jsonl` were present
  and internally consistent.
- `result.json` showed `data.count=0`, `data.findings=[]`, and the persisted
  findings DB path.
- Persisted SQLite `scan_runs` row for
  `ba4e1c1c-a035-4139-bfbf-a588294fc884` was `completed` with
  `findings_count=0`; the matching `findings` count was 0.
- `runs show run-1778601939-130e10d3700e` and
  `runs trace run-1778601939-130e10d3700e` matched the filesystem artifacts.

### Canvas Candidate Verdict

Killed as no-submit. Attacker control over canvas width/height and event-handler
timing is real, but the current source closes the known invalid-size
restoration class:

- `DispatchContextLostEvent` only starts the restored-event timer for
  `kInvalidCanvasSize` when `host->IsValidImageSize()` is still true.
- `RestoreFromInvalidSizeIfNeeded` starts restoration only for valid size and
  stops an active restored-event timer when the size becomes invalid again.
- `TryRestoreContextEvent` refetches the host, stops on null host, and stops
  restoration when the non-empty canvas size is invalid.
- `DispatchContextRestoredEvent` refetches/null-checks the host before
  restoring and dispatching `contextrestored`.
- `CanvasRenderingContext::Dispose` clears `host_`, and
  `CanvasRenderingContext2D::Stop` stops the restore timer when disposing a
  lost context.
- OffscreenCanvas placeholder updates use placeholder-ID lookup and dispatcher
  weak pointers rather than a durable raw placeholder pointer.

No concrete UAF/OOB/stale-object primitive was identified after the corrected
focused run and manual review.

### Next Exact Target

Next best target is ANGLE image conversion pitch arithmetic:

- Files:
  `third_party/angle/src/image_util/loadimage.h` and
  `third_party/angle/src/image_util/loadimage.cpp`.
- Primary function:
  `angle::LoadA8ToRGBA8`.
- Sibling targets:
  adjacent `Load*To*` conversion functions using `width`, `height`, `depth`,
  `inputRowPitch`, `inputDepthPitch`, `outputRowPitch`, `outputDepthPitch`,
  `priv::OffsetDataPointer`, and SSE load/store loops.
- Variant shape:
  attacker-influenced WebGL/ANGLE pixel upload or texture conversion where
  row/depth pitch arithmetic, alignment, or remainder handling diverges from
  the actual mapped buffer size and produces OOB read/write rather than a
  CHECK/null dereference.

Submission gate remains no-submit for the completed hunt. Continue with the
ANGLE `image_util/loadimage` target above if another pass is requested.

## Continuation: ANGLE Loadimage Pitch Arithmetic

### Focused Primary Scan

Ran the recommended focused `agentic-sast:scan` against:

- `third_party/angle/src/image_util/loadimage.h`
- `third_party/angle/src/image_util/loadimage.cpp`

Hunt focus: `LoadA8ToRGBA8` and sibling `Load*To*` functions where
attacker-influenced `width`, `height`, `depth`, `inputRowPitch`,
`inputDepthPitch`, `outputRowPitch`, or `outputDepthPitch` feed
`priv::OffsetDataPointer`, SSE/vectorized load-store paths, row/depth loops, or
integer overflow into short buffers.

Result:

- Run artifact: `run-1778604236-9c41aa69656e`.
- Persisted DB scan: `ab819e1b-fe12-49a0-99e3-b18e0312d8c7`.
- Findings: 0.
- Cost: `0.02559`.

Zero-finding audit:

- `summary.json` showed `status=complete`, tool `agentic-sast:scan`, target
  `/workspaces/targets/chromium-src`, 0 findings, and input/result artifacts.
- `input.json` preserved the GPT-5.5 model, two-pass settings, exact
  `loadimage.h/.cpp` include patterns, and the loadimage pitch/SSE hunt focus.
- `result.json` showed `ok=true`, `data.count=0`, `data.findings=[]`, and the
  persisted DB run ID.
- `trace.jsonl` contained started and complete events with cost `0.02559`.
- Persisted SQLite `scan_runs` row for
  `ab819e1b-fe12-49a0-99e3-b18e0312d8c7` was `completed` with
  `findings_count=0`; the matching `findings` count was 0.
- `runs show run-1778604236-9c41aa69656e` and
  `runs trace run-1778604236-9c41aa69656e` matched the filesystem artifacts.

### Caller-Side Follow-Up Scan

The first scan did not explicitly include `loadimage.inc`, which is pulled by
`loadimage.h` and contains the shared `priv::OffsetDataPointer` and template
loader helpers. A second focused scan included the primary files, the `.inc`,
and immediate caller/pitch derivation code:

- `third_party/angle/src/image_util/loadimage.h`
- `third_party/angle/src/image_util/loadimage.cpp`
- `third_party/angle/src/image_util/loadimage.inc`
- `third_party/angle/src/libANGLE/formatutils.h`
- `third_party/angle/src/libANGLE/formatutils.cpp`
- `third_party/angle/src/libANGLE/renderer/d3d/d3d11/Image11.cpp`
- `third_party/angle/src/libANGLE/renderer/d3d/d3d9/Image9.cpp`
- `third_party/angle/src/libANGLE/renderer/d3d/d3d9/formatutils9.cpp`
- `third_party/angle/src/libANGLE/renderer/load_functions_table_autogen.cpp`

Result:

- Run artifact: `run-1778604462-56022dda3b10`.
- Persisted DB scan: `f5beba7a-f669-4c10-abcc-9c336a1374bc`.
- Findings: 0.
- Cost: `0.08057000000000002`.

Zero-finding audit:

- `summary.json`, `input.json`, `result.json`, and `trace.jsonl` were present
  and internally consistent.
- `result.json` showed `ok=true`, `data.count=0`, `data.findings=[]`, and the
  persisted findings DB path.
- Persisted SQLite `scan_runs` row for
  `f5beba7a-f669-4c10-abcc-9c336a1374bc` was `completed` with
  `findings_count=0`; the matching `findings` count was 0.
- `runs show run-1778604462-56022dda3b10` and
  `runs trace run-1778604462-56022dda3b10` matched the filesystem artifacts.

### Manual Review / Kill Rationale

Killed as no-submit. The code is unsafe-buffer style, but current source review
did not produce a concrete reachable OOB read/write primitive:

- `LoadA8ToRGBA8` uses `priv::OffsetDataPointer` for row/depth offsets and
  writes `dest[x]` for `x < width`; its SSE path aligns destination writes
  before `_mm_store_si128` and only does 8-pixel chunks while `x + 7 < width`,
  then handles the tail.
- Shared `OffsetDataPointer` in `loadimage.inc` is raw pointer arithmetic, but
  it is not itself attacker-controlled without a caller-side pitch/extent
  mismatch.
- D3D11 `Image11::loadData` derives `inputRowPitch`, `inputDepthPitch`, and
  `inputSkipBytes` via `computeRowPitch`, `computeDepthPitch`, and
  `computeSkipBytes`, all guarded by `ANGLE_CHECK_GL_MATH`, then writes to a
  D3D mapped subresource using driver-provided `RowPitch`/`DepthPitch`.
- D3D9 `Image9::loadData` similarly derives `inputRowPitch` with checked math
  and writes to a locked rectangle using `locked.Pitch`.
- `InternalFormat::computeRowPitch`, `computeDepthPitch`, and
  `computeSkipBytes` use `CheckedNumeric`/`CheckedMathResult` before the values
  reach the loader.
- Validation calls `ValidImageDataSize`, which computes the pack/unpack end
  byte, checks integer overflow, and bounds PBO offsets or robust client-side
  image sizes before the backend loader path.
- WebGL compatibility adds row/image-height constraints such as
  `skipPixels + width <= rowLength-or-width` and `skipRows + height <=
  imageHeight-or-height`.

No evidence was found that WebGL/ANGLE input can force `LoadA8ToRGBA8` or its
plain sibling converters to see a too-small input/output pitch or mapped output
buffer while still passing validation. This target is not submit-ready.

### Next Exact Target

Next best image-conversion target is ANGLE compressed ETC/EAC/ASTC decode and
transcode code:

- Files:
  `third_party/angle/src/image_util/loadimage_etc.cpp`,
  `third_party/angle/src/image_util/loadimage_astc.cpp`,
  `third_party/angle/src/image_util/AstcDecompressor.cpp`, and
  `third_party/angle/src/image_util/AstcDecompressor.h`.
- Primary functions:
  `LoadETC2RGB8ToRGBA8`, `LoadETC2RGBA8ToRGBA8`,
  `LoadETC2RGB8ToBC1`, `LoadETC2RGBA8ToBC3`, and
  `LoadASTCToRGBA8Inner`.
- Variant shape:
  compressed WebGL texture input where block count, partial edge blocks,
  4x4/ASTC block dimensions, row/depth pitch, or output block-row writes
  diverge from validated image size and produce OOB read/write rather than a
  validation error or ordinary decode failure.

## Continuation: ANGLE Compressed Texture Decode/Transcode

Command run:

```bash
target/release/kuzushi run --target /workspaces/targets/chromium-src --plain --input '{
  "model":"openai-codex:gpt-5.5",
  "maxFindings":10,
  "passes":2,
  "maxInventoryFiles":80,
  "maxBytesPerFile":32768,
  "severity":["ERROR","WARNING"],
  "includePatterns":[
    "third_party/angle/src/image_util/loadimage_etc.cpp",
    "third_party/angle/src/image_util/loadimage_astc.cpp",
    "third_party/angle/src/image_util/AstcDecompressor.cpp",
    "third_party/angle/src/image_util/AstcDecompressor.h",
    "third_party/angle/src/image_util/loadimage.h",
    "third_party/angle/src/image_util/loadimage.inc",
    "third_party/angle/src/libANGLE/formatutils.cpp",
    "third_party/angle/src/libANGLE/formatutils.h"
  ],
  "huntFocus":"ANGLE compressed texture memory-safety hunt. Focus on ETC/EAC/ASTC decode and BC1/BC3 transcode paths: LoadETC2RGB8ToRGBA8, LoadETC2RGBA8ToRGBA8, LoadETC2RGB8ToBC1, LoadETC2RGBA8ToBC3, LoadASTCToRGBA8Inner. Look for OOB read/write from block-count math, partial edge blocks, width/height not divisible by block size, inputRowPitch/inputDepthPitch/outputRowPitch/outputDepthPitch mismatch, y/4 block-row indexing, ASTC block dimension assumptions, or compressed image size validation divergence. Report only concrete reachable memory-safety primitives; kill validation errors, CHECK/DCHECK, null deref, and ordinary DoS."
}' agentic-sast:scan > /tmp/angle-compressed-agentic.json
```

Result:

- Run artifact: `run-1778605044-999c8867fec8`.
- Persisted DB scan: `cca5862d-76a3-479f-8ae9-135410fe8285`.
- Findings: 4 medium ASTC pitch findings.
- Cost: `0.1669`.

Artifact audit:

- `summary.json`, `input.json`, `result.json`, and `trace.jsonl` were present
  under `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778605044-999c8867fec8/`.
- `summary.json` reported `status=complete`, `tool=agentic-sast:scan`,
  target `/workspaces/targets/chromium-src`, 4 findings, and cost `0.1669`.
- `result.json` reported `ok=true`, persisted DB
  `/workspaces/targets/chromium-src/.kuzushi/v2/findings.sqlite3`, and the same
  persisted run id.
- Findings were:
  `astc-input-pitch-oob-read`,
  `astc-output-pitch-oob-write`,
  `astc-input-depth-pitch-oob-read`, and
  `astc-output-depth-pitch-oob-write`, all in
  `third_party/angle/src/image_util/loadimage_astc.cpp`.

### Manual Review / Kill Rationale

Killed as no-submit. The ASTC findings correctly noticed that
`LoadASTCToRGBA8Inner` ignores `inputRowPitch`/`outputRowPitch`, computes a
tight ASTC `blockSize`, and calls `AstcDecompressor::decompress` with a tight
RGBA8 output contract. That is not enough for a Chrome VRP memory-safety bug:
the reachable callers do not expose a short source or destination pitch to
WebGL.

- `LoadASTCToRGBA8Inner` computes `blockSize = ceil(width/blockWidth) *
  ceil(height/blockHeight) * 16`, passes that as `dataLength`, and advances
  input/output only by depth pitch.
- `AstcDecompressor` documents and implements a tight output buffer of
  `imgWidth * imgHeight * 4`; it has no row-pitch support.
- Vulkan can route ASTC fallback formats to `R8G8B8A8_UNORM` through
  `vk_format_map.json` and `GetLoadFunctionsMap`, but
  `Context.cpp` hides emulated ASTC from WebGL contexts when
  `limitations.emulatedAstc` is set. Native ASTC does not use the CPU ASTC
  decoder.
- The Vulkan upload staging path computes compressed input pitch through
  `ImageHelper::calculateBufferInfo`, which calls
  `InternalFormat::computeRowPitch` and `computeDepthPitch`. For compressed
  images those ignore pack row/image-height parameters and derive tight block
  pitches. The output staging allocation is also tight RGBA8:
  `width * pixelBytes` and `rowPitch * height`.
- WebGL/client validation requires compressed `imageSize` to equal
  `computeCompressedImageSize` for both full image and subimage paths, and
  `ValidImageDataSize` bounds PBO/client reads against the computed end byte.
- D3D11 compressed uploads call `Image11::loadCompressedData`, which computes
  compressed row/depth pitch with checked math and writes into D3D mapped
  subresources using driver-provided `RowPitch`/`DepthPitch`. The ASTC-to-RGBA8
  load function is not selected on the D3D compressed storage table path.
- WGPU's compressed texture entry points are currently no-op `Continue`
  stubs, so they do not provide the missing WebGL decode sink.
- The ETC/EAC functions inspected here (`LoadETC2RGB8ToRGBA8`,
  `LoadETC2RGBA8ToRGBA8`, `LoadETC2RGB8ToBC1`, `LoadETC2RGBA8ToBC3`, plus
  adjacent BC4/BC5 transcodes) use block-row loops where `x`/`y` offsets match
  the validated compressed block count. Edge blocks can write a full BC block,
  but output row pitch is allocated as `ceil(width/4) * blockBytes`, so the
  last partial block remains within the destination row.

No concrete attacker-controlled route was found where WebGL can pass a too-small
compressed input slice, too-small RGBA/BC output slice, or mismatched block
pitch through validation into these decoders. This target is not submit-ready.

### Next Exact Target

Next best goal: leave `loadimage_*` and hunt Chromium/Blink's WebGL-to-ANGLE
compressed upload boundary for validation/backend divergence before the data
reaches the loader.

- Primary files:
  `third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.cc`,
  `third_party/blink/renderer/modules/webgl/webgl2_rendering_context_base.cc`,
  `third_party/blink/renderer/modules/webgl/webgl_texture.cc`,
  `third_party/blink/renderer/platform/graphics/gpu/webgraphics_context_3d_provider_impl.cc`,
  and ANGLE entry/validation paths for `CompressedTexImage*`,
  `CompressedTexSubImage*`, and pixel-unpack buffers.
- Focus:
  mismatches between Blink's `ArrayBufferView`/PBO/imageSize validation and
  ANGLE's `computeCompressedImageSize`/`computePackUnpackEndByte`, especially
  2D array/depth handling, skip state, extension-gated ASTC/ETC formats,
  `UNPACK_FLIP_Y_WEBGL`/premultiply paths, and robust access size checks.
- Submit bar:
  a reachable OOB read/write or stale uninitialized GPU upload from WebGL
  content, not a rejected validation error or unsupported extension path.

## WebGL Compressed Upload Boundary Scan - 2026-05-12

### Runs / Artifacts

Ran the bounded WebGL compressed-texture boundary scan. The persisted artifacts
were internally consistent:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778605948-a395c7ce920a/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  `agentic-sast:scan`, cost `0.095895`, and 0 findings.
- `/workspaces/targets/chromium-src/.kuzushi/v2/findings.sqlite3` recorded
  persisted scan `0db942b2-0769-4a1c-a74a-74ff96ad7228` as completed with
  0 findings.

The first scan capped files at 32 KiB, which truncated the main Blink and ANGLE
validation files. A deeper focused rerun used larger per-file caps:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778606167-b49f53a055b6/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.085925`, and 0 findings.
- Persisted scan `5aaa6a74-4685-4c7d-81a8-db4786746e0e` completed with
  0 findings.

### Manual Review

Blink's direct `ArrayBufferView` compressed upload paths validate the extension
format, extract the byte length through checked conversion, cap the length
against `kMaximumSupportedArrayBufferSize`, and pass the resulting `imageSize`
to the command buffer. WebGL2 `srcOffset` and `srcLengthOverride` overloads
reject offsets past the buffer and reject overrides past the remaining data
before passing a subspan pointer. The PBO overloads forward `imageSize` and an
offset, relying on command-buffer validation rather than duplicating all checks
in Blink.

ANGLE's validation side requires exact compressed image sizes for 2D and 3D
compressed image and subimage uploads. `ValidImageDataSize` checks client and
PBO bounds through `computePackUnpackEndByte`, and compressed row/depth pitch
calculation derives tight block pitches rather than honoring unpack row length
or image height. No WebGL-controlled short slice, negative offset, skip-state
divergence, or extension-gated format mismatch survived these checks.

### Rejected Lead: ETC/EAC Validating Decoder Fallback

One manually interesting lead was outside the original Blink/ANGLE boundary:
`gpu/command_buffer/service/gles2_cmd_decoder.cc` has an ETC/EAC fallback
decompression path for the validating decoder. `DecompressTextureData` allocates
`output_pixel_size * width * height * depth` with 32-bit operands, then passes
32-bit-derived row/depth pitches to the ANGLE ETC loaders. For a `32768x32768`
ETC/EAC upload, the compressed size can still fit the checked compressed-size
validation while the decompressed RGBA8 size is exactly `2^32` and wraps to
0 before allocation.

A narrow follow-up scan over the command-buffer fallback path completed with no
findings:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778606854-ea3b04b890e2/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.087455`, and 0 findings.
- Persisted scan `d3a66b06-9e1a-4d17-af63-79556712350e` completed with
  0 findings.

Killed as not submit-ready at this stage. This was revisited later with a
larger focused inventory that included the fallback implementation, ETC
extension exposure gates, ANGLE backend caps, and `HeapArray` zero-size
semantics. The final rejection is recorded below under "ETC/EAC Software
Decompression Output Size Wrap"; the short version is that the arithmetic is
suspicious, but the reachable shape collapses to a null/empty allocation crash
rather than a useful pre-`loadimage_*` memory-safety primitive.

### Rejected Lead: WebGL2 Compressed PBO Offset Wrap

An additional blind-spot pass checked the WebGL2 compressed PBO overloads. The
ordinary `texImage*` and `texSubImage*` PBO paths call
`ValidateValueFitNonNegInt32` for `GLintptr offset`, but the compressed
`compressedTexImage*` and `compressedTexSubImage*` PBO overloads forward the
offset directly:

- `webgl2_rendering_context_base.idl` exposes `GLintptr offset` for compressed
  PBO uploads.
- `webgl2_rendering_context_base.cc` casts that offset to a pointer without the
  ordinary non-negative 32-bit helper.
- `gpu/command_buffer/common/gles2_cmd_utils.h::ToGLuint` truncates the pointer
  to 32 bits for the command-buffer command.

Focused scan:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778607372-0bc54ea24695/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.10653`, and 0 findings.
- Persisted scan `a82ac537-c646-40f5-a384-9aa302511194` completed with
  0 findings.

Killed as no-submit. Negative or larger-than-32-bit offsets can wrap to an
in-bounds positive offset, but the final read is still checked against the PBO:
passthrough routes unpack-buffer data as an offset span and ANGLE's image-data
validation bounds `offset + required compressed bytes`; the validating decoder
uses `RequestBufferAccess` with the interpreted offset and exact compressed
byte count. Since WebGL buffer sizes are themselves capped and the attacker
controls the aliased in-bounds PBO bytes, this is a conformance/spec-error lead,
not a WebGL content OOB read/write or stale upload.

The separate `srcLengthOverride` signedness concern is also killed:
`kMaximumSupportedArrayBufferSize` is documented as roughly `2GB - 2MB`, below
`INT_MAX`, so the WebGL2 `GLuint src_length_override` cannot become a negative
`GLsizei` after the existing cap.

### Rejected Lead: WebGL Unpack Flags On Compressed Uploads

The original focus included `UNPACK_FLIP_Y_WEBGL` and premultiply behavior, so a
standalone pass checked these WebGL-only pixel store flags around compressed
uploads:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778607737-d42fc7850434/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.091845`, and 0 findings.
- Persisted scan `f6ca1905-8368-4ab7-84cb-613e9c07ce03` completed with
  0 findings.

Killed as no-submit. Blink's ordinary uncompressed ArrayBuffer and PBO paths do
extra work for `UNPACK_FLIP_Y_WEBGL` and `UNPACK_PREMULTIPLY_ALPHA_WEBGL`, but
compressed uploads forward the byte stream directly. That does not create a
validated-size/backend-size mismatch: ANGLE and the command buffer validate the
compressed byte count from the compressed format and dimensions, not from a
post-conversion RGBA shape. At worst this is ignored WebGL-specific state or a
conformance question, not an OOB/stale-upload primitive.

### Rejected Lead: Extension / Format Gating Matrix

A final focused scan compared Blink's `compressed_texture_formats_` allowlist
against command-buffer validators and ANGLE format tables:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778607794-b9c07f058469/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.116985`, and 0 findings.
- Persisted scan `da10aeab-8287-4cb8-aeba-bbbbc103a8fb` completed with
  0 findings.

Killed as no-submit. The interesting-looking S3TC sRGB `NV` names that Blink
adds are numeric aliases for ANGLE's `EXT` names (`0x8C4C` through `0x8C4F`),
so they hit the same validators and compressed-size calculations. ASTC,
ETC/EAC/ETC1, S3TC, PVRTC, and ATC formats all reduce to either matching block
size/min-block handling, a GL validation error, or an unsupported-extension
path before loader code.

### Rejected Lead: Immutable Storage / Compressed Subimage Format Mismatch

A focused scan checked `texStorage2D`/`texStorage3D` allocation with one
compressed internal format followed by `compressedTexSubImage2D`/`3D` upload
with a separate `format` parameter:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778608297-a5e96b386327/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.081955`, and 0 findings.
- Persisted scan `646d8527-370c-4f67-b135-e962ffe77cbf` completed with
  0 findings.

Killed as no-submit. Blink forwards `texStorage2D`/`texStorage3D` to GL after
checking only context loss and opaque textures, but the backend boundary is
guarded before loader code: ANGLE rejects compressed subimages when
`format != actualInternalFormat`, and the validating command-buffer decoder
performs the same stored-level `internal_format != format` check before exact
compressed-size and subimage-dimension validation.

### Rejected Lead: Passthrough Upload Range Serialization

A focused scan traced compressed texture uploads through Blink, the
command-buffer client, transfer-buffer/bucket/PBO serialization, the
passthrough service handler, and ANGLE validation:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778608444-416b621f439a/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.10613`, and 0 findings.
- Persisted scan `c7e896dd-a79f-437f-8fec-9c1bd5e16984` completed with
  0 findings.

Killed as no-submit. The interesting offset-truncation shape remains only a
conformance/spec issue: PBO offsets are serialized through `ToGLuint`, but the
command-buffer client bounds-checks transfer-buffer offsets with checked
32-bit arithmetic, the passthrough service treats PBO input as an offset span
instead of dereferencing it, and ANGLE/command-buffer compressed validators
require exact image size plus in-bounds PBO/client end bytes before backend
upload code.

### Rejected Lead: ArrayBufferView Lifetime / Shared Buffer Race

A focused scan checked compressed upload IDL signatures and the path from
`[AllowShared, BufferSourceTypeNoSizeLimit] ArrayBufferView` through Blink's
`byteLength`/`srcOffset`/`srcLengthOverride` checks and command-buffer upload
serialization:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778608800-b20f947de8cd/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.098705`, and 0 findings.
- Persisted scan `6ea4387e-16f7-4543-ae6e-f30fa3016afc` completed with
  0 findings.

Killed as no-submit. Shared-array contents can race, but the byte length and
validated subspan are stable for the call, and the command-buffer client either
copies the exact `image_size` into a bucket or validates the exact PBO/transfer
buffer range before the service/ANGLE boundary. This does not create a
validated-length versus backend-read mismatch for compressed uploads.

### Rejected Lead: Bucket Size / Passthrough Doer Truncation

A focused scan checked non-PBO compressed uploads copied into command-buffer
buckets, service handlers that derive `image_size` from `bucket->size()`, and
passthrough doers that call `glCompressedTexImage*` / `glCompressedTexSubImage*`
directly:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778608955-2009ae063d8f/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.113375`, and 0 findings.
- Persisted scan `15e241c0-05ec-46d5-a998-cfc48eba2f15` completed with
  0 findings.

Killed as no-submit. The bucket path is fed by Blink's capped `image_size` for
web-exposed ArrayBuffer uploads, `bucket->GetData(0, image_size)` exposes
exactly the stored byte count, and ANGLE's compressed validators still require
the expected compressed image size before backend upload. Larger renderer-made
buckets would be outside the web-content Blink validation boundary being hunted
here.

### Rejected Lead: WebGL2 Unpack Skip State / Compressed PBO Bounds

A focused scan checked WebGL2 `GL_UNPACK_ROW_LENGTH`,
`GL_UNPACK_IMAGE_HEIGHT`, and `GL_UNPACK_SKIP_PIXELS` / `ROWS` / `IMAGES` state
against compressed PBO uploads:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778609246-f89fd321a0ac/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.08128`, and 0 findings.
- Persisted scan `acc2eb3f-6e55-4dad-b510-42bb5bbc59b0` completed with
  0 findings.

Killed as no-submit. Blink forwards compressed PBO offsets without resetting
WebGL2 unpack skip state, but the ANGLE side is not weaker: compressed
validators require the exact compressed image size, and generic PBO
end-byte validation can only add skip-derived bounds. That makes the path
stricter or a GL error/conformance difference, not a backend read past the
validated PBO range.

### Rejected Lead: Robust Resource Init / Stale Compressed Subimage Upload

A focused scan checked compressed subimage uploads against texture cleared-state
tracking, `ClearTextureLevel`, compressed clear helpers, passthrough doers, and
ANGLE validation:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778609365-0e2c5c54a728/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.12301`, and 0 findings.
- Persisted scan `ad495552-40bb-4ad3-801b-cd971eec9a7b` completed with
  0 findings.

Killed as no-submit. Full-level compressed uploads require exact logical
dimensions and exact compressed byte size. Partial compressed subimage uploads
in the validating decoder clear uncleared levels before upload; passthrough
paths rely on ANGLE/backend validation and did not expose a Blink-side condition
that marks a level cleared while uploading less than the validated compressed
region. No stale or uninitialized GPU upload primitive was found.

### Rejected Lead: `GLsizei imageSize` Conversion For Compressed PBO Overloads

A focused scan checked WebGL2 compressed PBO overloads where the IDL exposes
`GLsizei imageSize` and `GLintptr offset`, and Blink forwards `imageSize`
without the ordinary `ValidateValueFitNonNegInt32` helper used by some
uncompressed PBO paths:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778609559-7a363abe4fdb/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.10151`, and 0 findings.
- Persisted scan `aeb8e106-600f-47c0-9d6f-bc205ed5a2b1` completed with
  0 findings.

Killed as no-submit. The command-buffer client can receive signed `image_size`,
but negative or wrong compressed sizes are rejected by the service/ANGLE
compressed validators before backend upload. No path was found where JavaScript
numeric conversion, command serialization, transfer-buffer validation, or ANGLE
validation disagree enough for a negative, wrapped, or oversized `imageSize` to
reach backend `loadimage_*` or read beyond the validated range.

### Rejected Lead: `srcOffset` / `srcLengthOverride` Byte-Versus-Element Semantics

A focused scan checked WebGL2 compressed ArrayBufferView overloads where Blink
compares `srcOffset` and `srcLengthOverride` against `data->byteLength()` and
passes `ByteSpanMaybeShared().subspan(srcOffset).data()` plus
`imageSize=srcLengthOverride` to the command buffer:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778610128-08bcbc227e8e/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.10661`, and 0 findings.
- Persisted scan `210cf3cb-e94c-431e-bb08-1812b437d924` completed with
  0 findings.

Killed as no-submit. No path was found where the bindings, Blink validation,
command-buffer serialization, and ANGLE compressed `imageSize` checks disagree
such that a typed-array element offset is accepted as a smaller byte offset, or
such that the backend reads beyond the byte range Blink validated. Remaining
effects reduce to attacker-controlled wrong bytes or GL validation failures.

### Rejected Lead: WebGL2 3D / 2D-Array Target And Depth Semantics

A focused scan checked `compressedTexImage3D` and `compressedTexSubImage3D`
across Blink's `TEXTURE_3D` / `TEXTURE_2D_ARRAY` binding validation,
command-buffer texture target and level validation, and ANGLE's compressed 3D
and 2D-array rules:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778610336-f98863e10da8/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.083865`, and 0 findings.
- Persisted scan `2dbda10b-41f6-444f-b491-80907ecb667b` completed with
  0 findings.

Killed as no-submit. Blink only accepts `GL_TEXTURE_3D` and
`GL_TEXTURE_2D_ARRAY` for these overloads. ANGLE rejects unsupported compressed
formats for 3D/2D-array targets, requires `format == actualInternalFormat` for
subimages, and enforces valid level dimensions plus block-aligned or boundary
reaching subimage extents. The command-buffer path also checks stored level
format, valid dimensions, and exact compressed byte size before backend upload.

### Rejected Lead: Compressed PBO Overloads Skipping Blink Validation

A focused scan checked WebGL2 compressed PBO overloads where Blink forwards
some calls without the same Blink-side `ValidateTexture*Binding` and
`ValidateCompressedTexFormat` checks used by ArrayBufferView overloads:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778611131-5d57a6e3349a/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.127805`, and 0 findings.
- Persisted scan `e4117653-4ffe-4109-bf45-2ade502491e7` completed with
  0 findings.

Killed as no-submit. The target-rebind angle is closed because
`WebGLTexture::SetTarget` finalizes a texture's target on first bind, and
`bindTexture` rejects reuse of a texture object with another target. The
remaining PBO validation gaps are redundant for memory safety: the validating
decoder rejects invalid targets, formats, negative or wrong `imageSize`, missing
texture bindings, immutable textures, mismatched subimage internal formats, bad
dimensions, and PBO ranges before upload. Passthrough validates the command
buffer memory span, then relies on ANGLE's compressed texture validation to
reject wrong image sizes and PBO offsets. The only observed Blink-side bypass
candidate was opaque-texture policy validation for some PBO forms, but
`WebGLUnownedTexture` has no reachable constructor use in this checkout and no
pre-`loadimage_*` memory-safety primitive was found.

### Rejected Lead: Compressed Cube-Map Face Validation

A manual pass checked whether Blink's 2D compressed texture helper could accept
cube-map face inputs that later diverge from command-buffer or ANGLE size
validation.

Killed as no-submit. Blink's 2D binding validator maps cube-map face targets to
the current cube-map binding, while `ValidateTexFuncDimensions` rejects
non-square cube-map `texImage` faces and overlarge levels. The command-buffer
texture manager maps cube-map face targets back to the cube binding and
`ValidForTextureTarget` requires cube-map images to be square with depth 1.
ANGLE repeats the cube-face dimension checks in `ValidateES*TexImageParameters`
and then requires exact compressed image size. No reachable face/target
confusion or partial-face byte-range mismatch was found before backend upload.

### Rejected Lead: WebGL Unpack Flags And Compressed Uploads

A focused scan checked WebGL-specific unpack state
(`UNPACK_FLIP_Y_WEBGL`, `UNPACK_PREMULTIPLY_ALPHA_WEBGL`,
`UNPACK_COLORSPACE_CONVERSION_WEBGL`) and WebGL2 unpack skip/row/image-height
state against compressed `ArrayBufferView` and PBO uploads:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778611501-22b9901c0e8e/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.129445`, and 0 findings.
- Persisted scan `9c3775fa-0d55-4276-bd55-230d9ba76c49` completed with
  0 findings.

Killed as no-submit. Blink stores the WebGL-only unpack flags in local state and
uses them in uncompressed image/typed-array/copy conversion paths. The
compressed upload paths do not enter the `TexImageHelperDOMArrayBufferView`
conversion logic that consumes flip/premultiply/colorspace state. For PBO
uploads, command-buffer and ANGLE validation still enforce exact compressed
`imageSize` and PBO bounds before backend upload. No path was found where unpack
state changes the source byte range for compressed upload or causes stale GPU
data to be treated as initialized before `loadimage_*`.

### Rejected Lead: Robust / Generated `imageSize` Wrappers

A focused scan checked generated compressed command structs, ANGLE generated
entry points, and any reachable robust or `bufSize` variants:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778611700-765b6c2e36a0/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.134405`, and 0 findings.
- Persisted scan `332d3b0a-f969-406d-b275-7c89042f4ce7` completed with
  0 findings.

Killed as no-submit. ANGLE has packed-enum metadata for
`glCompressedTex*Robust`, but no reachable `CompressedTex*Robust`
implementation or Chrome WebGL command path exists in this checkout. Chrome
command structs carry signed `GLsizei imageSize`, and both the validating
decoder and ANGLE reject negative or non-exact compressed sizes before upload.
No robust `bufSize` / `imageSize` split was found that validates one byte count
and uploads another.

### Rejected Lead: S3TC Extension Alias Split

A manual pass checked the S3TC naming split where Blink exposes WebGL
`*_EXT` constants, uses some legacy `*_NV` sRGB names internally, and ANGLE's
format table names DXT3/DXT5 with `*_ANGLE` constants.

Killed as no-submit. The `*_NV`, `*_EXT`, and `*_ANGLE` names used here are
numeric aliases for the same GL enum values. Chrome's command-buffer
`FeatureInfo` also synthesizes the DXT1/DXT3/DXT5 extension strings and
compressed-format validators from `GL_EXT_texture_compression_s3tc`, while
ANGLE's GL backend maps S3TC-capable native drivers into the same texture-cap
bits used by `formatutils.cpp`. No Blink-exposed S3TC format was found that
passes Blink format validation but reaches ANGLE with a different block size or
extension gate before backend upload.

### Rejected Lead: Zero-Size Compressed Uploads

A manual pass checked whether zero width, height, or depth could make Blink pass
a zero or user-chosen byte length while ANGLE's compressed min-block logic reads
non-zero data.

Killed as no-submit. Blink allows zero dimensions after rejecting negative and
over-limit sizes, then forwards the caller's `imageSize` / typed-array length.
ANGLE's compressed upload validators compute the exact expected byte count and
reject negative or non-matching `imageSize`. For ordinary block-compressed
formats, a zero dimension produces a zero expected block count. For PVRTC,
Chrome's service helper treats zero as power-of-two and requires the
minimum-block byte count, while ANGLE's `isPow2(0)` rejects the upload before
state is recorded. A native backend that accepts the zero-size PVRTC call would
still receive the exact service-computed byte range. No zero-size path was found
that validates one source range and uploads another.

### Rejected Lead: BPTC / RGTC Extension Gate Gap

A focused scan checked `EXT_texture_compression_bptc` and
`EXT_texture_compression_rgtc`, which were not covered by the earlier
`webgl_compressed_texture_*` filename pattern and are only partially covered by
the broader `*compressed*` wording:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778612730-43a0b5f8f679/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.117565`, and 0 findings.
- Persisted scan `f5be2edc-5dc4-43f7-8a3d-0b7a1e828c8d` completed with
  0 findings.

Killed as no-submit. Blink exposes BPTC/RGTC only after the matching
`GL_EXT_texture_compression_*` extension is supported and adds the exact enum
set to `compressed_texture_formats_`. Chrome's command-buffer `FeatureInfo`
adds the same enums to compressed-format and texture-storage validators, while
ANGLE's `formatutils.cpp` uses matching 4x4 block sizes, extension gates, and
8/16-byte block sizes. The validating decoder and ANGLE still reject wrong
`imageSize`, invalid target/depth usage, and non-aligned partial subimages. No
reachable BPTC/RGTC byte-count or extension-gate mismatch was found before
backend upload.

### Artifact Audit

Checked `/workspaces/targets/chromium-src/.kuzushi` after the WebGL compressed
texture passes. The artifact directory is small (`6.6M`) and there were no
active `kuzushi` / `agentic-sast` scan processes.

The active WebGL/Blink-to-ANGLE boundary set contains 22 persisted scan IDs.
All 22 are `completed`, with 0 reported findings and 0 rows in the persisted
`findings` table for those scan IDs. The latest run directory,
`run-1778615295-d346b6b43317`, is internally consistent: `summary.json`
reports `status=complete`, `findings=0`, and `result.json` reports `ok=true`,
`count=0`, persisted as scan `4f9c996d-a8ab-4e04-ae8d-a8d256c5426d`.

Two run directories have no `result.json`, but both are explicit failed
`systems-hunt:systems-hunt` attempts with `empty_model_output`; they are not
hidden findings. The persisted database has 11 older finding rows overall,
covering earlier base/WebNN experiments and the out-of-scope ASTC
`loadimage_astc.cpp` backend leads; none belong to the active pre-`loadimage_*`
WebGL validation objective.

### Rejected Lead: ANGLE-Only Copy/Get And ATC Surfaces

A final symbol pass checked remaining compressed copy/get/storage entry points
after the BPTC/RGTC gap was closed.

Killed as no-submit. Blink WebGL exposes compressed uploads only through
`WebGLRenderingContextBase` / `WebGL2RenderingContextBase` plus the registered
compressed texture extensions already checked. ANGLE exposes
`GL_CHROMIUM_copy_compressed_texture` and `glGetCompressedTexImageANGLE`, and
Chrome command-buffer validators know ATC formats, but no Blink WebGL extension
or IDL registers those as JS-reachable compressed upload APIs. `texStorage*`
can allocate compressed immutable storage, but it carries no attacker data
bytes and later `compressedTexSubImage*` still validates exact format,
dimensions, `imageSize`, and PBO/bucket ranges. No remaining JS-reachable
Blink-to-ANGLE pre-`loadimage_*` compressed data side door was found.

### Rejected Lead: WebGL2 PBO Offset / `imageSize` Bridge

A narrow follow-up scan covered the WebGL2 compressed upload overloads with
`srcOffset`, `srcLengthOverride`, `PIXEL_UNPACK_BUFFER`, and the Chrome
validating/passthrough command-buffer bridge files that were outside the
original Blink/ANGLE-only prompt:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778613717-ee187ed6c20f/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.131535`, and 0 findings.
- Persisted scan `80183e19-c428-447e-be08-03e3d9926571` completed with
  0 findings.

Killed as no-submit. Blink's typed-array overloads bound `srcOffset` and
`srcLengthOverride` against the current view byte length and pass exactly the
selected byte count to `CompressedTex*`. The PBO overloads do little Blink-side
range checking, but the Chrome validating decoder rejects negative
`imageSize`, exact-size mismatches, and PBO `offset + bytes_required` range
failures before upload. The passthrough handlers validate shared-memory spans
and pass PBO offsets through to ANGLE/native GL; ANGLE's compressed validators
reject negative `imageSize`, require the exact compressed block byte count, and
check PBO end-byte bounds before backend work. No path was found where Blink or
command-buffer validation accepts one attacker-controlled byte range but
ANGLE/backend upload consumes another before `loadimage_*`.

### Rejected Lead: ANGLE-Only Compressed Format Families

A final format-family enumeration checked compressed enums known to ANGLE or
Chrome but absent from Blink's WebGL extension surface: ATC, paletted formats,
`GL_ANGLE_lossy_etc_decode`, 3D ASTC OES block shapes, and PVRTC sRGB forms.

Killed as no-submit. Blink's compressed WebGL exposure is constrained to the
formats registered through `AddCompressedTextureFormat`: ETC/EAC, ETC1, S3TC,
S3TC-sRGB aliases, PVRTC non-sRGB, ASTC LDR/HDR 2D block shapes, RGTC, and
BPTC. The extra ANGLE format families appear in ANGLE's native extension tables
or Chrome internal validators, but no Blink WebGL IDL or extension constructor
adds them to `compressed_texture_formats_`. Chrome's command-buffer WebGL
validators also add only the WebGL-facing subsets for ETC, ETC1, S3TC, BPTC,
RGTC, ASTC, and PVRTC. No JS-reachable compressed upload path was found for
ANGLE-only lossy ETC, paletted, ATC-only, 3D ASTC OES, or PVRTC-sRGB formats.

### Rejected Lead: WebGL2 Compressed PBO 64-bit Offset Truncation

A focused pass checked one concrete mismatch candidate: WebGL IDL defines
`GLintptr` as `long long`, uncompressed WebGL2 PBO texture uploads validate
offsets with `ValidateValueFitNonNegInt32`, but the compressed PBO overloads
forward the `int64_t offset` directly as a pointer. The command-buffer client
then stores that pointer/offset with `ToGLuint`, truncating to a 32-bit command
field.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778614130-0de62d85f9f8/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.124985`, and 0 findings.
- Persisted scan `05b8cb14-ab1b-4faa-af0c-107c0f298b84` completed with
  0 findings.

Killed as no-submit. This appears to be, at most, a WebGL validation/conformance
bug: a huge JS-visible PBO offset could wrap to a different 32-bit offset before
the command buffer and ANGLE validate the range. It does not produce a
pre-`loadimage_*` memory-safety primitive in this path. WebGL buffer allocation
is capped below 32-bit limits, `bufferData(null)` zero-initializes driver
storage, the validating decoder's `Buffer::CheckRange` rejects negative,
oversized, and out-of-range signed offsets, and ANGLE/passthrough validation
checks the 32-bit PBO range it actually forwards to the backend. The observable
effect is selecting different in-bounds bytes from the caller-owned PBO, not
OOB read/write or cross-origin/stale data exposure.

### Rejected Lead: ETC/EAC Software Decompression Output Size Wrap

A final focused pass checked Chrome's validating command decoder fallback for
ETC/EAC formats when `WEBGL_compressed_texture_etc` is exposed but the current
GL version is below GLES 3.0. This path validates the compressed byte count and
then calls ANGLE's ETC/EAC software decompression helpers with a temporary
uncompressed buffer.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778615295-d346b6b43317/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.16632`, and 0 findings.
- Persisted scan `4f9c996d-a8ab-4e04-ae8d-a8d256c5426d` completed with
  0 findings.

Killed as no-submit. The suspicious arithmetic is real in isolation:
`DecompressTextureData` allocates `HeapArray<uint8_t>::Uninit(output_pixel_size
* width * height * depth)` using `uint32_t` operands, while
`ValidateCompressedTexFuncData` checks only the compressed ETC/EAC byte count.
However, the reachable WebGL1/ES2 fallback needs maximum 2D texture dimensions
large enough to wrap the RGBA8 output allocation. Common ANGLE backends cap 2D
textures at 16384, and the 32768-square case wraps to an empty `HeapArray`
whose `data()` is null before the later `empty()` context-loss check. That is a
GPU-process crash/null write shape, not a useful pre-`loadimage_*` OOB
read/write primitive. WebGL2 2D-array/depth variants do not rescue the lead
because the fallback branch is gated on `!IsAtLeastGLES(3,0)`, while WebGL2
requires ES3-capable validation.

### Rejected Lead: Command-Buffer / ANGLE Compressed PBO Pixel-Store Split

A follow-up WebGL-only scan widened the previous compressed PBO checks just
enough to include Blink, the command-buffer client/service split, passthrough
doers, and ANGLE GL/Vulkan backend upload code:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778616283-716ef8274d9f/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.1931`, and 0 findings.
- Persisted scan `d8f470a5-69be-40a0-b9f4-8130ea36e404` completed with
  0 findings.

Killed as no-submit. The interesting-looking split is real but not exploitable:
Blink WebGL2 exposes `UNPACK_ROW_LENGTH`, `UNPACK_IMAGE_HEIGHT`, and
`UNPACK_SKIP_*`; the command-buffer client handles skip state locally and the
service rejects skip `PixelStorei` commands, while compressed PBO commands
validate only `offset + imageSize`. That matches OpenGL ES 3.0.6 §3.8.6:
compressed texture images are an array of `imageSize` bytes relative to `data`,
and all pixel storage modes are ignored when decoding a compressed image. ANGLE's
standalone validation can add skip-derived PBO bounds for compressed data, which
is stricter than the spec, but the Chrome WebGL command-buffer path does not
under-validate a backend read. No pre-`loadimage_*` OOB read/write or stale
upload primitive was found.

### Rejected Lead: WebGL Passthrough Compressed PBO Argument Validation

A narrower WebGL-only scan and manual review checked the passthrough command
decoder path that bypasses Chrome's validating GLES2 decoder for compressed
uploads:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778616477-e28606751281/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.0804`, and 0 findings.
- Persisted scan `57610b6a-43c2-405a-94d9-c97377bc9a01` completed with
  0 findings.

Killed as no-submit. Blink's typed-array overloads bound `srcOffset` and
`srcLengthOverride` against the ArrayBufferView length before passing a byte
span to the GLES2 client. For PBO overloads, the service passthrough handler
validates non-PBO shared-memory spans, rejects non-null shared memory while a
PBO is bound, and converts PBO data into an offset-only pointer for the native
upload. Transfer-buffer PBOs are range-checked client-side before command
submission; service-side PBO offsets are ultimately validated by the
ANGLE/native GL compressed upload path. Negative `imageSize` is not consumed as
a Chrome shared-memory span: non-PBO passthrough paths reject it via the
unsigned size check, while PBO passthrough paths pass the signed `GLsizei` on to
GL/ANGLE validation. The remaining shape is spec/conformance behavior or
driver-owned validation, not a Chrome-controlled pre-`loadimage_*` memory-safety
primitive.

### Rejected Lead: ANGLE Vulkan Compressed Upload Staging Size Mismatch

A final WebGL-only pass checked whether ANGLE's Vulkan backend can stage or copy
more compressed texture data than Blink/command-buffer validation accepted:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778616655-d2b523605de0/`
  reported `status=complete`, target `/workspaces/targets/chromium-src`,
  cost `0.106465`, and 0 findings.
- Persisted scan `8ebe2a38-93b5-42a5-9d93-d49299822b36` completed with
  0 findings.

Killed as no-submit. ANGLE's compressed validators require
`imageSize == computeCompressedImageSize(extents)` and reject negative sizes.
The compressed size, row-pitch, depth-pitch, and staging allocation helpers use
checked arithmetic and the same block geometry. The only subtle-looking state
split is pixel-store: Chrome's GLES2 client forwards `UNPACK_ROW_LENGTH` and
`UNPACK_IMAGE_HEIGHT` in ES3 contexts, but keeps all `UNPACK_SKIP_*` values
client-side; ANGLE's compressed row/depth helpers ignore row length and image
height, and no nonzero skip reaches the compressed backend staging path. The
Vulkan PBO fast path converts the compressed row/depth pitch back into rounded
block-multiple `bufferRowLength`/`bufferImageHeight`, while the CPU staging path
allocates exactly the checked compressed image size before calling the load
function. No path was found where accepted `imageSize` bytes become a larger
Chrome-controlled backend read before `loadimage_*`.

### Rejected Lead: Bounded Blink/ANGLE Compressed Validation Recheck

The requested bounded scan rechecked only Blink WebGL compressed upload
entrypoints and ANGLE compressed validation/format helpers, with explicit focus
on ArrayBufferView/PBO `imageSize`, 2D-array/depth, skip-state divergence,
ASTC/ETC extension gating, `UNPACK_FLIP_Y_WEBGL`, premultiply state, and robust
access sizing:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778616755-31936fe3ecea/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.097365`, and 0 findings.
- Persisted scan `39eda7d4-de2a-4aa7-b0cb-b26fe1fa22ed` completed with
  0 findings.

Killed as no-submit. The scan found no Blink/ANGLE compressed texture
validation/backend mismatch. Manual follow-up on the prompt-specific
flip/premultiply angle did not expose a compressed upload path either:
`UNPACK_FLIP_Y_WEBGL` and `UNPACK_PREMULTIPLY_ALPHA_WEBGL` are stored as Blink
WebGL pixel-store booleans and used by image/bitmap/video tex-image conversion
helpers, while compressed uploads pass caller-provided bytes directly as
`BaseAddressMaybeShared()` or bounded `ByteSpanMaybeShared().subspan()` data.
WebGL2 ArrayBuffer overloads validate `srcOffset`/`srcLengthOverride`; WebGL1
typed-array overloads validate the view byte length; PBO overloads still defer
the exact compressed byte count to command-buffer/ANGLE validation. No
pre-`loadimage_*` OOB read/write or stale upload primitive was found.

### Rejected Lead: PVRTC/ETC1 3D/2D-Array Storage Mismatch

A follow-up WebGL-only pass checked the remaining target-specific compressed
edge: Blink lets WebGL2 callers reach `texStorage3D`,
`compressedTexImage3D`, and `compressedTexSubImage3D` with extension-exposed
compressed formats, while ANGLE rejects PVRTC on `TEXTURE_2D_ARRAY` and
rejects PVRTC/ETC1/ETC2 for `TEXTURE_3D`.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778617149-94e3c3a782c1/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.1203`, and 0 findings.
- Persisted scan `59c5eb9d-4cd8-45d6-945c-79ae251ec8c3` completed with
  0 findings.

Killed as no-submit. The validating decoder does have a state-consistency smell:
`TexStorageImpl` records immutable texture-manager levels before calling
`glTexStorage3D`, and Chrome's `ValidateCompressedFormatTarget` does not reject
PVRTC/ETC1 for all of the same 3D/2D-array targets that ANGLE rejects. That
does not become a WebGL memory-safety primitive in the checked paths. Direct
`compressedTexImage3D` only calls `SetLevelInfo` after `LOCAL_PEEK_GL_ERROR`
reports success, passthrough `TexStorage3D` updates size only after its error
callback stays clean, and later compressed subimage validation still
range-checks ArrayBuffer/PBO bytes before forwarding to ANGLE/native GL. The
stale validating-decoder storage state can at most lead to backend validation
errors or benign zero-clearing attempts; no path was found where attacker data
is read, a backend allocation is overrun, or an upload reaches ANGLE's
`loadimage_*` conversion with mismatched bounds.

### Rejected Lead: WebGL2 Compressed PBO 3D Format Gate

A narrow pass checked the WebGL2 PBO overloads of `compressedTexImage3D` and
`compressedTexSubImage3D`. Unlike the ArrayBuffer overloads, these PBO overloads
do not call Blink's `ValidateCompressedTexFormat` before forwarding the raw
`internalformat`/`format` enum to the GLES2 client.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778617350-53791da5857d/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.09315`, and 0 findings.
- Persisted scan `4600c2a8-b997-4b15-a9c2-1650d8cdb1a7` completed with
  0 findings.

Killed as no-submit. The omission can let the service, not Blink, become the
first compressed-format gate for those PBO 3D overloads. The service gate still
requires `validators_->compressed_texture_format`, rejects negative
`imageSize`, computes the exact compressed byte count with checked block math,
and range-checks the PBO offset/size before issuing the GL call. Native-only or
service-only compressed formats therefore collapse to extension/conformance
behavior or backend validation errors. No path was found where a raw GLenum
bypass causes Chrome to read outside the PBO, mis-size a shared-memory span, or
stage attacker-controlled bytes with a different format geometry before ANGLE or
native GL validation runs.

### Rejected Lead: WebGL2 Compressed PBO 2D Format Gate

A follow-up pass checked the 2D PBO overloads of `compressedTexImage2D` and
`compressedTexSubImage2D`. These overloads also forward directly to
`ContextGL()` without Blink-side `ValidateTexture2DBinding` or
`ValidateCompressedTexFormat`, unlike the ArrayBuffer overloads.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778617507-cc8fe2a8b848/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.10837`, and 0 findings.
- Persisted scan `f80db285-a850-49f9-a937-b924a2370a2a` completed with
  0 findings.

Killed as no-submit. This is the same service-first validation shape as the
3D PBO overloads. Chrome's validating decoder checks the texture target,
service compressed-format validator, nonnegative `imageSize`, exact compressed
byte count, and PBO/shared-memory range before the GL call. The passthrough
decoder rejects malformed shared-memory spans and leaves PBO byte validation to
the ANGLE/native compressed upload validation. The remaining effect is
extension-gating or WebGL conformance drift, not a pre-`loadimage_*` OOB read,
OOB write, stale initialized GPU upload, or backend staging-size mismatch.

### Rejected Lead: ANGLE D3D Compressed Upload Staging Mismatch

A backend-specific pass checked ANGLE's D3D compressed texture upload and copy
paths, after Blink/WebGL validation but before compressed bytes reach
`loadimage_*` conversion helpers:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778617588-5e643787386a/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.122135`, and 0 findings.
- Persisted scan `32b6ae85-1e72-4e2d-b4e6-150e643b9d84` completed with
  0 findings.

Killed as no-submit. `TextureD3D::{setCompressedImageImpl,subImageCompressed}`
derive the CPU pointer through `GetUnpackPointer`, then pass full or subimage
areas into `ImageD3D::loadCompressedData`. The D3D 2D-array wrappers compute a
per-layer compressed depth pitch and add that as a layer offset, but this is the
same block-geometry model validated by ANGLE's compressed image-size checks.
The backend methods ignore their `imageSize` parameter directly and rely on
front-end validation, but no divergence was found where validated bytes are
smaller than the layer iteration, PBO offset, or D3D load area. No pre-loader
OOB read/write or stale upload primitive was identified.

### Rejected Lead: ANGLE Metal Compressed Upload Staging Mismatch

A matching backend-specific pass checked ANGLE's Metal compressed texture
upload and copy paths, again after Blink/WebGL validation but before compressed
bytes reach `loadimage_*` conversion helpers:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778617670-8e91875433aa/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.09607`, and 0 findings.
- Persisted scan `fe44b4eb-3bbc-446f-bebc-82bdb7ad8a03` completed with
  0 findings.

Killed as no-submit. `TextureMtl::setCompressedImage` and
`setCompressedSubImage` route through the common Metal image upload helpers
with the compressed format metadata. Those helpers compute compressed
row/depth pitch through the same `InternalFormat` block geometry used by ANGLE
validation and use checked math for compressed image sizes and staging buffers.
When Metal must decompress because intended and actual formats differ, that
work is the explicitly excluded `loadimage_*` conversion boundary. No
pre-loader mismatch was found where accepted `imageSize` bytes become a larger
Metal staging read/write or a stale initialized upload.

### Rejected Lead: ANGLE GL Compressed Upload And Storage Emulation

A final backend-specific pass checked ANGLE's GL backend compressed upload path
and immutable compressed storage emulation. The adjacent WGPU backend compressed
methods were spot-checked first and are no-op stubs in this tree, so the scan
focused on GL:

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778617736-6881fb3bc030/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.09973`, and 0 findings.
- Persisted scan `d183b481-4728-4bf7-9e30-04ad271a7a34` completed with
  0 findings.

Killed as no-submit. `TextureGL::setCompressedImage` and
`setCompressedSubImage` translate to native compressed formats, set GL unpack
state, and forward the already-validated `imageSize` to native
`glCompressedTexImage*`/`glCompressedTexSubImage*`. The immutable-storage
emulation path uses checked `computeCompressedImageSize` for each level/face
before issuing null-data compressed image allocation calls. No path was found
where Blink/ANGLE validation accepts one compressed byte range but GL backend
translation, target selection, or emulated storage consumes a larger/different
range before native validation.

### Rejected Lead: WebGL2 Compressed TexStorage2D State Split

A storage-specific pass checked `texStorage2D` with compressed internal formats.
Blink's WebGL2 method forwards the raw `internalformat` to the GLES2 client, and
Chrome's validating decoder can accept extension-enabled compressed storage
formats and write texture-manager immutable level metadata before the backend
`glTexStorage2D` call.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778617831-395d6f97a6cc/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.12557`, and 0 findings.
- Persisted scan `f499d41c-6a78-436e-ba4b-2686ed41da19` completed with
  0 findings.

Killed as no-submit. The validating decoder checks the texture target, compressed
storage format, level count, dimensions, checked compressed level sizes, and
texture immutability before recording levels. ANGLE rejects compressed rectangle
storage and validates compressed image size for 2D/cube targets. Passthrough
updates size only after its error callback is clean. The stale-state shape found
earlier for `texStorage3D` does not become an exploitable `texStorage2D` path:
later compressed subimage clears/uploads still validate exact compressed size
and PBO/shared-memory bounds before native/ANGLE upload.

### Rejected Lead: CopyTextureCHROMIUM Compressed Texture Copy Reachability

A compressed-adjacent pass checked whether Blink WebGL could route compressed
textures through `CopyTextureCHROMIUM`, `CopySubTextureCHROMIUM`, media/canvas
GPU `texImage` fast paths, or ANGLE's `GL_CHROMIUM_copy_compressed_texture`
entry point.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778618013-c5e398e99cc6/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.10144`, and 0 findings.
- Persisted scan `bba18d1e-672f-4e03-b20e-c7a0a14ef5cd` completed with
  0 findings.

Killed as no-submit. Blink rejects compressed internal formats on the normal
`texImage*` source path with "compressed texture formats are not accepted".
The command-buffer `CopyTextureCHROMIUM`/`CopySubTextureCHROMIUM` validators use
`ValidateCopyTextureCHROMIUMInternalFormats`, whose source and destination
whitelists contain only uncompressed formats. Chromium's command-buffer tree has
no exposed `CompressedCopyTextureCHROMIUM` command; the matching ANGLE entry
point is an ANGLE extension surface and not reachable from Blink WebGL in this
path. No compressed source/destination can reach backend copy code through this
surface.

### Rejected Lead: WebGL2 Compressed ArrayBuffer Source Window

A focused pass checked WebGL2's `srcOffset`/`srcLengthOverride` overloads for
compressed `ArrayBufferView` uploads. This is the non-PBO caller-byte path where
Blink chooses a source window before the GLES2 client serializes the command.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778618124-36b99beae767/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.100005`, and 0 findings.
- Persisted scan `7f36b1eb-bc7c-49e0-ac6a-5f9737dc1d24` completed with
  0 findings.

Killed as no-submit. `ExtractDataLengthIfValid<GLuint>` rejects ArrayBuffer
views whose byte length cannot fit the `GLuint` source-window arithmetic.
Blink rejects `srcOffset > data_length`, clamps default `srcLengthOverride == 0`
to the remaining bytes, and rejects explicit overrides larger than that
remaining range before taking `ByteSpanMaybeShared().subspan(src_offset)`.
The GLES2 client then copies exactly `image_size == srcLengthOverride` bytes
into the bucket for non-PBO uploads, and the service/ANGLE compressed validators
still require exact compressed image sizes. No mismatched span was found.

### Rejected Lead: WebGLOnWebGPU Compressed Upload Path

The experimental WebGL-on-WebGPU implementation was spot-checked as an alternate
backend path. `WebGLRenderingContextWebGPUBase` has WebGL1/WebGL2 compressed
upload overload declarations, but every compressed `TexImage`/`TexSubImage`
implementation in the file is currently `NOTIMPLEMENTED()`. That makes it a
feature gap or context error surface, not a compressed upload path that can
reach WebGPU/Dawn memory handling with attacker-controlled compressed bytes.

### Rejected Lead: Compressed TexStorage Clear-State Ordering

A clear-state pass checked whether compressed immutable levels created by
`texStorage2D`/`texStorage3D` could be marked cleared before a backend clear or
partial compressed upload failed, exposing uninitialized texture contents.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778618330-e9d294592b47/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.080815`, and 0 findings.
- Persisted scan `a639e044-34b0-46fa-8fb9-8b9a6bc05bab` completed with
  0 findings.

Killed as no-submit. The interesting local shape is that
`Texture::ClearLevel` clears compressed immutable levels through
`ClearCompressedTextureLevel*`, and full-level subimages mark the level cleared
before the backend subimage call. That does not become a WebGL leak path in the
reachable compressed upload matrix: `texStorage*` first accepts only storage
formats in the service validator, checks compressed target/dimensions and
estimated level sizes, and WebGL2 ETC/EAC exposure aligns with native/ANGLE
support rather than the ES2 decompression-only fallback. Later partial
compressed subimage still validates the exact compressed byte size and target
region before any clear/upload. Remaining failure cases are backend/driver GL
errors after valid commands, not a browser-side attacker-controlled
validation/backend mismatch.

### Rejected Lead: BPTC/RGTC Mip-Level Strictness Split

A final dimension-rule pass checked BPTC/RGTC full compressed image uploads at
nonzero mip levels. Chrome's service-side `ValidateCompressedTexDimensions`
requires BPTC/RGTC width/height to be multiples of four only at level 0, while
ANGLE's WebGL validation uses `ValidCompressedBaseLevel(width << level)` to
enforce a stricter base-level multiple-of-four rule.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778618466-4d4a20b3d8f0/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.105555`, and 0 findings.
- Persisted scan `50baecea-265b-49d8-9224-dad818b67fea` completed with
  0 findings.

Killed as no-submit. The mismatch is a validation strictness difference, not a
memory primitive. Chrome still computes the compressed byte count with checked
ceil(block) math, and full compressed image uploads only call
`TextureManager::SetLevelInfo` after `LOCAL_PEEK_GL_ERROR` reports
`GL_NO_ERROR`. On ANGLE-backed paths the stricter ANGLE validator rejects before
backend upload; on native paths that accept the dimensions, the consumed byte
range is still the exact checked compressed size. No stale metadata,
uninitialized sampling, or larger backend read was found.

### Rejected Lead: ASTC 2D Format On WebGL2 3D Upload

An ASTC target-rule pass checked WebGL2 `compressedTexImage3D` with ASTC LDR
2D block formats. Blink's `WEBGL_compressed_texture_astc` extension adds the
2D ASTC format constants, and the direct WebGL2 upload path only checks
compressed-format membership before forwarding. Chrome's `TexStorage` path has
an explicit ASTC 3D/HDR gate; the direct `DoCompressedTexImage` path instead
relies on `ValidateCompressedFormatTarget` and backend validation.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778618530-2772cbb56730/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.105315`, and 0 findings.
- Persisted scan `742931c3-9da0-43c7-aae3-91d71b932e4b` completed with
  0 findings.

Killed as no-submit. ANGLE's ES3 validator rejects ASTC 2D formats for
`TEXTURE_3D` unless ASTC HDR or sliced-3D support is exposed. In the validating
decoder, direct compressed image uploads still compute exact checked
compressed sizes, call the backend, and only record `SetLevelInfo` after
`LOCAL_PEEK_GL_ERROR` returns `GL_NO_ERROR`. Rejection therefore leaves no stale
Chrome texture state; acceptance on a backend that genuinely supports the
target is a valid native upload with the exact byte range. No pre-loader memory
safety primitive was found.

### Rejected Lead: Compressed Command Serialization Width

A command-bridge pass checked whether Blink's validated compressed source byte
count could change while crossing the GLES2 client, generated command structs,
bucket commands, or service handlers.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778618625-74fb257c5d54/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.117075`, and 0 findings.
- Persisted scan `34b4106c-479f-4686-91a2-3eb6ea2f1cc1` completed with
  0 findings.

Killed as no-submit. Non-PBO compressed uploads either copy exactly the
validated `image_size` bytes into a bucket or reject before serialization.
Bucket commands carry only the bucket id; service handlers use the bucket's
actual `uint32_t` size as `image_size`. PBO and shared-memory commands preserve
`imageSize` as a signed 32-bit field and service handlers reject negative sizes
before range validation or backend upload. The generated 2D/3D command layouts
preserve target, level, offsets, dimensions, format, and `imageSize` without a
field-width mismatch that can make the service or ANGLE read a larger/different
compressed byte range.

### Rejected Lead: Compressed Size Arithmetic And Range Helpers

A service-side arithmetic pass checked whether compressed image byte-size
calculation, subimage range validation, or texture level bookkeeping could let
the service accept one source range while ANGLE or the backend consumes a
larger/different compressed byte range.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778618870-1f9b4823b75f/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.17273`, and 0 findings.
- Persisted scan `2d38fa6a-9aef-4d27-84b8-763c4dda2dfe` completed with
  0 findings.

Killed as no-submit. `GetCompressedTexSizeInBytes` uses checked arithmetic for
ceil(block) width/height, block byte count, and depth multiplication, and both
the direct upload validator and texture estimated-size bookkeeping use that
same helper. `Texture::ValidForTexture` checks `x/y/z + width/height/depth`
with `base::CheckAdd` before compressed subimage block-alignment helpers run.
The S3TC/ASTC helper has a suspicious redundant `width - xoffset > tex_width`
shape, but it is pre-gated by the checked `Texture::ValidForTexture` range
check in the only decoder upload path. `TexStorage` estimates all mip sizes
with checked accumulation before mutating immutable texture state, and
shared-image compressed initial data uses the same dimension and exact-size
helpers. No exploitable pre-loader arithmetic or stale-state split was found.

### Rejected Lead: WebGL2 Uncompressed PBO Pixel-Store Source Window

A WebGL follow-up pass moved from compressed uploads to uncompressed WebGL2
texture upload plumbing, checking whether Blink or the GLES2 client could
validate one ArrayBuffer/PBO range while the service or ANGLE consumed another
because of `UNPACK_ROW_LENGTH`, `UNPACK_IMAGE_HEIGHT`, `UNPACK_SKIP_*`,
alignment, row pitch, or depth pitch.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778619084-725a768a8d33/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.147325`, and 0 findings.
- Persisted scan `ab09fbcf-71e9-427e-a8cc-89d47859d5be` completed with
  0 findings.

Killed as no-submit. The GLES2 client computes client source size and skip
bytes through `ComputeImageDataSizesES3`, rejects checked size overflows, and
adds PBO skip bytes to offsets with checked arithmetic before command
serialization. Client transfer-buffer upload paths reject ES3 unpack skip/row
state rather than forwarding partially-applied state. When the service receives
PBO-backed uploads, `ValidateTexImage`/`ValidateTexSubImage` recompute the range
from `ContextState::GetUnpackParams`, check `offset + pixels_size` against the
bound unpack buffer, and only then enter row/alignment workaround paths. Those
workarounds operate on already-validated byte ranges; the unsigned padding
underflow-looking checks are pre-gated by the buffer-size validation. No
ArrayBuffer/PBO range split was found.

### Rejected Lead: WebGL2 ReadPixels Pack/PBO Destination Window

A readback pass checked whether WebGL2 `readPixels` could validate one DOM
ArrayBufferView or `PIXEL_PACK_BUFFER` destination range while the GLES2
service, passthrough decoder, native GL, or ANGLE wrote a larger/different
range because of pack row length, pack skip, alignment, framebuffer clipping,
async readback staging, or row-by-row workarounds.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778619211-3e9579159db0/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.17974`, and 0 findings.
- Persisted scan `546e08de-e905-46e5-9a79-7c64d9042bff` completed with
  0 findings.

Killed as no-submit. Blink computes `bytes_required + skip_bytes` before
reading into DOM views or PBO offsets, and the WebGL2 PBO overload rejects
negative/out-of-range offsets before forwarding. The GLES2 client keeps
`PACK_SKIP_*` client-side only: DOM readbacks add skip bytes when copying into
the caller buffer, while PBO readbacks fold skip into the command offset and do
not send skip state to the service. The service therefore validates PBO
`offset + size` with `pack_skip_* == 0`, honors row-length/alignment state, and
clips out-of-framebuffer reads before reporting `row_length`/`num_rows` to the
client. The negative-`x` leading-byte adjustment is bounded by the clipped
service result; fully off-left/offscreen reads return no successful rows. No
destination-range write primitive was found.

### Rejected Lead: Passthrough Compressed Error-Callback State Update

A passthrough-decoder pass checked whether compressed `TexImage` failures could
leave Chrome-side texture bookkeeping ahead of native GL/ANGLE validation,
especially around PVRTC zero dimensions, ASTC 2D formats on 3D targets,
BPTC/RGTC mip strictness, PBO offset-only spans, negative `imageSize`, and
bucket-size versus command-size differences.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778619590-d49cc21b1c46/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.136`, and 0 findings.
- Persisted scan `b434fb1d-9c42-40b2-b9be-cc5abec3d84b` completed with
  0 findings.

Killed as no-submit. Passthrough compressed `TexImage2D/3D` doers call
`CheckErrorCallbackState()`, issue the native compressed upload, and only call
`UpdateTextureSizeFromTarget()` if the GL debug callback did not report an API
error. Passthrough initialization requires `GL_KHR_debug` and installs
`PassthroughGLDebugMessageCallback`, whose API-error path flushes `glGetError`
into the decoder error set. The post-success update queries
`GL_MEMORY_SIZE_ANGLE` and writes only `TexturePassthrough::estimated_size`;
it does not maintain validating-decoder `Texture::LevelInfo` used for upload
range validation. Non-PBO data is bounded by shared-memory size or bucket size,
PBO data is represented as an offset-only span and left to ANGLE/native GL
validation, and compressed subimage passthroughs do not update texture size.
No WebGL-reachable stale validation state or pre-loader byte-range split was
found.

### Rejected Lead: WebGL Draw Input Validation First Pass

A first draw-input pass checked whether Blink/GLES2 validates one vertex or
element-array range while ANGLE or a backend can read a larger/different range
through `drawArrays`, `drawElements`, instancing, base-vertex/base-instance,
`WEBGL_multi_draw`, VAO enabled attribute masks, transform feedback state, or
cached index ranges.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778619711-54a8746630ea/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.18559`, and 0 findings.
- Persisted scan `bfbc5e82-7ebe-4ceb-9b04-8e4984b83741` completed with
  0 findings.

Killed as no-submit for the validation/serialization layer covered by this
pass. Blink rejects invalid draw offsets and validates multidraw array bounds
before forwarding. GLES2 multidraw handlers compute every shared-memory array
size with `base::CheckedNumeric<uint32_t>` from `drawcount` and reject missing
or short arrays. `CheckMultiDrawArraysVertices` rejects negative `first`,
`count`, and `primcount`, then checks `first + count - 1` with checked
arithmetic. `CheckMultiDrawElementsVertices` calls
`Buffer::GetMaxValueForRange`, which validates
`offset + count * sizeof(index)` and alignment against the element-array shadow
buffer before scanning max index. `VertexAttribManager::ValidateBindings`
then calls `CanAccess` for the max vertex, instance divisor, base vertex, and
base instance. The signed/unsigned-looking base-vertex path feeds this
pre-draw bounds check and over-rejects when it underflows rather than allowing a
backend read past a validated attribute buffer. No first-pass WebGL draw range
split was found.

### Rejected Lead: ANGLE D3D Draw Conversion

A D3D backend pass checked whether ANGLE's D3D9/D3D11 vertex or index
translation can consume more source bytes than the WebGL validation layer
approved, especially through `VertexDataManager`, `IndexDataManager`,
`IndexBuffer`, `VertexBuffer`, `BufferD3D`, line-loop/triangle-fan conversion,
primitive-restart conversion, client-side arrays, and base-vertex/base-instance
emulation.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778619894-cbfbe6221974/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.163635`, and 0 findings.
- Persisted scan `b8dd88df-3f71-4dd0-a322-4b4917a056c5` completed with
  0 findings.

Killed as no-submit for this backend slice. `IndexDataManager` either binds a
validated aligned index buffer directly or streams exactly `count` translated
indices; `StreamInIndexBuffer` rejects destination-size overflow before mapping,
and the static-buffer path is guarded by the prevalidated `offset + count *
sizeof(index)` invariant. `VertexDataManager` computes attribute byte windows
from `ComputeVertexAttributeOffset`, `ComputeVertexAttributeStride`, and
`ComputeVertexAttributeTypeSize` through checked arithmetic before reserving or
copying dynamic/static vertex data. The visible conversion helpers do not
introduce a second larger source range after the front-door draw and attribute
validators approve a range. No D3D backend read-range split was found.

### Rejected Lead: Ordinary CopyTexImage Into Compressed Texture State

A compressed-adjacent copy pass checked ordinary WebGL `copyTexImage2D`,
`copyTexSubImage2D`, and WebGL2 `copyTexSubImage3D`, distinct from the earlier
`CopyTextureCHROMIUM` pass. The goal was to see whether an existing compressed
texture level, immutable compressed storage, compressed requested
`internalformat`, cube/2D-array target, or read-framebuffer copy could reach
backend copy code and write a larger/different region or mark stale initialized
compressed state before validation rejects it.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778620051-408f5f679bf5/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.13467`, and 0 findings.
- Persisted scan `8c6def01-5aca-4a0e-922e-f461ce5e4d32` completed with
  0 findings.

Killed as no-submit. Blink's `copyTexImage2D` first checks
`ValidateCopyTexFormat`, whose allowlist is the ordinary renderable copy
internal-format set and not the compressed texture extension set.
`copyTexSubImage2D` and `copyTexSubImage3D` do not carry a new compressed
`internalformat`, but the command-buffer decoder fetches the existing texture
level's format and runs `ValidateCopyTexFormat` before issuing any GL copy.
ANGLE's `ValidateCopyTexImageParametersBase` independently rejects copy
destinations whose format info is depth, compressed, or paletted. The 2D
decoder marks cleared state only after `LOCAL_PEEK_GL_ERROR` reports success;
the 3D decoder may clear an uncleared level before copying, but that zeroes the
level rather than preserving attacker-controlled stale data. No ordinary
copy-into-compressed WebGL path reaches backend copy code with a compressed
destination or creates a stale initialized upload primitive.

### Rejected Lead: GenerateMipmap On Compressed Texture State

A focused compressed-mipmap pass checked whether `generateMipmap` can be called
on compressed texture levels, immutable compressed storage, or cube-map faces in
a way that reaches backend mip generation or marks generated mip state before
validation rejects the texture.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778620267-002d45c8cf33/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.084535`, and 0 findings.
- Persisted scan `467574ba-ab54-4911-a469-b7663eb95c31` completed with
  0 findings.

Killed as no-submit. Blink's `generateMipmap` only checks that the target has a
texture binding before forwarding the command, but the command-buffer decoder
calls `TextureManager::CanGenerateMipmaps` before clearing any base level or
calling `glGenerateMipmapEXT`. That gate rejects any face whose base-level
`internal_format` is a registered compressed texture format, along with
depth/stencil, zero-size WebGL, incomplete cube, and unsupported filter/render
cases. `MarkMipmapsGenerated` is called only after the GL call reports
`GL_NO_ERROR`. ANGLE's `ValidateGenerateMipmapBase` has the same defense in
the native path: base formats that are `GL_NONE`, compressed, paletted, depth,
or stencil are rejected before generation. No compressed mipmap path reaches a
backend generator or stale generated-mip state update.

### Rejected Lead: Final Compressed Texture API-Surface Audit

A final bounded inventory pass mapped the Blink WebGL/WebGL2 texture
storage/content surface against command-buffer and ANGLE validators. The pass
explicitly covered compressed uploads, ordinary uploads and subimage uploads,
TexStorage, ordinary copyTex paths, `CopyTextureCHROMIUM`, `generateMipmap`,
framebuffer attachment paths, pixel-store upload state, readPixels/PBO state
where it can affect texture validation, WebGLOnWebGPU mirrors, and backend
compressed staging paths.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778620351-41c566a61827/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.1205`, and 0 findings.
- Persisted scan `9f83f70f-1844-4079-b311-d7193bdc477e` completed with
  0 findings.

Killed as no-submit for the active compressed-texture objective. The remaining
surface inventory did not identify an unlogged Blink entry point that can carry
or mutate compressed texture data/state before command-buffer and ANGLE
compressed/copy/storage/mipmap validation. The broad compressed upload pass and
the follow-up narrow passes now cover the visible routes into `loadimage_*`,
backend staging, compressed immutable storage, copy, mip generation, and
passthrough state update.

### Rejected Lead: Uncompressed WebGL Texture Upload First Pass

After exhausting compressed texture coverage, a bounded pivot checked
uncompressed WebGL `texImage*` and `texSubImage*` uploads from
`ArrayBufferView`, PBO offsets, `ImageData`, `HTMLImageElement`, canvas,
`OffscreenCanvas`, `HTMLVideoElement`, `VideoFrame`, and `ImageBitmap` sources
into ANGLE `loadimage_*` and GL backend upload code. The pass focused on
source extraction and row math disagreements involving flip-y, premultiply
alpha, unpack alignment, row length, image height, skip rows/pixels/images,
WebGL2 3D/depth uploads, command-buffer end-byte checks, and ANGLE
row-pitch/skip-byte conversion.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778620513-6705ef65de5e/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.13835000000000003`, and
  0 findings.
- Persisted scan `de0a0450-06bb-4e95-8c85-288ce20f6874` completed with
  0 findings.

Killed as no-submit for the first uncompressed upload sweep. The scan did not
identify a Blink `WebGLImageConversion`/source extraction range that diverges
from command-buffer unpack validation or ANGLE `loadimage_*` row-pitch handling
into an out-of-bounds source or destination primitive. This is a first-pass
pivot result, not the same exhausted confidence level as the compressed texture
track.

### Rejected Lead: GPU-Backed Media And Canvas Upload Fast Paths

A narrower WebGL pivot checked GPU-backed upload/copy paths that may bypass the
ordinary CPU `WebGLImageConversion` route: `VideoFrame`,
`HTMLVideoElement`, `ImageBitmap`, canvas/`OffscreenCanvas`,
`AcceleratedStaticBitmapImage`, shared-image/mailbox sources,
`CopyVideoFrameTexturesToGLTextureViaIntermediateSI`,
`CopySharedImageToGLTexture`, and `CopySubTextureCHROMIUM` /
`CopyTextureCHROMIUM` bridges.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778620614-36f08be61994/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.15307500000000002`, and
  0 findings.
- Persisted scan `7883c44c-eb4f-423c-87a6-79632c286d15` completed with
  0 findings.

Killed as no-submit for this first fast-path slice. The scan did not identify a
VRP-grade source-rectangle, visible-rect/coded-size, shared-image
format/alpha, sync-token/lifetime, destination texture state, or
flip-y/premultiply mismatch that would let WebGL GPU-backed media/canvas
uploads read or write outside validated bounds or copy stale protected pixels.

### Rejected Lead: Older ASTC `loadimage_*` Pitch Findings

The existing `.kuzushi` findings database contains 11 older findings. Seven are
outside the active WebGL compressed-texture target (`base/*` and WebNN). The
four compressed-texture-adjacent entries are duplicates from persisted scan
`cca5862d-76a3-479f-8ae9-135410fe8285`, run
`/workspaces/targets/chromium-src/.kuzushi/runs/run-1778605044-999c8867fec8/`:

- `astc-input-pitch-oob-read`
- `astc-output-pitch-oob-write`
- `astc-input-depth-pitch-oob-read`
- `astc-output-depth-pitch-oob-write`

Rejected for the Chrome WebGL objective. These findings are inside
`third_party/angle/src/image_util/loadimage_astc.cpp`, so they are not a
Blink-vs-ANGLE mismatch before data reaches `loadimage_*`. They also do not
survive caller reachability review as a VRP-grade Chrome WebGL primitive:
compressed input pitch is computed by `InternalFormat::computeRowPitch` /
`computeDepthPitch`, which route compressed formats through
`computeCompressedImageRowPitch` / `computeCompressedImageDepthPitch`; the
validated compressed `imageSize` uses the same block-count math through
`computeCompressedImageSize`. D3D and Vulkan conversion callers either map a
destination resource whose row/depth pitch is exact-or-larger, or allocate a
conversion/staging buffer from `width * 4` and `height`. No reviewed WebGL path
lets script provide a shorter `inputDepthPitch`, `outputRowPitch`, or
`outputDepthPitch` to `LoadASTCToRGBA8Inner`.

### Rejected Lead: Full-Level Compressed Subimage Cleared-State Ordering

A sharper follow-up checked a validating-decoder state-ordering concern: in
`DoCompressedTexSubImage`, a full-level upload into an uncleared immutable
compressed texture level can mark the level cleared before the backend
`glCompressedTexSubImage*` or ETC fallback upload. Unlike
`DoCompressedTexImage`, this path does not gate a texture-manager state update
on a later `LOCAL_PEEK_GL_ERROR`.

- `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778621048-40295acf824c/`
  contains `input.json`, `result.json`, `summary.json`, and `trace.jsonl`.
- The run reported `status=complete`, target
  `/workspaces/targets/chromium-src`, cost `0.105545`, and 0 findings.
- Persisted scan `358eb0da-eb24-4d72-bc79-2eefdf07b036` completed with
  0 findings.

Killed as no-submit. The reviewed mismatch shape requires both stale
texture-manager state and a later readable stale/uninitialized backend
allocation. The checked paths still do not expose that primitive: compressed
subimage validation requires an existing level, exact compressed `imageSize`,
valid target/format dimensions, and PBO/shared-memory range checks before the
state mark. Known compressed target mismatches either fail storage/allocation
and leave no readable backend image, become ordinary backend GL errors, force a
zero-clear path for partial uploads, or lose the context on failed ETC/EAC
fallback decompression. No path was found where script data or uninitialized
storage becomes readable after the pre-call cleared-state mark.

### Rejected Lead: GLES2 Client Compressed Upload Bridge

The GLES2 client serializer was checked as the remaining compressed-texture
surface not included in the exact broad prompt. `GLES2Implementation` routes
client-pointer compressed uploads through exact-size buckets, and routes
PBO/transfer-buffer uploads through `GetBoundPixelTransferBufferIfValid`, which
checks `offset + image_size` and shared-memory offset arithmetic before sending
the command. The pointer-as-offset path still uses `ToGLuint(data)`, but in
this API family that only truncates the caller-supplied PBO offset before the
service-side range validation; it does not create a larger service read.

The service bucket handlers do not turn this into a separate primitive. Bucket
size is capped at 1 GiB, bucket data is zero-initialized and range-checked, and
bucket commands feed the same `DoCompressedTexImage*` /
`DoCompressedTexSubImage*` validators or the passthrough ANGLE/native GL upload
path. No client/service split was found where a WebGL ArrayBuffer, bucket, PBO
offset, or transfer-buffer command can desynchronize `imageSize` from the
validated compressed dimensions.

### Rejected Lead: Mechanical Compressed Enum Cross-Check

A final low-memory enum comparison parsed Blink's compressed-extension
registration files and compared the WebGL-exposed compressed format set against
Chrome's service compressed helpers and ANGLE's compressed format tables. After
expanding Blink's ASTC loop and normalizing known S3TC aliases (`NV`/`EXT` and
DXT3/DXT5 `EXT`/`ANGLE` names), Blink exposes 59 compressed format constants.

Rejected as no-submit. The normalized Blink set has no missing entries in
`gpu/command_buffer/service/gl_utils.cc` compressed size/target cases,
`third_party/angle/src/libANGLE/renderer/Format_table_autogen.cpp`, or
ANGLE's `AddCompressedFormat` table in
`third_party/angle/src/libANGLE/formatutils.cpp`. The only spelling
differences are known numeric aliases, not size-table or backend-validation
gaps.

### Recommended Next Goal

The active compressed-texture objective is now exhausted with 0 findings across
the broad Blink/ANGLE pass, passthrough compressed upload, compressed storage,
ordinary copy, `generateMipmap`, WebGLOnWebGPU, backend staging, PBO/source
window, pixel-store, zero-size, GLES2 client serialization, mechanical enum
cross-check, and final API-surface audit tracks. Do not rerun the
compressed-texture prompts unless Chromium has changed.

If continuing WebGL, keep the pivot narrow. The next target should be the
single most suspicious GPU-backed media/canvas path from the fast-path
inventory rather than another all-texture sweep. The older stored Kuzushi
findings have now been triaged for relevance to the compressed-texture goal;
the current WebGL continuation added no new findings.

### Completion Audit: Active Compressed-Texture Objective

Objective restated: find a Chrome VRP-worthy WebGL compressed texture
validation/backend mismatch between Blink and ANGLE, before bytes reach
`loadimage_*`, yielding an OOB read/write or stale/uninitialized GPU upload
primitive. Coverage deliverables were the requested bounded scan plus concrete
evidence for ArrayBufferView/PBO `imageSize`, 2D-array/depth, skip state,
ASTC/ETC extension gates, WebGL unpack flags, premultiply paths, robust access
wrappers, backend staging, and visible compressed API entry points.

Prompt-to-artifact checklist:

- Requested bounded scan: run
  `/workspaces/targets/chromium-src/.kuzushi/runs/run-1778616755-31936fe3ecea/`
  has the exact requested model, include patterns, `passes=2`,
  `maxInventoryFiles=90`, `maxBytesPerFile=32768`, and hunt focus; result
  persisted scan `39eda7d4-de2a-4aa7-b0cb-b26fe1fa22ed` with 0 findings.
- Broad Blink/ANGLE compressed upload baseline: runs
  `run-1778605948-a395c7ce920a` and `run-1778606167-b49f53a055b6` completed
  with 0 findings and are logged above.
- Source-window and byte-count requirements: WebGL1/WebGL2
  ArrayBufferView, `srcOffset`/`srcLengthOverride`, PBO offset, negative
  `GLsizei imageSize`, transfer-buffer, bucket, and command-serialization paths
  are logged under their rejected leads above.
- Target/depth requirements: cube, 3D, 2D-array, ASTC-on-3D, PVRTC/ETC
  storage, and mip-level strictness paths are logged under rejected leads above.
- Extension-gate requirements: ASTC/ETC/S3TC/PVRTC plus BPTC/RGTC and
  service-only/native-only format gaps were checked; remaining effects were
  conformance or backend validation, not a memory-safety primitive.
- WebGL unpack and robust-access requirements: `UNPACK_FLIP_Y_WEBGL`,
  premultiply/colorspace state, WebGL2 unpack skips, generated robust wrappers,
  and `bufSize`/`imageSize` split were checked and rejected as non-primitives.
- Backend and pre-`loadimage_*` requirements: validating decoder, passthrough,
  ANGLE Vulkan/D3D/Metal/GL staging, `TexStorage`, copy, mipmap, clear-state,
  WebGLOnWebGPU mirrors, and GLES2 client serialization are logged above.
- Format-table consistency: the mechanical enum cross-check above verified that
  all 59 Blink-exposed compressed formats are present in Chrome service and
  ANGLE compressed size/format tables after known alias normalization.
- Current persisted state: the `.kuzushi` findings database has 75 completed
  scan rows and 11 stored findings total. None are a confirmed active-objective
  finding: seven are unrelated older `base/*` or WebNN findings, and four are
  older ASTC `loadimage_*` pitch findings rejected above for this objective.

Audit result: coverage is complete enough to stop rerunning compressed-texture
prompts on this checkout, but the goal itself is not achieved because no
Chrome VRP-worthy pre-`loadimage_*` compressed WebGL finding was confirmed.
