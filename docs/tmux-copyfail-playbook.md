# Running Kuzushi TUI in tmux for Linux kernel "Copy Fail" style hunting

This playbook is a reproducible path for running the Rust TUI shell under tmux,
using OpenAI OAuth, and scanning Linux kernel targets for
AF_ALG/splice/page-cache style privilege-escalation bugs (the class behind
"Copy Fail").

## 1) Preconditions (Linux host)

- `tmux` installed.
- Rust toolchain + cargo available.
- Network egress for model/provider calls.
- OAuth credential file at `~/.kuzushi/oauth-credentials.json` containing an
  OpenAI token bag. The manual migration below writes the runtime
  compatibility key for older pi-agent-core provider routing.

If you only have `/home/claude/.codex/remote/.oauth_token`, copy it once:

```bash
mkdir -p ~/.kuzushi
python3 - <<'PY'
import json, pathlib
src = pathlib.Path('/home/claude/.codex/remote/.oauth_token')
out = pathlib.Path.home()/'.kuzushi'/'oauth-credentials.json'
tok = src.read_text().strip()
out.write_text(json.dumps({"openai-codex":{"access":tok}}, indent=2)+"\n")
print(out)
PY
```

## 2) Build and smoke-check the Rust shell

```bash
cargo run -p kuzushi-cli -- --help
cargo run -p kuzushi-cli -- auth ping --model openai:gpt-5.5-mini
```

`auth ping` should report OAuth readiness and a successful round-trip before
starting long scans.

## 3) Launch tmux + shell (open source target)

Use one pane for interactive TUI and one pane for logs.

```bash
tmux new-session -d -s kz-copyfail -c /path/to/linux
# optional split for monitoring log output
tmux split-window -t kz-copyfail:0 -v -c /path/to/linux

# run shell in pane 0 and tee logs
tmux send-keys -t kz-copyfail:0.0 \
  'cargo run -p kuzushi-cli -- shell --target /path/to/linux 2>&1 | tee /tmp/kuzushi-copyfail.log' C-m

tmux attach -t kz-copyfail
```

Inside the TUI, run this sequence:

1. `auth status`
2. `model 3`
3. `use core:sast` (or `modules` then pick the SAST module shown)
4. `scan /path/to/linux`

For this bug family, bias prompts toward syscall-reachable flows touching:

- `AF_ALG`/`algif_aead`/`authencesn`
- `splice`/`sendmsg`/`recvmsg`
- scatterlist aliasing (`req->src == req->dst`, `sg_chain`)
- writes into caller-controlled destination buffers used as scratch

## 4) Non-interactive fallback (CI-friendly)

If tmux key injection is flaky in your environment, keep tmux for session
management but run `kuzushi run` for deterministic execution:

```bash
cargo run -p kuzushi-cli -- --target /path/to/linux run core:sast:scan --input '{"focus":"linux crypto AF_ALG splice page-cache write primitive"}'
```

This uses the same Rust runtime/module pipeline without depending on terminal
key handling.

## 5) Triage checklist for Copy-Fail-like findings

- Confirm user-controlled file page references can enter crypto TX SGL.
- Confirm any in-place or aliasing path mixes read-only references into
  writable destination chains.
- Confirm post-output scratch writes can land in chained pages.
- Confirm failure path does not roll back side effects.
- Validate exploitability across distros by checking semantics rather than
  offsets only.

## 6) Quick troubleshooting

- OAuth not detected: verify `~/.kuzushi/oauth-credentials.json` readability.
  For direct file inspection, the OpenAI token bag may live under the
  compatibility key written by the migration snippet above.
- Missing module/tool name: run `tools` and use the exact `<module>:<action>`
  name exposed by the build.
- TUI seems idle: inspect `/tmp/kuzushi-copyfail.log` and run `auth ping`
  outside shell to isolate auth/runtime issues.

## 7) Validated command path (tested in this repo)

The following command sequence is known-good in this repository and mirrors a
Copy-Fail-style Rust workflow without relying on interactive key routing:

```bash
# 0) optional: install tmux if missing
sudo apt-get update && sudo apt-get install -y tmux

# 1) build CLI once
cargo run -p kuzushi-cli -- --help

# 2) inspect tools and confirm hunt tool availability
target/debug/kuzushi tools | rg 'full-mode:hunt|sast:scan|context:build'

# 3) build context (same runtime path shell/run/scan share)
target/debug/kuzushi --target /workspace/Kuzushi run context:build --input '{}'

# 4) run Copy-Fail-style hunt in cost-safe dry-run mode against a C fixture
target/debug/kuzushi \
  --target /workspace/Kuzushi/tests/fixtures/systems-hunt/resource-provenance-positive \
  run full-mode:hunt \
  --input '{"dryRun":true,"focus":"AF_ALG splice page-cache write primitive"}'
```

Expected result in step 4: a dry-run plan with chunk/file/token estimates and
no token spend. If you remove `dryRun`, you must configure role model routing
first (`roles.full_mode_multi`) or the run will fail with a model-config error.

## 8) Known runtime caveats

- `kuzushi auth ping --model openai:...` currently errors when the selected
  provider route is not available through the auth-ping bridge path.
- For OpenAI OAuth runs, configure model routing in `models.toml` (or shell
  `setg MODEL_*`) before launching non-dry LLM hunts. The adapter still
  translates OpenAI OAuth routing to the legacy pi-agent-core selector
  internally.
