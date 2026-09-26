#!/usr/bin/env bash
# Record in the job summary whether this runner actually exercised the
# isolating patch-validation sandbox.
#
# `SandboxBackend::detect_backend` (crates/kuzushi-sandbox/src/backend/mod.rs)
# resolves to `Plain` when neither `bwrap` nor `podman` is on PATH, and the
# sandbox tests stay green there on purpose: the argv builders are pure string
# assembly, and the one execution test branches on `which("bwrap")`. A green
# job on a runner without bubblewrap therefore proves less than the same job on
# Linux, and the summary has to say so instead of leaving the reader to assume.
set -euo pipefail

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

backend="none"
if command -v bwrap >/dev/null 2>&1; then
  backend="bwrap"
elif command -v podman >/dev/null 2>&1; then
  backend="podman"
fi

{
  echo "### Patch-validation sandbox coverage"
  echo
  echo "- Runner OS: \`${RUNNER_OS:-$(uname -s)}\`"
  echo "- Isolating backend on PATH: \`${backend}\`"
} >>"${summary}"

if [ "${backend}" = "none" ]; then
  {
    echo "- **Bubblewrap and AppArmor execution was NOT exercised on this runner.**"
    echo "  Kuzushi resolves \`SandboxBackend::Plain\`, so repository-execution"
    echo "  isolation is unproven by this run. Only a Linux runner"
    echo "  (the hosted default, or the monthly hosted sweep) covers it."
  } >>"${summary}"
  echo "::warning title=Sandbox isolation unproven::No isolating sandbox backend on PATH; bubblewrap/AppArmor execution was not exercised."
else
  echo "- Isolating backend present; repository-execution tests can exercise it." >>"${summary}"
fi
