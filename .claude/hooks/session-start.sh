#!/bin/bash
# SessionStart hook: ensure Kuzushi's offense engine has an isolating sandbox
# backend. Live `offense:chain` runs send traffic with curl inside
# kuzushi-sandbox; with bwrap/podman present that traffic is namespace-isolated
# from the host, and findings record backend=bwrap instead of the unsandboxed
# `plain` fallback (which raises a warning for non-loopback targets).
#
# Idempotent and non-fatal: skips when an isolating backend already exists, and
# never fails session start if the install cannot run.
set -uo pipefail

# Only needed in the ephemeral remote (web) container; local machines keep
# whatever the operator installed.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

if command -v bwrap >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
  echo "session-start: isolating sandbox backend already present" >&2
  exit 0
fi

install_bubblewrap() {
  command -v apt-get >/dev/null 2>&1 || return 1
  local sudo=""
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    sudo="sudo"
  fi
  DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y bubblewrap >/dev/null 2>&1
}

if install_bubblewrap && command -v bwrap >/dev/null 2>&1; then
  echo "session-start: installed bubblewrap ($(bwrap --version 2>/dev/null))" >&2
else
  echo "session-start: could not install bubblewrap; offense:chain will use the Plain backend (loopback targets only)" >&2
fi
exit 0
