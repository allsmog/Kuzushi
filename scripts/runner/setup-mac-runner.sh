#!/usr/bin/env bash
# Install the Kuzushi self-hosted GitHub Actions runner on this Mac.
#
# THE REPOSITORY OWNER RUNS THIS, NOT CI AND NOT AN AGENT. It creates a
# macOS user, downloads a release tarball, and installs a launchd job.
#
#   sudo bash scripts/runner/setup-mac-runner.sh
#
# It is idempotent: every step checks for its own result first, so a rerun
# after a partial failure (or after bumping RUNNER_VERSION below) converges
# instead of duplicating anything.
#
# What it deliberately does NOT do:
#   - grant the runner user admin rights, sudo, or Full Disk Access
#   - store a token anywhere on disk (see run-ephemeral-loop.sh; the
#     fine-grained PAT lives only in the runner user's login Keychain)
#   - register the runner with GitHub (the ephemeral loop does that, per job)
#
# Read scripts/runner/README.md first. It carries the threat model, the exact
# PAT scope, and the teardown procedure.
set -euo pipefail

# Pinned from the actions/runner release notes checksum table:
#   gh api repos/actions/runner/releases/latest --jq .body
# Bump both values together; a mismatch aborts the install.
RUNNER_VERSION="2.337.0"
RUNNER_SHA256="5a2cd92908a93d7276a194e1de6008099f3e7946f3f8e14aa7a1a7b4a31fdec2"
RUNNER_TARBALL="actions-runner-osx-arm64-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_TARBALL}"

RUNNER_USER="_ghrunner"
RUNNER_HOME="/Users/${RUNNER_USER}"
RUNNER_DIR="${RUNNER_HOME}/actions-runner"
LAUNCH_LABEL="com.kuzushi.ghrunner"
LAUNCH_AGENT_DIR="${RUNNER_HOME}/Library/LaunchAgents"
LAUNCH_PLIST="${LAUNCH_AGENT_DIR}/${LAUNCH_LABEL}.plist"
LOOP_SCRIPT="${RUNNER_DIR}/run-ephemeral-loop.sh"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo: sudo bash scripts/runner/setup-mac-runner.sh" >&2
    exit 1
  fi
}

require_apple_silicon() {
  if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
    echo "This installer targets Apple-Silicon macOS only (found $(uname -s)/$(uname -m))." >&2
    exit 1
  fi
}

next_free_uid() {
  local uid=600
  while dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "${uid}"; do
    uid=$((uid + 1))
  done
  printf '%s' "${uid}"
}

create_runner_user() {
  if id "${RUNNER_USER}" >/dev/null 2>&1; then
    echo "user ${RUNNER_USER} already exists"
    return
  fi
  local uid
  uid="$(next_free_uid)"
  echo "creating non-admin user ${RUNNER_USER} (uid ${uid})"
  # No -admin flag: the account gets no sudo rights. `-password -` leaves the
  # account without a usable password, so it cannot be logged into
  # interactively or over SSH.
  sysadminctl -addUser "${RUNNER_USER}" \
    -UID "${uid}" \
    -fullName "Kuzushi CI runner" \
    -home "${RUNNER_HOME}" \
    -shell /bin/bash \
    -password -
  # Keep the account out of the login window and out of Fast User Switching.
  dscl . -create "/Users/${RUNNER_USER}" IsHidden 1
}

verify_not_admin() {
  if dseditgroup -o checkmember -m "${RUNNER_USER}" admin >/dev/null 2>&1; then
    echo "${RUNNER_USER} is in the admin group. Remove it before continuing:" >&2
    echo "  sudo dseditgroup -o edit -d ${RUNNER_USER} -t user admin" >&2
    exit 1
  fi
  echo "${RUNNER_USER} is not an admin"
}

install_runner_tarball() {
  if [ -x "${RUNNER_DIR}/config.sh" ] && [ -f "${RUNNER_DIR}/.kuzushi-runner-version" ] &&
    [ "$(cat "${RUNNER_DIR}/.kuzushi-runner-version")" = "${RUNNER_VERSION}" ]; then
    echo "actions/runner ${RUNNER_VERSION} already installed"
    return
  fi

  local staging
  staging="$(mktemp -d)"
  trap 'rm -rf "${staging}"' RETURN

  echo "downloading actions/runner ${RUNNER_VERSION}"
  curl --fail --location --silent --show-error \
    --output "${staging}/${RUNNER_TARBALL}" "${RUNNER_URL}"

  echo "verifying SHA-256"
  echo "${RUNNER_SHA256}  ${staging}/${RUNNER_TARBALL}" | shasum -a 256 --check --status || {
    echo "checksum mismatch for ${RUNNER_TARBALL}; refusing to install" >&2
    exit 1
  }

  mkdir -p "${RUNNER_DIR}"
  tar -xzf "${staging}/${RUNNER_TARBALL}" -C "${RUNNER_DIR}"
  printf '%s\n' "${RUNNER_VERSION}" >"${RUNNER_DIR}/.kuzushi-runner-version"
  echo "installed actions/runner ${RUNNER_VERSION} into ${RUNNER_DIR}"
}

install_loop_script() {
  install -m 0755 "${script_dir}/run-ephemeral-loop.sh" "${LOOP_SCRIPT}"
  echo "installed ${LOOP_SCRIPT}"
}

install_launch_agent() {
  mkdir -p "${LAUNCH_AGENT_DIR}" "${RUNNER_HOME}/Library/Logs"
  cat >"${LAUNCH_PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LAUNCH_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${LOOP_SCRIPT}</string>
  </array>
  <key>WorkingDirectory</key><string>${RUNNER_DIR}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Standard</string>
  <key>StandardOutPath</key><string>${RUNNER_HOME}/Library/Logs/${LAUNCH_LABEL}.log</string>
  <key>StandardErrorPath</key><string>${RUNNER_HOME}/Library/Logs/${LAUNCH_LABEL}.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>KUZUSHI_RUNNER_REPO</key><string>allsmog/Kuzushi</string>
    <key>KUZUSHI_RUNNER_NAME</key><string>kuzushi-mac-1</string>
  </dict>
</dict>
</plist>
PLIST
  echo "wrote ${LAUNCH_PLIST}"
}

fix_ownership() {
  chown -R "${RUNNER_USER}:staff" "${RUNNER_HOME}"
  chmod 700 "${RUNNER_HOME}"
}

print_next_steps() {
  local uid
  uid="$(id -u "${RUNNER_USER}")"
  cat <<NEXT

Installed. Two steps remain, and both are deliberately manual because they
handle the credential and the launchd session.

1. Store the fine-grained PAT in the runner user's login Keychain. Run it as
   that user so the secret never lands in your own Keychain or in a file:

     sudo -u ${RUNNER_USER} -i security add-generic-password \\
       -s kuzushi-runner-pat -a ${RUNNER_USER} -w

   The PAT needs exactly one permission: repository allsmog/Kuzushi ->
   Administration: Read and write. Nothing else.

2. Start the LaunchAgent in ${RUNNER_USER}'s session:

     sudo launchctl bootstrap gui/${uid} ${LAUNCH_PLIST}
     sudo launchctl enable gui/${uid}/${LAUNCH_LABEL}

   A LaunchAgent only runs while that user has a launchd GUI session. If the
   bootstrap above reports "Could not find domain", log in once as
   ${RUNNER_USER} (or enable auto-login for it) and rerun. This is a real
   constraint, not a formality: with no session, the runner is simply not
   running, and jobs queue instead of failing.

Verify from your own account:

  gh api /repos/allsmog/Kuzushi/actions/runners --jq '.runners[] | {name, status, labels: [.labels[].name]}'

Teardown and the threat model live in scripts/runner/README.md.
NEXT
}

require_root
require_apple_silicon
create_runner_user
verify_not_admin
install_runner_tarball
install_loop_script
install_launch_agent
fix_ownership
print_next_steps
