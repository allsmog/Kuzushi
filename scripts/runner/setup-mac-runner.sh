#!/usr/bin/env bash
# Install the Kuzushi self-hosted GitHub Actions runner on this Mac.
#
# THE REPOSITORY OWNER RUNS THIS, NOT CI AND NOT AN AGENT. It creates a macOS
# user, downloads a release tarball, provisions toolchains, and installs a
# system LaunchDaemon.
#
#   sudo bash scripts/runner/setup-mac-runner.sh --dry-run   # print, touch nothing
#   sudo bash scripts/runner/setup-mac-runner.sh             # install
#   sudo bash scripts/runner/setup-mac-runner.sh --set-pat   # store/rotate the PAT
#
# It is idempotent: every step checks for its own result first, so a rerun
# after a partial failure (or after bumping RUNNER_VERSION below) converges
# instead of duplicating anything.
#
# A LaunchDaemon, not a LaunchAgent, on purpose. An agent runs only while its
# user holds a launchd GUI session, so on a laptop CI would stop silently
# whenever nobody is logged in as the runner user. A daemon runs from boot,
# with `UserName` dropping it to the unprivileged service account.
#
# What it deliberately does NOT do:
#   - grant the runner user admin rights, sudo, or Full Disk Access
#   - register the runner with GitHub (the ephemeral loop does that, per job)
#   - put the PAT on a command line or in shell history (see --set-pat)
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
LOOP_SCRIPT="${RUNNER_DIR}/run-ephemeral-loop.sh"
LOG_DIR="${RUNNER_HOME}/Library/Logs"
SECRET_DIR="${RUNNER_HOME}/.config/kuzushi-runner"
SECRET_FILE="${SECRET_DIR}/pat"

DAEMON_LABEL="com.kuzushi.runner"
DAEMON_PLIST="/Library/LaunchDaemons/${DAEMON_LABEL}.plist"

# Daemons inherit a minimal environment, so PATH is stated in full. The runner
# user's own cargo shims come first; Homebrew supplies actionlint, node, and
# pnpm.
DAEMON_PATH="${RUNNER_HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

DRY_RUN=0
MODE="install"

usage() {
  cat <<'USAGE'
Usage: sudo bash scripts/runner/setup-mac-runner.sh [--dry-run | --set-pat]

  (no flag)   install the runner, toolchains, and LaunchDaemon
  --dry-run   print the generated plist and every command, change nothing
  --set-pat   prompt for the fine-grained PAT and store it 0600, then exit
USAGE
}

for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=1 ;;
    --set-pat) MODE="set-pat" ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: ${arg}" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# In dry-run every line is prefixed, so no message can read as if the step
# already happened.
log() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '==> [dry-run] %s\n' "$*"
  else
    printf '==> %s\n' "$*"
  fi
}

# Every system-mutating command goes through this, so --dry-run is honest by
# construction rather than by remembering to guard each call site.
run() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '    [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

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

# The toolchain channel is read from the repository rather than duplicated
# here, so the runner user cannot drift from what CI compiles with.
rust_channel() {
  sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "${repo_root}/rust-toolchain.toml" | head -n 1
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
    log "user ${RUNNER_USER} already exists"
    return
  fi
  local uid
  uid="$(next_free_uid)"
  log "creating non-admin user ${RUNNER_USER} (uid ${uid})"
  # No -admin flag: the account gets no sudo rights. `-password -` leaves the
  # account without a usable password, so it cannot be logged into
  # interactively or over SSH.
  run sysadminctl -addUser "${RUNNER_USER}" \
    -UID "${uid}" \
    -fullName "Kuzushi CI runner" \
    -home "${RUNNER_HOME}" \
    -shell /bin/bash \
    -password -
  # Keep the account out of the login window and Fast User Switching.
  run dscl . -create "/Users/${RUNNER_USER}" IsHidden 1
}

verify_not_admin() {
  if [ "${DRY_RUN}" -eq 1 ] && ! id "${RUNNER_USER}" >/dev/null 2>&1; then
    log "${RUNNER_USER} does not exist yet; admin check deferred"
    return
  fi
  if dseditgroup -o checkmember -m "${RUNNER_USER}" admin >/dev/null 2>&1; then
    echo "${RUNNER_USER} is in the admin group. Remove it before continuing:" >&2
    echo "  sudo dseditgroup -o edit -d ${RUNNER_USER} -t user admin" >&2
    exit 1
  fi
  log "${RUNNER_USER} is not an admin"
}

install_runner_tarball() {
  if [ -x "${RUNNER_DIR}/config.sh" ] && [ -f "${RUNNER_DIR}/.kuzushi-runner-version" ] &&
    [ "$(cat "${RUNNER_DIR}/.kuzushi-runner-version")" = "${RUNNER_VERSION}" ]; then
    log "actions/runner ${RUNNER_VERSION} already installed"
    return
  fi
  if [ "${DRY_RUN}" -eq 1 ]; then
    log "would download ${RUNNER_URL}"
    log "would verify SHA-256 ${RUNNER_SHA256}"
    log "would extract into ${RUNNER_DIR}"
    return
  fi

  local staging
  staging="$(mktemp -d)"
  trap 'rm -rf "${staging}"' RETURN

  log "downloading actions/runner ${RUNNER_VERSION}"
  curl --fail --location --silent --show-error \
    --output "${staging}/${RUNNER_TARBALL}" "${RUNNER_URL}"

  log "verifying SHA-256"
  echo "${RUNNER_SHA256}  ${staging}/${RUNNER_TARBALL}" | shasum -a 256 --check --status || {
    echo "checksum mismatch for ${RUNNER_TARBALL}; refusing to install" >&2
    exit 1
  }

  mkdir -p "${RUNNER_DIR}"
  tar -xzf "${staging}/${RUNNER_TARBALL}" -C "${RUNNER_DIR}"
  printf '%s\n' "${RUNNER_VERSION}" >"${RUNNER_DIR}/.kuzushi-runner-version"
  log "installed actions/runner ${RUNNER_VERSION} into ${RUNNER_DIR}"
}

install_loop_script() {
  run mkdir -p "${RUNNER_DIR}"
  run install -m 0755 "${script_dir}/run-ephemeral-loop.sh" "${LOOP_SCRIPT}"
  log "installed ${LOOP_SCRIPT}"
}

# The secret is a plain 0600 file owned by the service account. A Keychain item
# would need that user's login Keychain unlocked, which a headless daemon
# cannot guarantee -- see README.md for what this costs.
create_secret_dir() {
  run install -d -m 0700 -o "${RUNNER_USER}" -g staff "${SECRET_DIR}"
  log "secret directory ${SECRET_DIR} (0700)"
}

# The runner user needs its own toolchains: CI jobs run as _ghrunner and cannot
# read the owner's ~/.rustup or ~/.cargo.
provision_runner_toolchain() {
  local channel
  channel="$(rust_channel)"
  log "provisioning Rust ${channel} for ${RUNNER_USER}"

  if ! command -v rustup >/dev/null 2>&1; then
    log "rustup is not on PATH. Install it system-wide first: brew install rustup"
    log "then rerun this script."
    [ "${DRY_RUN}" -eq 1 ] || return 0
  fi

  # rust-toolchain.toml pins the components, but the runner user needs the
  # toolchain present before a job starts so the first run is not a download.
  run sudo -u "${RUNNER_USER}" -H rustup toolchain install "${channel}" \
    --component clippy --component rustfmt --component llvm-tools-preview
  run sudo -u "${RUNNER_USER}" -H rustup default "${channel}"

  for tool in node pnpm actionlint; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
      log "WARNING: ${tool} is not on PATH. CI needs it: brew install ${tool}"
    fi
  done
}

render_plist() {
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${DAEMON_LABEL}</string>
  <key>UserName</key><string>${RUNNER_USER}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${LOOP_SCRIPT}</string>
  </array>
  <key>WorkingDirectory</key><string>${RUNNER_DIR}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Standard</string>
  <key>StandardOutPath</key><string>${LOG_DIR}/${DAEMON_LABEL}.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/${DAEMON_LABEL}.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>${RUNNER_HOME}</string>
    <key>PATH</key><string>${DAEMON_PATH}</string>
    <key>KUZUSHI_RUNNER_REPO</key><string>allsmog/Kuzushi</string>
    <key>KUZUSHI_RUNNER_NAME</key><string>kuzushi-mac-1</string>
  </dict>
</dict>
</plist>
PLIST
}

install_launch_daemon() {
  run install -d -m 0700 -o "${RUNNER_USER}" -g staff "${LOG_DIR}"
  if [ "${DRY_RUN}" -eq 1 ]; then
    local preview
    preview="$(mktemp -t kuzushi-runner-plist)"
    render_plist >"${preview}"
    log "would write ${DAEMON_PLIST} (root:wheel 0644):"
    echo
    cat "${preview}"
    echo
    plutil -lint "${preview}"
    rm -f "${preview}"
    log "would run: launchctl bootout system/${DAEMON_LABEL}"
    log "would run: launchctl bootstrap system ${DAEMON_PLIST}"
    log "would run: launchctl enable system/${DAEMON_LABEL}"
    return
  fi
  render_plist >"${DAEMON_PLIST}"
  chown root:wheel "${DAEMON_PLIST}"
  chmod 0644 "${DAEMON_PLIST}"
  plutil -lint "${DAEMON_PLIST}"
  log "wrote ${DAEMON_PLIST}"
}

start_launch_daemon() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    return
  fi
  # bootout first so a rerun reloads a changed plist instead of keeping the
  # old one resident.
  launchctl bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
  launchctl bootstrap system "${DAEMON_PLIST}"
  launchctl enable "system/${DAEMON_LABEL}"
  log "LaunchDaemon ${DAEMON_LABEL} bootstrapped"
}

fix_ownership() {
  run chown -R "${RUNNER_USER}:staff" "${RUNNER_HOME}"
  run chmod 700 "${RUNNER_HOME}"
  run chmod 700 "${SECRET_DIR}"
}

# Reads the PAT from the terminal with `read -rs`: it never appears in argv,
# in shell history, or on screen. `install -m 0600` creates the file with
# restrictive permissions from the start, never briefly world-readable.
set_pat() {
  require_root
  local pat
  printf 'Paste the fine-grained PAT (input hidden), then press Enter: '
  IFS= read -rs pat
  printf '\n'
  if [ -z "${pat}" ]; then
    echo "no token entered; nothing written" >&2
    exit 1
  fi
  install -d -m 0700 -o "${RUNNER_USER}" -g staff "${SECRET_DIR}"
  printf '%s\n' "${pat}" |
    install -m 0600 -o "${RUNNER_USER}" -g staff /dev/stdin "${SECRET_FILE}"
  unset pat
  log "wrote ${SECRET_FILE} (0600, owner ${RUNNER_USER})"
  log "the daemon picks up the new token on its next loop pass; force it with:"
  log "  sudo launchctl kickstart -k system/${DAEMON_LABEL}"
}

print_next_steps() {
  cat <<NEXT

Installed. One step remains, and it is deliberately separate because it
handles the credential:

  sudo bash scripts/runner/setup-mac-runner.sh --set-pat

The PAT needs exactly one permission: repository allsmog/Kuzushi ->
Administration: Read and write. Nothing else.

Verify from your own account:

  gh api /repos/allsmog/Kuzushi/actions/runners --jq '.runners[] | {name, status, labels: [.labels[].name]}'
  sudo launchctl print system/${DAEMON_LABEL} | head -20

Logs: ${LOG_DIR}/${DAEMON_LABEL}.log
Teardown and the threat model live in scripts/runner/README.md.
NEXT
}

if [ "${MODE}" = "set-pat" ]; then
  set_pat
  exit 0
fi

[ "${DRY_RUN}" -eq 1 ] || require_root
require_apple_silicon
create_runner_user
verify_not_admin
install_runner_tarball
install_loop_script
create_secret_dir
provision_runner_toolchain
install_launch_daemon
fix_ownership
start_launch_daemon
[ "${DRY_RUN}" -eq 1 ] || print_next_steps
