#!/usr/bin/env bash
# One ephemeral GitHub Actions runner registration per job, forever.
#
# This is the LaunchDaemon's target (see setup-mac-runner.sh). Each pass:
#   1. mints a short-lived registration token from the GitHub API, using a
#      fine-grained PAT read out of a 0600 file owned by this user
#   2. configures a fresh `--ephemeral` runner
#   3. runs it until it has executed exactly one job, then exits
#   4. wipes the work directory and repeats
#
# `--ephemeral` is the security property that matters: a job cannot leave
# state behind for the next one, because the registration is consumed and the
# work tree is deleted. The PAT never reaches the log or the process table: it
# is read from a 0600 file into a shell local and handed to curl on stdin.
#
# This runs as a LaunchDaemon under `UserName=_ghrunner`, so there is no GUI
# session and no unlocked login Keychain to read from. The secret file is that
# trade, made explicitly -- see README.md.
set -euo pipefail

REPO="${KUZUSHI_RUNNER_REPO:-allsmog/Kuzushi}"
RUNNER_NAME="${KUZUSHI_RUNNER_NAME:-kuzushi-mac-1}"
RUNNER_LABELS="${KUZUSHI_RUNNER_LABELS:-kuzushi-mac}"
RUNNER_DIR="${KUZUSHI_RUNNER_DIR:-${HOME}/actions-runner}"
WORK_DIR="_work"
SECRET_FILE="${KUZUSHI_RUNNER_PAT_FILE:-${HOME}/.config/kuzushi-runner/pat}"
# Long enough that a GitHub outage does not become a request flood, short
# enough that the runner is back within a coffee break.
RETRY_SECONDS="${KUZUSHI_RUNNER_RETRY_SECONDS:-30}"

cd "${RUNNER_DIR}"

log() {
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

# Reads the PAT from its 0600 file. Never echo the result. Reading it on every
# pass rather than once at startup is what makes rotation work: overwrite the
# file and the next loop pass uses the new token, no daemon restart needed.
read_pat() {
  local pat
  [ -r "${SECRET_FILE}" ] || return 1
  IFS= read -r pat <"${SECRET_FILE}" || return 1
  printf '%s' "${pat}"
}

# Mints a registration token. Prints ONLY the token on stdout; every
# diagnostic goes to stderr so a failure cannot leak the credential into a
# log line. `--fail-with-body` keeps the HTTP error visible without the
# request headers.
mint_registration_token() {
  local pat response token
  pat="$(read_pat)" || {
    log "cannot read ${SECRET_FILE}; run setup-mac-runner.sh --set-pat" >&2
    return 1
  }
  if [ -z "${pat}" ]; then
    log "${SECRET_FILE} is empty; run setup-mac-runner.sh --set-pat" >&2
    return 1
  fi

  response="$(
    printf 'Authorization: Bearer %s\n' "${pat}" |
      curl --fail-with-body --silent --show-error \
        --request POST \
        --header @- \
        --header "Accept: application/vnd.github+json" \
        --header "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${REPO}/actions/runners/registration-token"
  )" || {
    log "registration-token request failed" >&2
    return 1
  }
  unset pat

  token="$(printf '%s' "${response}" |
    sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [ -z "${token}" ]; then
    log "registration-token response carried no token" >&2
    return 1
  fi
  printf '%s' "${token}"
}

# config.sh only accepts the token as an argument, so it is briefly visible in
# this user's own process list. That is a registration token, not the PAT: it
# expires in an hour, only registers a runner, and is consumed by the
# `--ephemeral` registration it creates. The PAT itself never reaches argv.
configure_runner() {
  local token="$1"
  ./config.sh \
    --unattended \
    --ephemeral \
    --replace \
    --url "https://github.com/${REPO}" \
    --token "${token}" \
    --labels "${RUNNER_LABELS}" \
    --name "${RUNNER_NAME}" \
    --work "${WORK_DIR}" \
    >/dev/null
}

wipe_work_dir() {
  rm -rf "${WORK_DIR:?}"
  # `_diag` accumulates per-job runner logs; keep the tree genuinely clean.
  rm -rf "${RUNNER_DIR}/_diag"
}

run_one_job() {
  local token
  token="$(mint_registration_token)" || return 1
  configure_runner "${token}" || {
    unset token
    log "config.sh failed"
    return 1
  }
  unset token
  log "registered ${RUNNER_NAME} (${RUNNER_LABELS}); waiting for one job"
  ./run.sh || log "run.sh exited non-zero"
}

trap 'log "stopping"; exit 0' TERM INT

log "ephemeral runner loop starting in ${RUNNER_DIR} for ${REPO}"
while true; do
  wipe_work_dir
  if ! run_one_job; then
    log "pass failed; retrying in ${RETRY_SECONDS}s"
  fi
  wipe_work_dir
  sleep "${RETRY_SECONDS}"
done
