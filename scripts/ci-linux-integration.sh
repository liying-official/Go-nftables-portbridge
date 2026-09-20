#!/usr/bin/env bash
# Adapt the verifier's manual-release boundary, never a failed runtime gate.
set -euo pipefail
umask 077
GO_BIN=${1:-}
[[ $EUID == 0 ]] || { echo 'CI ERROR: isolated kernel tests require root.' >&2; exit 2; }
[[ $GO_BIN == /* && -x $GO_BIN ]] || { echo 'CI ERROR: supply an absolute executable Go path.' >&2; exit 2; }
[[ $("$GO_BIN" version) == 'go version go1.27.1 linux/amd64' ]] || { echo 'CI ERROR: Go 1.27.1 linux/amd64 is required.' >&2; exit 2; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
LOG_DIR=${PB_CI_LOG_DIR:-"$ROOT/ci-evidence"}
[[ $LOG_DIR == "$ROOT/ci-evidence" && ! -L $LOG_DIR ]] || { echo 'CI ERROR: log directory must be the workspace ci-evidence directory, not a symlink.' >&2; exit 2; }
if [[ -e $LOG_DIR ]]; then
  [[ -d $LOG_DIR && -z $(find "$LOG_DIR" -mindepth 1 -maxdepth 1 -print -quit) ]] || { echo 'CI ERROR: refusing to overwrite an existing nonempty log directory.' >&2; exit 2; }
else
  mkdir -m 0700 -- "$LOG_DIR"
fi
# Invoked indirectly by the EXIT trap, including early failure paths.
# shellcheck disable=SC2317
finish() {
  chmod u+rwX,go+rX "$LOG_DIR"
  find "$LOG_DIR" -maxdepth 1 -type f -exec chmod 0644 {} +
  if [[ ${SUDO_UID:-} =~ ^[0-9]+$ && ${SUDO_GID:-} =~ ^[0-9]+$ ]]; then
    chown -- "${SUDO_UID}:${SUDO_GID}" "$LOG_DIR"
    find "$LOG_DIR" -maxdepth 1 -type f -exec chown -- "${SUDO_UID}:${SUDO_GID}" {} +
  fi
}
trap 'finish' EXIT
LOG_FILE="$LOG_DIR/verify-candidate.log"
set +e
/bin/bash "$ROOT/scripts/verify-candidate.sh" "$GO_BIN" 2>&1 | tee "$LOG_FILE"
pipeline_status=("${PIPESTATUS[@]}")
set -e
rc=${pipeline_status[0]}
[[ ${pipeline_status[1]} == 0 ]] || { echo 'CI ERROR: log capture failed.' >&2; exit 1; }
evidence_path=$(sed -n 's/^Evidence and cache: \([^ ]*\) .*/\1/p' "$LOG_FILE")
[[ $evidence_path =~ ^/var/tmp/portbridge-verify\.[[:alnum:]]{6}$ && -d $evidence_path && ! -L $evidence_path ]] || { echo 'CI ERROR: missing or unexpected verifier evidence path.' >&2; exit 1; }
[[ $(stat -c %u -- "$evidence_path") == 0 ]] || { echo 'CI ERROR: evidence directory is not root-owned.' >&2; exit 1; }
expected_gates=(test-json race accept-independent accept-strict accept-race transparent-original transparent-strict transparent-race selective-unit selective-traffic transparent-fuzz-list transparent-fuzz vet build proxy-test-binary proxy-race-test-binary udp-interfaces udp-interfaces-race clean-go proc-subset boot-bind-component selection)
missing=0
for gate in "${expected_gates[@]}"; do
  exit_file="$evidence_path/$gate.exit"
  if [[ ! -f $exit_file || -L $exit_file ]] || [[ $(cat "$exit_file") != 0 ]] || [[ $(grep -Fxc "$gate exit=0" "$LOG_FILE" || true) != 1 ]]; then
    echo "CI ERROR: gate failed, missing or duplicated: $gate" >&2
    missing=1
  fi
  # Do not collect caches, executables, TLS/token fixtures or nested directories.
  for suffix in exit stdout stderr; do
    file="$evidence_path/$gate.$suffix"
    if [[ -f $file && ! -L $file ]]; then
      if (( $(stat -c %s -- "$file") <= 33554432 )); then
        cp -- "$file" "$LOG_DIR/$gate.$suffix"
      else
        echo "CI NOTE: omitted oversized result file: $gate.$suffix"
      fi
    fi
  done
done
terminal='BLOCKED: v2.4.9 bounded selective-ACL support does not certify arbitrary stateful/side-effecting firewall policies, actual reboot or the complete original-user systemd unit. This unsigned candidate is not release-approved.'
if [[ $rc == 2 && $missing == 0 ]] && grep -Fxq "Review logs in $evidence_path. Runtime validation is separate from release approval." "$LOG_FILE" && grep -Fxq "$terminal" "$LOG_FILE"; then
  echo 'CI PASS: all 22 runtime gates passed; the documented manual-release boundary is not release approval.'
  exit 0
fi
echo "CI ERROR: verifier did not reach the exact successful runtime boundary (exit=$rc)." >&2
exit 1
