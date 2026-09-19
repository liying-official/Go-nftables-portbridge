#!/usr/bin/env bash
# Read-only boot identity wiring, in NEW user/mount/PID/network namespaces only.
set -euo pipefail
BIN=${1:?absolute compiled proxy test executable required}; shift
[[ $BIN == /* && -x $BIN ]] || exit 2
PARENT_NET=$(readlink /proc/self/ns/net)
PARENT_MNT=$(readlink /proc/self/ns/mnt)
export PARENT_NET PARENT_MNT
unshare -Urnmp --fork true || { echo 'BLOCKED: user/mount/PID/network namespaces unavailable'; exit 2; }
exec unshare -Urnmp --fork /bin/bash -c '
  set -euo pipefail
  trap '\''echo "BLOCKED: ProcSubset identity fixture setup failed" >&2; exit 2'\'' ERR
  [[ $(readlink /proc/self/ns/net) != "$PARENT_NET" && $(readlink /proc/self/ns/mnt) != "$PARENT_MNT" ]]
  mount --make-rprivate /
  mount -t tmpfs -o nosuid,nodev,noexec tmpfs /run
  touch /run/portbridge-boot-id
  mount --bind /proc/sys/kernel/random/boot_id /run/portbridge-boot-id
  mount -o remount,bind,ro /run/portbridge-boot-id
  mount -t proc -o nosuid,nodev,noexec,subset=pid proc /proc
  [[ ! -e /proc/sys/kernel/random/boot_id && -r /run/portbridge-boot-id ]]
  export PB_REVIEW_PROC_SUBSET=1
  trap - ERR
  echo ISOLATED_PROC_SUBSET_READY
  exec "$@"
' bash "$BIN" "$@"
