#!/usr/bin/env bash
# Isolated boot-bind COMPONENT test; deliberately not a full ProcSubset claim.
set -euo pipefail
BIN=${1:?absolute compiled proxy test executable required}; shift
[[ $BIN == /* && -x $BIN ]] || exit 2
export PARENT_NET=$(readlink /proc/self/ns/net) PARENT_MNT=$(readlink /proc/self/ns/mnt)
unshare -Urnm true || { echo 'BLOCKED: user/mount/network namespaces unavailable'; exit 2; }
exec unshare -Urnm /bin/bash -c '
  set -euo pipefail
  trap '\''echo "BLOCKED: boot-bind component fixture setup failed" >&2; exit 2'\'' ERR
  [[ $(readlink /proc/self/ns/net) != "$PARENT_NET" && $(readlink /proc/self/ns/mnt) != "$PARENT_MNT" ]]
  mount --make-rprivate /
  mount -t tmpfs -o nosuid,nodev,noexec tmpfs /run
  touch /run/portbridge-boot-id
  mount --bind /proc/sys/kernel/random/boot_id /run/portbridge-boot-id
  mount -o remount,bind,ro /run/portbridge-boot-id
  mount -t tmpfs -o ro,nosuid,nodev,noexec tmpfs /proc/sys
  [[ ! -e /proc/sys/kernel/random/boot_id && -r /run/portbridge-boot-id ]]
  export PB_REVIEW_BOOT_BIND_COMPONENT=1
  trap - ERR
  echo ISOLATED_BOOT_BIND_COMPONENT_READY_NOT_FULL_SYSTEMD
  exec "$@"
' bash "$BIN" "$@"
