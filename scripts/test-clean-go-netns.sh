#!/usr/bin/env bash
# Test-only driver. Hide executable views only inside NEW mount+network
# namespaces; never rename/delete a host nft executable. Pass a compiled Go
# proxy test binary, not a production service binary.
set -euo pipefail
umask 077
binary=${1:?absolute proxy test binary required}; shift
[[ $binary == /* && -f $binary && -x $binary ]] || { echo "Invalid test binary" >&2; exit 2; }
for tool in /usr/bin/unshare /usr/bin/readlink /usr/bin/mount /usr/sbin/ip; do
 [[ -x $tool ]] || { echo "BLOCKED: missing isolated-test prerequisite $tool" >&2; exit 2; }
done
parent_net=$(/usr/bin/readlink /proc/self/ns/net)
parent_mount=$(/usr/bin/readlink /proc/self/ns/mnt)
/usr/bin/unshare -Urnm true || { echo "BLOCKED: user/mount/network namespace creation unavailable" >&2; exit 2; }
exec /usr/bin/unshare -Urnm /bin/bash -c '
set -euo pipefail
ready=0
trap '\''rc=$?; if [[ $ready != 1 ]]; then echo "BLOCKED: isolated executable view setup failed" >&2; exit 2; fi; exit "$rc"'\'' EXIT
parent_net=$1; parent_mount=$2; binary=$3; shift 3
[[ $(/usr/bin/readlink /proc/self/ns/net) != "$parent_net" && $(/usr/bin/readlink /proc/self/ns/mnt) != "$parent_mount" ]]
/usr/bin/mount --make-rprivate /
/usr/sbin/ip link set lo up
/usr/sbin/ip -6 addr add 2001:db8:55::1/128 dev lo nodad
/usr/sbin/ip -6 addr add 2001:db8:55::2/128 dev lo nodad
# Both trusted fixed nft paths now provably do not exist in this process view.
/usr/bin/mount -t tmpfs -o ro,nosuid,nodev,noexec tmpfs /usr/sbin
/usr/bin/mount -t tmpfs -o ro,nosuid,nodev,noexec tmpfs /usr/bin
export PB_REVIEW_CLEAN_NETNS=1 PB_REVIEW_PARENT_NS="$parent_net" PB_V245_IPV6_MULTI=1
ready=1
echo "ISOLATED_CLI_VIEW_READY (parent/child network and mount identities verified)"
exec "$binary" "$@"
' bash "$parent_net" "$parent_mount" "$binary" "$@"
