#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
if [[ $EUID -ne 0 ]]; then echo "请使用 root 或 sudo 运行。" >&2; exit 1; fi
if [[ "${1:-}" == "--purge" && ( -e /etc/portbridge/tls || -L /etc/portbridge/tls ) && ( -e /etc/portbridge-tls/legacy-config-tls || -L /etc/portbridge-tls/legacy-config-tls ) ]]; then
  echo "TLS 保留目标 /etc/portbridge-tls/legacy-config-tls 已存在；拒绝覆盖，请先处理。" >&2
  exit 1
fi
if systemctl list-unit-files portbridge.service --no-legend 2>/dev/null | grep -q portbridge.service; then
  systemctl stop portbridge.service
  systemctl is-active --quiet portbridge.service && { echo "portbridge.service 仍在运行，拒绝卸载。" >&2; exit 1; }
  systemctl disable portbridge.service >/dev/null
fi
if pgrep -u portbridge -x portbridge >/dev/null 2>&1; then
  echo "仍有 portbridge 进程运行，拒绝卸载。" >&2
  exit 1
fi
if command -v ss >/dev/null 2>&1 && ss -H -ltnup 2>/dev/null | grep -Fq portbridge; then
  echo "仍有 portbridge 监听端口，拒绝卸载。" >&2
  exit 1
fi
if [[ -x /usr/local/bin/portbridge ]]; then
  /usr/local/bin/portbridge --cleanup-nft
fi
rm -f /etc/systemd/system/portbridge.service /usr/local/bin/portbridge /etc/sysctl.d/90-portbridge.conf
systemctl daemon-reload
if [[ "${1:-}" == "--purge" ]]; then
  if [[ -e /etc/portbridge/tls || -L /etc/portbridge/tls ]]; then
    [[ ! -L /etc/portbridge-tls ]] || { echo "/etc/portbridge-tls 不能是符号链接。" >&2; exit 1; }
    install -d -o root -g root -m 0700 /etc/portbridge-tls
    mv -- /etc/portbridge/tls /etc/portbridge-tls/legacy-config-tls
  fi
  rm -rf /etc/portbridge /etc/default/portbridge /usr/share/doc/portbridge
  userdel portbridge 2>/dev/null || true
  groupdel portbridge 2>/dev/null || true
  echo "程序和配置均已删除。TLS 材料仍保留在 /etc/portbridge-tls，如不再需要请单独删除。"
else
  echo "程序已删除；配置保留在 /etc/portbridge。使用 --purge 可一并删除。"
fi
