#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
if [[ $EUID -ne 0 ]]; then echo "Run this script as root or with sudo." >&2; exit 1; fi
if [[ "${1:-}" == "--purge" && ( -e /etc/portbridge/tls || -L /etc/portbridge/tls ) && ( -e /etc/portbridge-tls/legacy-config-tls || -L /etc/portbridge-tls/legacy-config-tls ) ]]; then
  echo "TLS retention target /etc/portbridge-tls/legacy-config-tls already exists; refusing to overwrite it." >&2
  exit 1
fi
if systemctl list-unit-files portbridge.service --no-legend 2>/dev/null | grep -q portbridge.service; then
  systemctl stop portbridge.service
  systemctl is-active --quiet portbridge.service && { echo "portbridge.service is still active; refusing to uninstall." >&2; exit 1; }
  systemctl disable portbridge.service >/dev/null
fi
if pgrep -u portbridge -x portbridge >/dev/null 2>&1; then
  echo "A portbridge process is still running; refusing to uninstall." >&2
  exit 1
fi
if command -v ss >/dev/null 2>&1 && ss -H -ltnup 2>/dev/null | grep -Fq portbridge; then
  echo "A portbridge listener is still present; refusing to uninstall." >&2
  exit 1
fi
if [[ -x /usr/local/bin/portbridge ]]; then
  /usr/local/bin/portbridge --cleanup-nft
fi
rm -f /etc/systemd/system/portbridge.service /usr/local/bin/portbridge /etc/sysctl.d/90-portbridge.conf
systemctl daemon-reload
if [[ "${1:-}" == "--purge" ]]; then
  if [[ -e /etc/portbridge/tls || -L /etc/portbridge/tls ]]; then
    [[ ! -L /etc/portbridge-tls ]] || { echo "/etc/portbridge-tls must not be a symbolic link." >&2; exit 1; }
    install -d -o root -g root -m 0700 /etc/portbridge-tls
    mv -- /etc/portbridge/tls /etc/portbridge-tls/legacy-config-tls
  fi
  rm -rf /etc/portbridge /etc/default/portbridge /usr/share/doc/portbridge
  userdel portbridge 2>/dev/null || true
  groupdel portbridge 2>/dev/null || true
  echo "Program and configuration removed. TLS material remains in /etc/portbridge-tls and must be removed separately if no longer needed."
else
  echo "Program removed; configuration retained in /etc/portbridge. Use --purge to remove it too."
fi
