#!/usr/bin/env bash
set -euo pipefail
umask 077

PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOW=""
NO_START=0
SHOW_TOKEN=0
TLS_CERT=""
TLS_KEY=""
TLS_NAMES=()

usage() {
  cat <<USAGE
用法: sudo ./scripts/install.sh [选项]
  --allow IP或CIDR[,更多]  为可信管理地址添加临时启动 ACL（不能替代公网 TLS）
  --tls-cert FILE        导入正式证书（必须同时提供 --tls-key）
  --tls-key FILE         导入对应私钥（源文件不修改）
  --tls-name DNS或IP      为自动生成的自签证书追加 SAN，可重复
  --no-start              安装后不立即启动服务
  --show-token            安装后将管理员令牌输出到终端（可能被部署日志记录）
USAGE
}

while (($#)); do
  case "$1" in
    --allow) ALLOW="${2:?缺少 IP/CIDR}"; shift 2 ;;
    --tls-cert) TLS_CERT="${2:?缺少证书路径}"; shift 2 ;;
    --tls-key) TLS_KEY="${2:?缺少私钥路径}"; shift 2 ;;
    --tls-name) TLS_NAMES+=("${2:?缺少证书 DNS/IP 名称}"); shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --show-token) SHOW_TOKEN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage; exit 2 ;;
  esac
done

# PORTBRIDGE_ARGS is expanded by systemd as command-line arguments. Limit the
# bootstrap ACL to IP/CIDR syntax before writing it to EnvironmentFile so
# whitespace, quotes, or newlines cannot inject extra arguments/assignments.
if [[ -n "$ALLOW" ]]; then
  if [[ ! "$ALLOW" =~ ^[0-9A-Fa-f:.,/]+$ || "$ALLOW" == ,* || "$ALLOW" == *, || "$ALLOW" == *,,* ]]; then
    echo "--allow 仅接受用逗号分隔的 IP 或 CIDR，不能包含空格、引号或控制字符。" >&2
    exit 2
  fi
fi

if [[ $EUID -ne 0 ]]; then
  echo "请使用 root 或 sudo 运行。" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) ARCH="" ;;
esac

BIN=""
PREBUILT=0
if [[ -n "$ARCH" && -x "$ROOT_DIR/dist/go-nftables-portbridge-linux-$ARCH" ]]; then
  BIN="$ROOT_DIR/dist/go-nftables-portbridge-linux-$ARCH"
	PREBUILT=1
elif [[ -n "$ARCH" && -x "$ROOT_DIR/dist/portbridge-linux-$ARCH" ]]; then
  BIN="$ROOT_DIR/dist/portbridge-linux-$ARCH"
	PREBUILT=1
else
  command -v go >/dev/null 2>&1 || { echo "源码安装需要 Go 1.27.1；预编译安装请使用已签名发布包。" >&2; exit 1; }
  [[ "$(go env GOVERSION)" == go1.27.1 ]] || { echo "源码安装要求精确使用 Go 1.27.1。" >&2; exit 1; }
  mkdir -p "$ROOT_DIR/build"
  VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"
  (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid= -X main.version=$VERSION" -o build/portbridge ./cmd/portbridge)
  BIN="$ROOT_DIR/build/portbridge"
fi

if [[ $PREBUILT -eq 1 ]]; then
  MANIFEST="$ROOT_DIR/release-bundle-manifest.json"
  SIGNATURE="$MANIFEST.sig"
  SIGNERS="$ROOT_DIR/packaging/release-signers"
  EXPECTED_RELEASE_SIGNER='portbridge-release-v2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVc6m1afFOM3gsLO6VXuLyAlHbkvBP83wlMEqArW/0k'
  EXPECTED_RELEASE_SIGNER_FINGERPRINT='SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o'
  if [[ ! -f "$MANIFEST" || ! -f "$SIGNATURE" ]]; then
    echo "预编译发布二进制必须带有已签名的 release-bundle 清单。" >&2
    exit 1
  fi
  command -v ssh-keygen >/dev/null 2>&1 || { echo "验证发布签名需要 ssh-keygen。" >&2; exit 1; }
  if [[ -L "$SIGNERS" || ! -f "$SIGNERS" || "$(LC_ALL=C stat -c %F -- "$SIGNERS" 2>/dev/null)" != "regular file" || "$(stat -c %h -- "$SIGNERS" 2>/dev/null)" != 1 ]]; then
    echo "发布签名者文件必须是包内唯一硬链接的常规文件，不能是符号链接。" >&2
    exit 1
  fi
  RELEASE_SIGNER_SIZE="$(stat -c %s -- "$SIGNERS" 2>/dev/null)"
  if [[ ! "$RELEASE_SIGNER_SIZE" =~ ^[0-9]+$ ]] || (( RELEASE_SIGNER_SIZE < ${#EXPECTED_RELEASE_SIGNER} || RELEASE_SIGNER_SIZE > ${#EXPECTED_RELEASE_SIGNER} + 1 )); then
    echo "发布签名者文件长度无效。" >&2
    exit 1
  fi
  mapfile -t RELEASE_SIGNER_LINES < "$SIGNERS"
  if [[ ${#RELEASE_SIGNER_LINES[@]} -ne 1 || "${RELEASE_SIGNER_LINES[0]}" != "$EXPECTED_RELEASE_SIGNER" ]]; then
    echo "发布签名者文件与安装器固定的可信公钥不一致。" >&2
    exit 1
  fi
  ACTUAL_RELEASE_SIGNER_FINGERPRINT="$(ssh-keygen -lf "$SIGNERS" -E sha256 2>/dev/null | awk 'NR == 1 {print $2}')"
  if [[ "$ACTUAL_RELEASE_SIGNER_FINGERPRINT" != "$EXPECTED_RELEASE_SIGNER_FINGERPRINT" ]]; then
    echo "发布签名者指纹与安装器固定的可信指纹不一致。" >&2
    exit 1
  fi
  ssh-keygen -Y verify -q -f "$SIGNERS" -I portbridge-release-v2 -n portbridge-release -s "$SIGNATURE" < "$MANIFEST" || {
    echo "发布包签名验证失败。" >&2; exit 1;
  }
  VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"
  SIGNED_VERSION="$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$MANIFEST")"
  SIGNED_REVISION="$(sed -n 's/^  "source_revision": "\([^"]*\)",$/\1/p' "$MANIFEST")"
  SIGNED_TOOLCHAIN="$(sed -n 's/^  "release_toolchain": "\([^"]*\)",$/\1/p' "$MANIFEST")"
  SIGNED_SOURCE_SHA="$(sed -n 's/^  "source_manifest_sha256": "\([0-9a-f]\{64\}\)",$/\1/p' "$MANIFEST")"
  EXPECTED_SHA="$(sed -n "s/^    \"$ARCH\": \"\([0-9a-f]\{64\}\)\"[,]\{0,1\}$/\1/p" "$MANIFEST")"
  if [[ "$SIGNED_VERSION" != "$VERSION" || ! "$SIGNED_REVISION" =~ ^[0-9a-f]{40}$ || "$SIGNED_TOOLCHAIN" != go1.27.1 || -z "$SIGNED_SOURCE_SHA" || -z "$EXPECTED_SHA" ]]; then
    echo "签名发布元数据不完整或不一致。" >&2
    exit 1
  fi
  [[ -f "$ROOT_DIR/source-tree.sha256" ]] || { echo "发布包缺少源码哈希清单。" >&2; exit 1; }
  [[ "$(sha256sum "$ROOT_DIR/source-tree.sha256" | awk '{print $1}')" == "$SIGNED_SOURCE_SHA" ]] || { echo "源码哈希清单与签名元数据不一致。" >&2; exit 1; }
  (cd "$ROOT_DIR" && sha256sum -c source-tree.sha256 >/dev/null) || { echo "发布包源码/脚本完整性验证失败。" >&2; exit 1; }
  ACTUAL_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
  [[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || { echo "预编译二进制哈希与签名清单不一致。" >&2; exit 1; }
  [[ "$($BIN -version)" == "$VERSION" ]] || { echo "预编译二进制版本与 VERSION 不一致。" >&2; exit 1; }
fi

if [[ -n "$ALLOW" ]]; then
  ALLOW="$($BIN -validate-bootstrap-allow "$ALLOW")" || {
    echo "--allow 包含无效或不安全的 IP/CIDR。" >&2; exit 2;
  }
fi

TLS_PREFLIGHT=(--check-https)
if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
  TLS_PREFLIGHT+=(--tls-cert "$TLS_CERT" --tls-key "$TLS_KEY")
fi
for TLS_NAME in "${TLS_NAMES[@]}"; do TLS_PREFLIGHT+=(--tls-name "$TLS_NAME"); done
"$BIN" "${TLS_PREFLIGHT[@]}"

if ! command -v nft >/dev/null 2>&1 || ! command -v conntrack >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables conntrack
fi

if getent group portbridge >/dev/null; then
  PORTBRIDGE_GID="$(getent group portbridge | cut -d: -f3)"
  [[ "$PORTBRIDGE_GID" =~ ^[0-9]+$ && "$PORTBRIDGE_GID" -lt 1000 ]] || { echo "现有 portbridge 组不是系统组。" >&2; exit 1; }
else
  groupadd --system portbridge
  PORTBRIDGE_GID="$(getent group portbridge | cut -d: -f3)"
fi
if id -u portbridge >/dev/null 2>&1; then
  IFS=: read -r _ _ PORTBRIDGE_UID EXISTING_GID _ EXISTING_HOME EXISTING_SHELL < <(getent passwd portbridge)
  [[ "$PORTBRIDGE_UID" -lt 1000 && "$EXISTING_GID" == "$PORTBRIDGE_GID" && "$EXISTING_HOME" == /nonexistent && ( "$EXISTING_SHELL" == /usr/sbin/nologin || "$EXISTING_SHELL" == /bin/false ) ]] || {
    echo "现有 portbridge 账户的 UID/GID/home/shell 属性不符合预期。" >&2; exit 1;
  }
  EXTRA_GROUPS="$(id -Gn portbridge | tr ' ' '\n' | grep -vx portbridge || true)"
  [[ -z "$EXTRA_GROUPS" ]] || { echo "现有 portbridge 账户含有异常附加组。" >&2; exit 1; }
else
  useradd --system --gid portbridge --home-dir /nonexistent --shell /usr/sbin/nologin portbridge
fi
PORTBRIDGE_UID="$(id -u portbridge)"

[[ ! -L /etc/portbridge && ( ! -e /etc/portbridge || -d /etc/portbridge ) ]] || { echo "/etc/portbridge 必须是常规目录且不能是符号链接。" >&2; exit 1; }
[[ ! -L /etc/portbridge-tls && ( ! -e /etc/portbridge-tls || -d /etc/portbridge-tls ) ]] || { echo "/etc/portbridge-tls 必须是常规目录且不能是符号链接。" >&2; exit 1; }

validate_state_file() {
  local state_file="$1" state_owner
  [[ -e "$state_file" || -L "$state_file" ]] || return 0
  [[ -f "$state_file" && ! -L "$state_file" ]] || { echo "$state_file 必须是常规文件且不能是符号链接。" >&2; return 1; }
  [[ "$(stat -c %h "$state_file")" == 1 ]] || { echo "$state_file 不能是硬链接文件。" >&2; return 1; }
  state_owner="$(stat -c %u "$state_file")"
  [[ "$state_owner" == 0 || "$state_owner" == "$PORTBRIDGE_UID" ]] || { echo "$state_file 的属主不安全。" >&2; return 1; }
}
for STATE_FILE in /etc/portbridge/config.json /etc/portbridge/admin.token; do
  validate_state_file "$STATE_FILE"
done

# 在替换二进制和 unit 前先由当前版本完成清理，避免接管没有所有权标记的旧 nft 表。
OLD_UNIT_STOP_OK=false
if systemctl list-unit-files portbridge.service --no-legend 2>/dev/null | grep -q portbridge.service; then
  if systemctl stop portbridge.service; then
    OLD_UNIT_STOP_OK=true
  else
    echo "旧 unit 的停止后清理失败。仅在没有服务身份绑定恢复记录的旧部署上允许 root 重试。" >&2
  fi
fi
systemctl is-active --quiet portbridge.service && { echo "现有服务未能干净停止。" >&2; exit 1; }
pgrep -x portbridge >/dev/null 2>&1 && { echo "仍有 portbridge 进程运行，拒绝替换二进制。" >&2; exit 1; }
if [[ -x /usr/local/bin/portbridge ]]; then
  if [[ -e /etc/portbridge/config.json.nft-state.json || -L /etc/portbridge/config.json.nft-state.json ]]; then
    # v2.4.6 records are bound to the service UID. Do not impersonate that
    # identity from the legacy root fallback or erase an unresolved record.
    [[ $OLD_UNIT_STOP_OK == true ]] || { echo "服务身份绑定的 NFT 恢复尚未完成；请保留旧二进制与恢复文件。" >&2; exit 1; }
  else
    /usr/local/bin/portbridge --config=/etc/portbridge/config.json --cleanup-nft
  fi
fi

for STATE_FILE in /etc/portbridge/config.json /etc/portbridge/admin.token; do
  validate_state_file "$STATE_FILE"
done

install -m 0755 "$BIN" /usr/local/bin/.portbridge.new
mv -f /usr/local/bin/.portbridge.new /usr/local/bin/portbridge
install -d -o portbridge -g portbridge -m 0750 /etc/portbridge
install -d -o root -g portbridge -m 0750 /etc/portbridge-tls
for STATE_FILE in /etc/portbridge/config.json /etc/portbridge/admin.token; do
  if [[ -e "$STATE_FILE" ]]; then
    chown --no-dereference portbridge:portbridge "$STATE_FILE"
    chmod 0600 "$STATE_FILE"
  fi
done
# Prepare HTTPS while the service is stopped, then prove its account can read it.
HTTPS_ARGS=(--prepare-https --https-gid "$PORTBRIDGE_GID" --https-language zh-CN)
if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
  [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]] || { echo "--tls-cert 与 --tls-key 必须同时提供" >&2; exit 2; }
  HTTPS_ARGS+=(--tls-cert "$TLS_CERT" --tls-key "$TLS_KEY")
fi
for TLS_NAME in "${TLS_NAMES[@]}"; do HTTPS_ARGS+=(--tls-name "$TLS_NAME"); done
/usr/local/bin/portbridge "${HTTPS_ARGS[@]}"
for STATE_FILE in /etc/portbridge/config.json /etc/portbridge/admin.token; do
  validate_state_file "$STATE_FILE"
  chown --no-dereference portbridge:portbridge "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
done
runuser -u portbridge -- /usr/local/bin/portbridge --https-info --https-language zh-CN

install -d -m 0755 /usr/share/doc/portbridge
DOC="$ROOT_DIR/README.zh-CN.md"
[[ -f "$DOC" ]] || DOC="$ROOT_DIR/README.md"
install -m 0644 "$DOC" /usr/share/doc/portbridge/README.md
install -m 0644 "$ROOT_DIR/config.public.example.json" /usr/share/doc/portbridge/config.public.example.json
install -m 0644 "$ROOT_DIR/SECURITY.md" /usr/share/doc/portbridge/SECURITY.md
install -m 0644 "$ROOT_DIR/packaging/portbridge.service" /etc/systemd/system/.portbridge.service.new
mv -f /etc/systemd/system/.portbridge.service.new /etc/systemd/system/portbridge.service
install -m 0644 "$ROOT_DIR/packaging/90-portbridge.conf" /etc/sysctl.d/90-portbridge.conf
sysctl --system >/dev/null

if [[ -n "$ALLOW" ]]; then
  printf 'PORTBRIDGE_ARGS="--bootstrap-allow=%s"\n' "$ALLOW" > /etc/default/portbridge
else
  printf 'PORTBRIDGE_ARGS=""\n' > /etc/default/portbridge
fi
chmod 0600 /etc/default/portbridge

systemctl daemon-reload
systemctl enable portbridge.service >/dev/null
if [[ $NO_START -eq 0 ]]; then
  systemctl restart portbridge.service
  STABLE_ACTIVE=0
  for _ in {1..40}; do
    if systemctl is-active --quiet portbridge.service; then
      STABLE_ACTIVE=$((STABLE_ACTIVE + 1))
    else
      STABLE_ACTIVE=0
    fi
    [[ $STABLE_ACTIVE -ge 4 && -s /etc/portbridge/admin.token ]] && break
    sleep 0.25
  done
  if [[ $STABLE_ACTIVE -lt 4 ]] || ! systemctl is-active --quiet portbridge.service; then
    echo "portbridge.service 未能保持稳定运行；请检查 journalctl -u portbridge -n 100 --no-pager。" >&2
    exit 1
  fi
  echo
  echo "Go-nftables-portbridge 已安装并启动。"
  echo "管理页面强制使用 HTTPS；实际地址、证书类型及指纹见上方。"
  echo "自签证书需先核对指纹再在客户端信任；正式证书可在 Web 设置替换并重启。"
  echo "公网直连前：先配置原生 TLS 并重启确认 HTTPS，再从 HTTPS 启用严格 IP 白名单，同时配置主机防火墙；参考 config.public.example.json。"
  if [[ -s /etc/portbridge/admin.token ]]; then
    echo "管理员令牌文件: /etc/portbridge/admin.token"
    if [[ $SHOW_TOKEN -eq 1 ]]; then
      echo "管理员令牌: $(cat /etc/portbridge/admin.token)"
    else
      echo "需要查看时运行: sudo cat /etc/portbridge/admin.token"
    fi
  else
    echo "令牌尚未生成，请检查: journalctl -u portbridge -n 100 --no-pager"
  fi
else
  echo "Go-nftables-portbridge 已安装，尚未启动。"
fi
