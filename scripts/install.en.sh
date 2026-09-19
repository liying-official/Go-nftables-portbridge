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
Usage: sudo ./scripts/install.sh [options]
  --allow IP_OR_CIDR[,MORE]  Add a trusted bootstrap ACL (not a substitute for public TLS)
  --tls-cert FILE        Import a certificate (requires --tls-key)
  --tls-key FILE         Import its key (source file is not modified)
  --tls-name DNS-or-IP    Add a SAN to a generated self-signed certificate; repeatable
  --no-start                 Install without starting the service
  --show-token               Print the administrator token after installation (deployment logs may capture it)
USAGE
}

while (($#)); do
  case "$1" in
    --allow) ALLOW="${2:?missing IP/CIDR}"; shift 2 ;;
    --tls-cert) TLS_CERT="${2:?missing certificate path}"; shift 2 ;;
    --tls-key) TLS_KEY="${2:?missing private key path}"; shift 2 ;;
    --tls-name) TLS_NAMES+=("${2:?missing certificate DNS/IP name}"); shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --show-token) SHOW_TOKEN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

# PORTBRIDGE_ARGS is expanded by systemd as command-line arguments. Limit the
# bootstrap ACL to IP/CIDR syntax before writing it to EnvironmentFile so
# whitespace, quotes, or newlines cannot inject extra arguments/assignments.
if [[ -n "$ALLOW" ]]; then
  if [[ ! "$ALLOW" =~ ^[0-9A-Fa-f:.,/]+$ || "$ALLOW" == ,* || "$ALLOW" == *, || "$ALLOW" == *,,* ]]; then
    echo "--allow accepts only comma-separated IP or CIDR values without spaces, quotes, or control characters." >&2
    exit 2
  fi
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run this installer as root or with sudo." >&2
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
  command -v go >/dev/null 2>&1 || { echo "A source install requires Go 1.27.1; use the signed release archive for prebuilt binaries." >&2; exit 1; }
  [[ "$(go env GOVERSION)" == go1.27.1 ]] || { echo "A source install requires exactly Go 1.27.1." >&2; exit 1; }
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
    echo "Prebuilt release binaries require a signed release-bundle manifest." >&2
    exit 1
  fi
  command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen is required to verify release signatures." >&2; exit 1; }
  if [[ -L "$SIGNERS" || ! -f "$SIGNERS" || "$(LC_ALL=C stat -c %F -- "$SIGNERS" 2>/dev/null)" != "regular file" || "$(stat -c %h -- "$SIGNERS" 2>/dev/null)" != 1 ]]; then
    echo "The release signer file must be a regular single-link file inside the bundle, not a symbolic link." >&2
    exit 1
  fi
  RELEASE_SIGNER_SIZE="$(stat -c %s -- "$SIGNERS" 2>/dev/null)"
  if [[ ! "$RELEASE_SIGNER_SIZE" =~ ^[0-9]+$ ]] || (( RELEASE_SIGNER_SIZE < ${#EXPECTED_RELEASE_SIGNER} || RELEASE_SIGNER_SIZE > ${#EXPECTED_RELEASE_SIGNER} + 1 )); then
    echo "The release signer file has an invalid length." >&2
    exit 1
  fi
  mapfile -t RELEASE_SIGNER_LINES < "$SIGNERS"
  if [[ ${#RELEASE_SIGNER_LINES[@]} -ne 1 || "${RELEASE_SIGNER_LINES[0]}" != "$EXPECTED_RELEASE_SIGNER" ]]; then
    echo "The release signer file does not match the trust anchor pinned in this installer." >&2
    exit 1
  fi
  ACTUAL_RELEASE_SIGNER_FINGERPRINT="$(ssh-keygen -lf "$SIGNERS" -E sha256 2>/dev/null | awk 'NR == 1 {print $2}')"
  if [[ "$ACTUAL_RELEASE_SIGNER_FINGERPRINT" != "$EXPECTED_RELEASE_SIGNER_FINGERPRINT" ]]; then
    echo "The release signer fingerprint does not match the trust anchor pinned in this installer." >&2
    exit 1
  fi
  ssh-keygen -Y verify -q -f "$SIGNERS" -I portbridge-release-v2 -n portbridge-release -s "$SIGNATURE" < "$MANIFEST" || {
    echo "Release bundle signature verification failed." >&2; exit 1;
  }
  VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"
  SIGNED_VERSION="$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$MANIFEST")"
  SIGNED_REVISION="$(sed -n 's/^  "source_revision": "\([^"]*\)",$/\1/p' "$MANIFEST")"
  SIGNED_TOOLCHAIN="$(sed -n 's/^  "release_toolchain": "\([^"]*\)",$/\1/p' "$MANIFEST")"
  SIGNED_SOURCE_SHA="$(sed -n 's/^  "source_manifest_sha256": "\([0-9a-f]\{64\}\)",$/\1/p' "$MANIFEST")"
  EXPECTED_SHA="$(sed -n "s/^    \"$ARCH\": \"\([0-9a-f]\{64\}\)\"[,]\{0,1\}$/\1/p" "$MANIFEST")"
  if [[ "$SIGNED_VERSION" != "$VERSION" || ! "$SIGNED_REVISION" =~ ^[0-9a-f]{40}$ || "$SIGNED_TOOLCHAIN" != go1.27.1 || -z "$SIGNED_SOURCE_SHA" || -z "$EXPECTED_SHA" ]]; then
    echo "Signed release metadata is incomplete or inconsistent." >&2
    exit 1
  fi
  [[ -f "$ROOT_DIR/source-tree.sha256" ]] || { echo "Release bundle source hash manifest is missing." >&2; exit 1; }
  [[ "$(sha256sum "$ROOT_DIR/source-tree.sha256" | awk '{print $1}')" == "$SIGNED_SOURCE_SHA" ]] || { echo "Source hash manifest does not match signed metadata." >&2; exit 1; }
  (cd "$ROOT_DIR" && sha256sum -c source-tree.sha256 >/dev/null) || { echo "Release source/script integrity verification failed." >&2; exit 1; }
  ACTUAL_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
  if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
    echo "Prebuilt binary checksum does not match the signed manifest." >&2
    exit 1
  fi
  if [[ "$($BIN -version)" != "$VERSION" ]]; then
    echo "Prebuilt binary version does not match VERSION." >&2
    exit 1
  fi
fi

if [[ -n "$ALLOW" ]]; then
  ALLOW="$($BIN -validate-bootstrap-allow "$ALLOW")" || {
    echo "--allow contains an invalid or unsafe IP/CIDR." >&2; exit 2;
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
  [[ "$PORTBRIDGE_GID" =~ ^[0-9]+$ && "$PORTBRIDGE_GID" -lt 1000 ]] || { echo "Existing portbridge group is not a system group." >&2; exit 1; }
else
  groupadd --system portbridge
  PORTBRIDGE_GID="$(getent group portbridge | cut -d: -f3)"
fi
if id -u portbridge >/dev/null 2>&1; then
  IFS=: read -r _ _ PORTBRIDGE_UID EXISTING_GID _ EXISTING_HOME EXISTING_SHELL < <(getent passwd portbridge)
  [[ "$PORTBRIDGE_UID" -lt 1000 && "$EXISTING_GID" == "$PORTBRIDGE_GID" && "$EXISTING_HOME" == /nonexistent && ( "$EXISTING_SHELL" == /usr/sbin/nologin || "$EXISTING_SHELL" == /bin/false ) ]] || {
    echo "Existing portbridge account has unexpected UID/GID/home/shell attributes." >&2; exit 1;
  }
  EXTRA_GROUPS="$(id -Gn portbridge | tr ' ' '\n' | grep -vx portbridge || true)"
  [[ -z "$EXTRA_GROUPS" ]] || { echo "Existing portbridge account has unexpected supplementary groups." >&2; exit 1; }
else
  useradd --system --gid portbridge --home-dir /nonexistent --shell /usr/sbin/nologin portbridge
fi
PORTBRIDGE_UID="$(id -u portbridge)"

[[ ! -L /etc/portbridge && ( ! -e /etc/portbridge || -d /etc/portbridge ) ]] || { echo "/etc/portbridge must be a real directory, not a symbolic link." >&2; exit 1; }
[[ ! -L /etc/portbridge-tls && ( ! -e /etc/portbridge-tls || -d /etc/portbridge-tls ) ]] || { echo "/etc/portbridge-tls must be a real directory, not a symbolic link." >&2; exit 1; }

validate_state_file() {
  local state_file="$1" state_owner
  [[ -e "$state_file" || -L "$state_file" ]] || return 0
  [[ -f "$state_file" && ! -L "$state_file" ]] || { echo "$state_file must be a regular non-symlink file." >&2; return 1; }
  [[ "$(stat -c %h "$state_file")" == 1 ]] || { echo "$state_file must not be hard-linked." >&2; return 1; }
  state_owner="$(stat -c %u "$state_file")"
  [[ "$state_owner" == 0 || "$state_owner" == "$PORTBRIDGE_UID" ]] || { echo "$state_file has an unsafe owner." >&2; return 1; }
}
for STATE_FILE in /etc/portbridge/config.json /etc/portbridge/admin.token; do
  validate_state_file "$STATE_FILE"
done

# Stop the currently loaded unit before replacing the binary/unit. This lets a
# legacy release run its own cleanup and avoids adopting an unmarked nft table.
OLD_UNIT_STOP_OK=false
if systemctl list-unit-files portbridge.service --no-legend 2>/dev/null | grep -q portbridge.service; then
  if systemctl stop portbridge.service; then
    OLD_UNIT_STOP_OK=true
  else
    echo "The old unit's post-stop cleanup failed. Root retry is permitted only for legacy deployments without service-bound recovery files." >&2
  fi
fi
systemctl is-active --quiet portbridge.service && { echo "Existing service did not stop cleanly." >&2; exit 1; }
pgrep -x portbridge >/dev/null 2>&1 && { echo "A portbridge process is still running; refusing to replace the binary." >&2; exit 1; }
if [[ -x /usr/local/bin/portbridge ]]; then
  if [[ -e /etc/portbridge/config.json.nft-state.json || -L /etc/portbridge/config.json.nft-state.json ]]; then
    # v2.4.6 records are bound to the service UID. Do not impersonate that
    # identity from the legacy root fallback or erase an unresolved record.
    [[ $OLD_UNIT_STOP_OK == true ]] || { echo "Service-identity NFT recovery is incomplete; retain the old binary and recovery files." >&2; exit 1; }
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
HTTPS_ARGS=(--prepare-https --https-gid "$PORTBRIDGE_GID" --https-language en-US)
if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
  [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]] || { echo "--tls-cert and --tls-key must be supplied together" >&2; exit 2; }
  HTTPS_ARGS+=(--tls-cert "$TLS_CERT" --tls-key "$TLS_KEY")
fi
for TLS_NAME in "${TLS_NAMES[@]}"; do HTTPS_ARGS+=(--tls-name "$TLS_NAME"); done
/usr/local/bin/portbridge "${HTTPS_ARGS[@]}"
for STATE_FILE in /etc/portbridge/config.json /etc/portbridge/admin.token; do
  validate_state_file "$STATE_FILE"
  chown --no-dereference portbridge:portbridge "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
done
runuser -u portbridge -- /usr/local/bin/portbridge --https-info --https-language en-US

install -d -m 0755 /usr/share/doc/portbridge
install -m 0644 "$ROOT_DIR/README.md" /usr/share/doc/portbridge/README.md
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
    echo "portbridge.service did not remain stably active; inspect journalctl -u portbridge -n 100 --no-pager." >&2
    exit 1
  fi
  echo
  echo "Go-nftables-portbridge is installed and running."
  echo "Management requires HTTPS; actual URLs, certificate type and fingerprint are shown above."
  echo "Verify self-signed fingerprints before trusting them. Replace certificates in Web settings and restart."
  echo "Before direct public exposure, configure native TLS and restart to verify HTTPS; then enable strict IP allowlisting from HTTPS and configure a host firewall. See config.public.example.json."
  if [[ -s /etc/portbridge/admin.token ]]; then
    echo "Administrator token file: /etc/portbridge/admin.token"
    if [[ $SHOW_TOKEN -eq 1 ]]; then
      echo "Administrator token: $(cat /etc/portbridge/admin.token)"
    else
      echo "Run this when needed: sudo cat /etc/portbridge/admin.token"
    fi
  else
    echo "The token has not been generated; inspect: journalctl -u portbridge -n 100 --no-pager"
  fi
else
  echo "Go-nftables-portbridge is installed but has not been started."
fi
