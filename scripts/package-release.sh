#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"
GO_BIN="${PORTBRIDGE_GO_BIN:-go}"
RELEASE_TOOLCHAIN="${PORTBRIDGE_RELEASE_TOOLCHAIN:-go1.27.1}"
RELEASE_DIR="${PORTBRIDGE_RELEASE_DIR:-$ROOT_DIR/release}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}"
SOURCE_REVISION_OVERRIDE="${PORTBRIDGE_SOURCE_REVISION:-}"
SIGNING_KEY="${PORTBRIDGE_SIGNING_KEY:-}"
SIGNER_FILE="$ROOT_DIR/packaging/release-signers"
SIGNER_IDENTITY="portbridge-release-v2"
SIGNATURE_NAMESPACE="portbridge-release"
EXPECTED_SIGNER_LINE='portbridge-release-v2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVc6m1afFOM3gsLO6VXuLyAlHbkvBP83wlMEqArW/0k'
EXPECTED_SIGNER_FINGERPRINT='SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o'

IS_GIT_WORKTREE=0
if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  IS_GIT_WORKTREE=1
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" log -1 --format=%ct)}"
else
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid VERSION: $VERSION" >&2
  exit 1
fi
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "Invalid SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH" >&2
  exit 1
fi
if [[ -n "$SOURCE_REVISION_OVERRIDE" && ! "$SOURCE_REVISION_OVERRIDE" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "Invalid PORTBRIDGE_SOURCE_REVISION: expected a 40-character Git commit hash" >&2
  exit 1
fi
if [[ "$RELEASE_DIR" == "/" || -z "$RELEASE_DIR" ]]; then
  echo "Refusing unsafe release directory: $RELEASE_DIR" >&2
  exit 1
fi
if [[ -z "$SIGNING_KEY" || ! -f "$SIGNING_KEY" ]]; then
  echo "PORTBRIDGE_SIGNING_KEY must name the offline Ed25519 release key" >&2
  exit 1
fi
if [[ -L "$SIGNING_KEY" || "$(stat -c %u "$SIGNING_KEY")" != "$(id -u)" ]]; then
  echo "Release signing key must be a non-symlink owned by the current offline signer account" >&2
  exit 1
fi
case "$(stat -c %a "$SIGNING_KEY")" in
  400|600) ;;
  *) echo "Release signing key permissions must be 0400 or 0600" >&2; exit 1 ;;
esac
if [[ -L "$SIGNER_FILE" || ! -f "$SIGNER_FILE" || "$(LC_ALL=C stat -c %F -- "$SIGNER_FILE" 2>/dev/null)" != "regular file" || "$(stat -c %h -- "$SIGNER_FILE" 2>/dev/null)" != 1 ]]; then
  echo "Pinned release signer must be a regular single-link file, not a symbolic link" >&2
  exit 1
fi
mapfile -t SIGNER_LINES < "$SIGNER_FILE"
if [[ ${#SIGNER_LINES[@]} -ne 1 || "${SIGNER_LINES[0]}" != "$EXPECTED_SIGNER_LINE" ]]; then
  echo "Pinned release signer file does not contain exactly the expected identity and key" >&2
  exit 1
fi
ACTUAL_SIGNER_FINGERPRINT="$(ssh-keygen -lf "$SIGNER_FILE" -E sha256 2>/dev/null | awk 'NR == 1 {print $2}')"
if [[ "$ACTUAL_SIGNER_FINGERPRINT" != "$EXPECTED_SIGNER_FINGERPRINT" ]]; then
  echo "Pinned release signer fingerprint does not match the expected trust anchor" >&2
  exit 1
fi
EXPECTED_SIGNER="${EXPECTED_SIGNER_LINE#"$SIGNER_IDENTITY "}"
ACTUAL_SIGNER="$(ssh-keygen -y -f "$SIGNING_KEY" | awk '{print $1" "$2}')"
if [[ -z "$EXPECTED_SIGNER" || "$ACTUAL_SIGNER" != "$EXPECTED_SIGNER" ]]; then
  echo "Release signing key does not match the pinned public signer" >&2
  exit 1
fi

cd -- "$ROOT_DIR"

export GOTOOLCHAIN="$RELEASE_TOOLCHAIN"
export GOFLAGS="-mod=vendor"
ACTUAL_TOOLCHAIN="$($GO_BIN env GOVERSION)"
if [[ "$ACTUAL_TOOLCHAIN" != "$RELEASE_TOOLCHAIN" ]]; then
  echo "Release requires $RELEASE_TOOLCHAIN, got $ACTUAL_TOOLCHAIN" >&2
  exit 1
fi

if [[ $IS_GIT_WORKTREE -eq 1 ]]; then
  git -C "$ROOT_DIR" diff --check
fi
"$GO_BIN" mod verify
"$GO_BIN" test ./...

if [[ -n "$SOURCE_REVISION_OVERRIDE" ]]; then
  SOURCE_REVISION="${SOURCE_REVISION_OVERRIDE,,}"
elif [[ $IS_GIT_WORKTREE -eq 1 ]] && git -C "$ROOT_DIR" diff --quiet && git -C "$ROOT_DIR" diff --cached --quiet && \
   [[ -z "$(git -C "$ROOT_DIR" ls-files --others --exclude-standard)" ]]; then
  SOURCE_REVISION="$(git -C "$ROOT_DIR" rev-parse HEAD)"
elif [[ $IS_GIT_WORKTREE -eq 1 ]]; then
  echo "Refusing to create signed release artifacts from a dirty Git worktree" >&2
  exit 1
else
  echo "PORTBRIDGE_SOURCE_REVISION is required for signed source-archive builds" >&2
  exit 1
fi

install -d -m 0755 "$RELEASE_DIR"
EN_NAME="Go-nftables-portbridge-v${VERSION}-en-US"
ZH_NAME="Go-nftables-portbridge-v${VERSION}-zh-CN"
EN_ARCHIVE="$RELEASE_DIR/${EN_NAME}.tar.gz"
ZH_ARCHIVE="$RELEASE_DIR/${ZH_NAME}.tar.gz"
CHECKSUMS="$RELEASE_DIR/Go-nftables-portbridge-v${VERSION}-SHA256SUMS.txt"
MANIFEST="$RELEASE_DIR/release-manifest.json"
MANIFEST_SIG="$MANIFEST.sig"
CHECKSUMS_SIG="$CHECKSUMS.sig"
rm -f -- "$EN_ARCHIVE" "$ZH_ARCHIVE" "$CHECKSUMS" "$CHECKSUMS_SIG" "$MANIFEST" "$MANIFEST_SIG"

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/portbridge-release.XXXXXX")"
trap 'rm -rf -- "$STAGING"' EXIT
COMMON="$STAGING/common"
install -d -m 0755 "$COMMON/dist"

for path in \
  .gitattributes .gitignore CONTRIBUTING.md LICENSE Makefile \
  README.md README.zh-CN.md RELEASE_NOTES.md RELEASE_NOTES.zh-CN.md \
  SECURITY.md VENDOR_PATCHES.md VERSION config.example.json \
  config.public.example.json go.mod go.sum cmd docs internal packaging scripts vendor; do
  cp -a -- "$ROOT_DIR/$path" "$COMMON/"
done

LDFLAGS="-s -w -buildid= -X main.version=$VERSION"

find "$COMMON" -type d -exec chmod 0755 {} +
find "$COMMON" -type f -exec chmod 0644 {} +
find "$COMMON/scripts" -type f -name '*.sh' -exec chmod 0755 {} +

cp -a -- "$COMMON" "$STAGING/$EN_NAME"
cp -a -- "$COMMON" "$STAGING/$ZH_NAME"

python3 "$ROOT_DIR/scripts/localize-package.py" "$STAGING/$EN_NAME" en-US
python3 "$ROOT_DIR/scripts/localize-package.py" "$STAGING/$ZH_NAME" zh-CN
for bundle in "$EN_NAME" "$ZH_NAME"; do
  for arch in amd64 arm64; do
    (cd -- "$STAGING/$bundle"; CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO_BIN" build -trimpath -ldflags="$LDFLAGS" \
      -o "dist/go-nftables-portbridge-linux-$arch" ./cmd/portbridge)
  done
done

write_bundle_metadata() {
  local bundle_root="$1"
  local source_manifest="$bundle_root/source-tree.sha256"
  local bundle_manifest="$bundle_root/release-bundle-manifest.json"
  local AMD64_SHA ARM64_SHA
  AMD64_SHA="$(sha256sum "$bundle_root/dist/go-nftables-portbridge-linux-amd64" | cut -d ' ' -f1)"
  ARM64_SHA="$(sha256sum "$bundle_root/dist/go-nftables-portbridge-linux-arm64" | cut -d ' ' -f1)"
  (
    cd -- "$bundle_root"
    LC_ALL=C find . -type f \
      ! -path './dist/*' \
      ! -name 'source-tree.sha256' \
      ! -name 'release-bundle-manifest.json' \
      ! -name 'release-bundle-manifest.json.sig' \
      -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > source-tree.sha256
  )
  local source_manifest_sha
  source_manifest_sha="$(sha256sum "$source_manifest" | cut -d ' ' -f1)"
  printf '%s\n' \
    '{' \
    '  "project": "Go-nftables-portbridge",' \
    "  \"version\": \"$VERSION\"," \
    "  \"source_revision\": \"$SOURCE_REVISION\"," \
    "  \"release_toolchain\": \"$ACTUAL_TOOLCHAIN\"," \
    "  \"source_manifest_sha256\": \"$source_manifest_sha\"," \
    '  "binaries": {' \
    "    \"amd64\": \"$AMD64_SHA\"," \
    "    \"arm64\": \"$ARM64_SHA\"" \
    '  }' \
    '}' > "$bundle_manifest"
  ssh-keygen -Y sign -q -f "$SIGNING_KEY" -n "$SIGNATURE_NAMESPACE" "$bundle_manifest"
}

write_bundle_metadata "$STAGING/$EN_NAME"
write_bundle_metadata "$STAGING/$ZH_NAME"
find "$STAGING/$EN_NAME" "$STAGING/$ZH_NAME" -type f -exec chmod 0644 {} +
find "$STAGING/$EN_NAME/scripts" "$STAGING/$ZH_NAME/scripts" -type f -name '*.sh' -exec chmod 0755 {} +
chmod 0755 "$STAGING/$EN_NAME/dist/"* "$STAGING/$ZH_NAME/dist/"*

find "$STAGING/$EN_NAME" "$STAGING/$ZH_NAME" -type f -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
find "$STAGING/$EN_NAME" "$STAGING/$ZH_NAME" -type d -exec touch -d "@$SOURCE_DATE_EPOCH" {} +

tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$STAGING" -cf - "$EN_NAME" | gzip -n > "$EN_ARCHIVE"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$STAGING" -cf - "$ZH_NAME" | gzip -n > "$ZH_ARCHIVE"

EN_SHA="$(sha256sum "$EN_ARCHIVE" | cut -d ' ' -f1)"
ZH_SHA="$(sha256sum "$ZH_ARCHIVE" | cut -d ' ' -f1)"
EN_SIZE="$(stat -c %s "$EN_ARCHIVE")"
ZH_SIZE="$(stat -c %s "$ZH_ARCHIVE")"

printf '%s\n' \
  '{' \
  '  "project": "Go-nftables-portbridge",' \
  "  \"version\": \"$VERSION\"," \
  "  \"source_revision\": \"$SOURCE_REVISION\"," \
  "  \"source_date_epoch\": $SOURCE_DATE_EPOCH," \
  "  \"release_toolchain\": \"$ACTUAL_TOOLCHAIN\"," \
  '  "minimum_source_toolchain": "go1.27.1",' \
  '  "binaries": [' \
  "    {\"os\":\"linux\",\"arch\":\"amd64\",\"language\":\"en-US\",\"sha256\":\"$(sha256sum "$STAGING/$EN_NAME/dist/go-nftables-portbridge-linux-amd64" | cut -d ' ' -f1)\"}," \
  "    {\"os\":\"linux\",\"arch\":\"arm64\",\"language\":\"en-US\",\"sha256\":\"$(sha256sum "$STAGING/$EN_NAME/dist/go-nftables-portbridge-linux-arm64" | cut -d ' ' -f1)\"}," \
  "    {\"os\":\"linux\",\"arch\":\"amd64\",\"language\":\"zh-CN\",\"sha256\":\"$(sha256sum "$STAGING/$ZH_NAME/dist/go-nftables-portbridge-linux-amd64" | cut -d ' ' -f1)\"}," \
  "    {\"os\":\"linux\",\"arch\":\"arm64\",\"language\":\"zh-CN\",\"sha256\":\"$(sha256sum "$STAGING/$ZH_NAME/dist/go-nftables-portbridge-linux-arm64" | cut -d ' ' -f1)\"}" \
  '  ],' \
  '  "archives": [' \
  "    {\"file\":\"${EN_NAME}.tar.gz\",\"language\":\"en-US\",\"bytes\":$EN_SIZE,\"sha256\":\"$EN_SHA\"}," \
  "    {\"file\":\"${ZH_NAME}.tar.gz\",\"language\":\"zh-CN\",\"bytes\":$ZH_SIZE,\"sha256\":\"$ZH_SHA\"}" \
  '  ]' \
  '}' > "$MANIFEST"
ssh-keygen -Y sign -q -f "$SIGNING_KEY" -n "$SIGNATURE_NAMESPACE" "$MANIFEST"

(
  cd -- "$RELEASE_DIR"
  sha256sum "$(basename "$EN_ARCHIVE")" "$(basename "$ZH_ARCHIVE")" "$(basename "$MANIFEST")" "$(basename "$MANIFEST_SIG")" > "$(basename "$CHECKSUMS")"
)
ssh-keygen -Y sign -q -f "$SIGNING_KEY" -n "$SIGNATURE_NAMESPACE" "$CHECKSUMS"

for bundle in "$EN_NAME" "$ZH_NAME"; do
  "$STAGING/$bundle/dist/go-nftables-portbridge-linux-amd64" -version
  "$GO_BIN" version -m "$STAGING/$bundle/dist/go-nftables-portbridge-linux-amd64" | grep -F "$ACTUAL_TOOLCHAIN"
  "$GO_BIN" version -m "$STAGING/$bundle/dist/go-nftables-portbridge-linux-arm64" | grep -F "$ACTUAL_TOOLCHAIN"
done
(
  cd -- "$RELEASE_DIR"
  sha256sum -c "$(basename "$CHECKSUMS")"
	ssh-keygen -Y verify -q -f "$SIGNER_FILE" -I "$SIGNER_IDENTITY" -n "$SIGNATURE_NAMESPACE" -s "$(basename "$MANIFEST_SIG")" < "$(basename "$MANIFEST")"
	ssh-keygen -Y verify -q -f "$SIGNER_FILE" -I "$SIGNER_IDENTITY" -n "$SIGNATURE_NAMESPACE" -s "$(basename "$CHECKSUMS_SIG")" < "$(basename "$CHECKSUMS")"
)

chmod 0644 "$EN_ARCHIVE" "$ZH_ARCHIVE" "$CHECKSUMS" "$CHECKSUMS_SIG" "$MANIFEST" "$MANIFEST_SIG"

printf 'Release assets written to %s\n' "$RELEASE_DIR"
