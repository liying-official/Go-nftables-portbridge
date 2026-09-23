#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"
GO_BIN="${PORTBRIDGE_GO_BIN:-go}"
RELEASE_TOOLCHAIN="${PORTBRIDGE_RELEASE_TOOLCHAIN:-go1.27.1}"
RELEASE_DIR="${PORTBRIDGE_RELEASE_DIR:-$ROOT_DIR/release/v$VERSION}"
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
OUTPUTS=(SHA256SUMS SHA256SUMS.sig SBOM)
for language in en-US zh-CN; do
  for arch in amd64 arm64; do
    OUTPUTS+=("portbridge-v${VERSION}-linux-${arch}-${language}.tar.gz")
  done
done
for name in "${OUTPUTS[@]}"; do
  if [[ -e "$RELEASE_DIR/$name" || -L "$RELEASE_DIR/$name" ]]; then
    echo "Refusing to overwrite release output: $name" >&2
    exit 1
  fi
done

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
if [[ -n "$(find "$COMMON" ! -type f ! -type d -print -quit)" ]]; then
  echo "Release sources must contain only regular files and directories" >&2
  exit 1
fi
find "$COMMON" -type d -exec chmod 0755 {} +
find "$COMMON" -type f -exec chmod 0644 {} +
find "$COMMON/scripts" -type f -name '*.sh' -exec chmod 0755 {} +
LDFLAGS="-s -w -buildid= -X main.version=$VERSION"

for language in en-US zh-CN; do
  LOCALIZED="$STAGING/localized-$language"
  cp -a -- "$COMMON" "$LOCALIZED"
  python3 "$ROOT_DIR/scripts/localize-package.py" "$LOCALIZED" "$language"
  for arch in amd64 arm64; do
    name="portbridge-v${VERSION}-linux-${arch}-${language}"
    bundle="$STAGING/$name"
    cp -a -- "$LOCALIZED" "$bundle"
    binary="$bundle/dist/go-nftables-portbridge-linux-$arch"
    (cd -- "$bundle"; CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO_BIN" build -trimpath -ldflags="$LDFLAGS" -o "$binary" ./cmd/portbridge)
    "$GO_BIN" version -m "$binary" | grep -F "$ACTUAL_TOOLCHAIN"
    if [[ "$arch" == "$($GO_BIN env GOHOSTARCH)" && "$($GO_BIN env GOHOSTOS)" == linux ]]; then
      [[ "$("$binary" -version)" == "$VERSION" ]]
    fi
    (
      cd -- "$bundle"
      LC_ALL=C find . -type f ! -path './dist/*' \
        ! -name 'source-tree.sha256' ! -name 'release-bundle-manifest.json' \
        ! -name 'release-bundle-manifest.json.sig' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > source-tree.sha256
    )
    python3 "$ROOT_DIR/scripts/release-metadata.py" bundle "$bundle" "$VERSION" "$SOURCE_REVISION" "$ACTUAL_TOOLCHAIN" --arch "$arch" --language "$language"
    ssh-keygen -Y sign -q -f "$SIGNING_KEY" -n "$SIGNATURE_NAMESPACE" "$bundle/release-bundle-manifest.json"
    ssh-keygen -Y verify -q -f "$SIGNER_FILE" -I "$SIGNER_IDENTITY" -n "$SIGNATURE_NAMESPACE" -s "$bundle/release-bundle-manifest.json.sig" < "$bundle/release-bundle-manifest.json"
    find "$bundle" -type f -exec chmod 0644 {} +
    find "$bundle/scripts" -type f -name '*.sh' -exec chmod 0755 {} +
    chmod 0755 "$binary"
    find "$bundle" -type f -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
    find "$bundle" -type d -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$STAGING" -cf - "$name" | gzip -n > "$RELEASE_DIR/$name.tar.gz"
  done
done
python3 "$ROOT_DIR/scripts/release-metadata.py" sbom "$RELEASE_DIR" "$VERSION" "$SOURCE_REVISION" "$ACTUAL_TOOLCHAIN" --source "$ROOT_DIR" --epoch "$SOURCE_DATE_EPOCH"
(
  cd -- "$RELEASE_DIR"
  sha256sum portbridge-v"$VERSION"-linux-{amd64,arm64}-{en-US,zh-CN}.tar.gz SBOM > SHA256SUMS
)
ssh-keygen -Y sign -q -f "$SIGNING_KEY" -n "$SIGNATURE_NAMESPACE" "$RELEASE_DIR/SHA256SUMS"
(
  cd -- "$RELEASE_DIR"
  sha256sum -c SHA256SUMS
  ssh-keygen -Y verify -q -f "$SIGNER_FILE" -I "$SIGNER_IDENTITY" -n "$SIGNATURE_NAMESPACE" -s SHA256SUMS.sig < SHA256SUMS
)
for name in "${OUTPUTS[@]}"; do chmod 0644 "$RELEASE_DIR/$name"; done
printf 'Release assets written to %s\n' "$RELEASE_DIR"
