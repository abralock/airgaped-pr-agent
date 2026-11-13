#!/usr/bin/env bash
# Download the pinned gitleaks release tarballs into vendor/ and verify them
# against the committed checksums. Run this on a connected machine; for an
# air-gapped build, copy the verified tarballs into vendor/ by hand.
set -euo pipefail

VERSION="8.30.1"
ARCHES=(x64 arm64)
BASE_URL="${GITLEAKS_BASE_URL:-https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}}"

cd "$(dirname "$0")/../vendor"
SUMS="gitleaks-${VERSION}.sha256"

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$@"; }
else
  sha256() { shasum -a 256 "$@"; }
fi

for arch in "${ARCHES[@]}"; do
  name="gitleaks_${VERSION}_linux_${arch}.tar.gz"
  if [ ! -f "$name" ]; then
    echo "fetching ${name}"
    curl -fsSL --retry 3 -o "${name}.part" "${BASE_URL}/${name}"
    mv "${name}.part" "$name"
  fi
  if ! grep -q "  ${name}\$" "$SUMS"; then
    echo "error: no checksum for ${name} in ${SUMS}" >&2
    exit 1
  fi
done

# Verify every tarball listed in the checksum file; a mismatch aborts.
sha256 -c "$SUMS"
