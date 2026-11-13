#!/usr/bin/env bash
# Build the offline install bundle for non-container Linux x86_64 runners:
#
#   dist/pr-agent-bundle-<version>-linux-x86_64.tar.gz
#     wheels/            project wheel + hash-locked runtime wheels (CPython 3.12)
#     bin/gitleaks       checksum-verified gitleaks
#     requirements.lock  the hashes install.sh verifies the wheels against
#     install.sh         offline installer (no index, nothing fetched)
#
# Run on a connected machine (any OS) with Python 3.12 after
# scripts/fetch-gitleaks.sh. Set PIP_INDEX_URL to use an internal mirror.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
GITLEAKS_VERSION="8.30.1"
GITLEAKS_TARBALL="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 COPYFILE_DISABLE=1

"$PYTHON" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))' \
  || { echo "error: Python 3.12 is required to build the bundle (set PYTHON=...)" >&2; exit 1; }

VERSION="$("$PYTHON" -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
NAME="pr-agent-bundle-${VERSION}-linux-x86_64"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/$NAME"
mkdir -p "$STAGE/wheels" "$STAGE/bin" dist

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$@"; }
else
  sha256() { shasum -a 256 "$@"; }
fi

# gitleaks: verify the vendored tarball against the committed checksum.
[ -f "vendor/$GITLEAKS_TARBALL" ] \
  || { echo "error: vendor/$GITLEAKS_TARBALL missing; run scripts/fetch-gitleaks.sh" >&2; exit 1; }
grep "  ${GITLEAKS_TARBALL}\$" "vendor/gitleaks-${GITLEAKS_VERSION}.sha256" > "$WORK/gitleaks.sha256"
(cd vendor && sha256 -c "$WORK/gitleaks.sha256")
tar -xzf "vendor/$GITLEAKS_TARBALL" -C "$STAGE/bin" gitleaks
chmod 0755 "$STAGE/bin/gitleaks"

# Project wheel, built with a hash-locked setuptools.
"$PYTHON" -m venv "$WORK/build"
"$WORK/build/bin/pip" install -q --require-hashes -r requirements-build.lock
"$WORK/build/bin/pip" wheel -q --no-deps --no-build-isolation --wheel-dir "$STAGE/wheels" .

# Runtime wheels for CPython 3.12 on manylinux x86_64, verified against the lock.
# Earlier --platform values are preferred, so the oldest glibc baseline wins.
"$WORK/build/bin/pip" download -q --require-hashes --only-binary=:all: \
  --implementation cp --python-version 3.12 \
  --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 \
  --platform manylinux_2_28_x86_64 \
  --dest "$STAGE/wheels" -r requirements.lock

cp requirements.lock "$STAGE/requirements.lock"

cat > "$STAGE/install.sh" <<'EOF'
#!/usr/bin/env bash
# Offline installer: creates a virtualenv from the bundled wheels only.
#   ./install.sh [VENV_DIR]     (default: <bundle>/venv; needs Python 3.12 and git)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="${1:-$HERE/venv}"
PYTHON="${PYTHON:-python3}"
export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1

"$PYTHON" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))' \
  || { echo "error: Python 3.12 is required (set PYTHON=/path/to/python3.12)" >&2; exit 1; }

"$PYTHON" -m venv "$VENV"
VENV="$(cd "$VENV" && pwd)"
"$VENV/bin/pip" install -q --no-index --find-links "$HERE/wheels" \
  --require-hashes -r "$HERE/requirements.lock"
"$VENV/bin/pip" install -q --no-index --find-links "$HERE/wheels" --no-deps airgap-pr-agent

echo "pr-agent installed into $VENV. Add to the runner environment:"
echo "export PATH=$VENV/bin:\$PATH"
echo "export GITLEAKS_BIN=$HERE/bin/gitleaks"
EOF
chmod 0755 "$STAGE/install.sh"

tar --no-xattrs -C "$WORK" -czf "dist/$NAME.tar.gz" "$NAME"
(cd dist && sha256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "built dist/$NAME.tar.gz"
