#!/usr/bin/env bash
# Release build: tarball + SHA256SUMS + optional GPG detached signature.
# Run at push time from the repo root. The private minting key and any
# keypair_*.json must NOT be inside this tree (tools_keygen lives outside).
set -euo pipefail
VER="${1:?usage: make_release.sh <version> [gpg-key-id]}"
KEY="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
find . -name '*.pyc' -delete 2>/dev/null || true

# guard: no private material may ever reach a release artifact
if find . -name 'keypair_*.json' | grep . ; then
  echo "ABORT: keypair file in tree"; exit 1
fi
if grep -rIlE --exclude-dir=.git -- "BEGIN[[:space:]][A-Z ]*PRIVATE[[:space:]]KEY" . ; then
  echo "ABORT: PEM private key material in tree"; exit 1
fi

TARBALL="swarm-re-fieldkit-${VER}.tar.gz"
TMPD="$(mktemp -d)"
tar --exclude='.git' -czf "$TMPD/$TARBALL" .
mv "$TMPD/$TARBALL" "$TARBALL"; rmdir "$TMPD"
sha256sum "$TARBALL" > SHA256SUMS.txt
if [ -n "$KEY" ]; then
  gpg --batch --yes -u "$KEY" -b -o "${TARBALL}.sig" "$TARBALL"
  gpg --batch --yes -u "$KEY" -b --armor -o SHA256SUMS.txt.asc SHA256SUMS.txt
  echo "signed with $KEY"
fi
echo "release artifact: $TARBALL"
sha256sum "$TARBALL"
