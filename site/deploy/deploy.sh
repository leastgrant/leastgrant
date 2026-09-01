#!/usr/bin/env bash
#
# Ship a built site to the origin and swap it in atomically.
#
#   ./site/deploy/deploy.sh user@vps
#   ./site/deploy/deploy.sh user@vps --dry-run
#
# Run from a clean checkout, after `npm run site:test` has passed. Nothing here
# needs a Cloudflare token: the tunnel is already running on the origin and
# points at a fixed local port, so a content deploy never touches it.
#
# The swap is a symlink rename, which is atomic on Linux. No request is ever
# served from a half-copied directory, and rolling back is the same rename in
# reverse -- see DEPLOY.md.

set -euo pipefail

TARGET="${1:-}"
DRY="${2:-}"

if [ -z "$TARGET" ]; then
  echo "usage: $0 user@host [--dry-run]" >&2
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$REPO/site/dist"
REMOTE_ROOT=/srv/leastgrant
KEEP=5

# --- refuse to ship something unverified -------------------------------------

if [ ! -d "$DIST" ]; then
  echo "no build at $DIST -- run: npm run site:build" >&2
  exit 1
fi

for required in index.html 404.html robots.txt sitemap.xml og.png; do
  if [ ! -f "$DIST/$required" ]; then
    echo "the build is missing $required; refusing to deploy a partial site" >&2
    exit 1
  fi
done

# A deploy from a dirty tree cannot be traced back to a commit. That is fine for
# an experiment and not fine for the thing on the public domain, so it has to be
# an explicit choice.
if git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then
  if [ -n "$(git -C "$REPO" status --porcelain)" ] && [ "${ALLOW_DIRTY:-}" != "1" ]; then
    echo "working tree is dirty. Commit, or re-run with ALLOW_DIRTY=1" >&2
    git -C "$REPO" status --short >&2
    exit 1
  fi
  COMMIT="$(git -C "$REPO" rev-parse --short HEAD)"
else
  COMMIT=unknown
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$COMMIT"
RELEASE="$REMOTE_ROOT/releases/$STAMP"

echo "deploying $COMMIT to $TARGET as $STAMP"

if [ "$DRY" = "--dry-run" ]; then
  echo "would rsync $(find "$DIST" -type f | wc -l) files to $RELEASE"
  echo "would point $REMOTE_ROOT/current at $STAMP"
  exit 0
fi

# --- copy ---------------------------------------------------------------------
#
# Into a new directory, never over the live one. `--delete` is deliberately
# absent: the target is empty by construction, and a --delete against the wrong
# path is the classic way to erase a server.

ssh "$TARGET" "mkdir -p '$RELEASE'"
rsync -a --checksum --chmod=D755,F644 "$DIST/" "$TARGET:$RELEASE/"

# The origin server itself, which changes rarely and lives outside the releases
# so a rollback of content does not roll back the server.
rsync -a --chmod=F644 "$REPO/site/serve.mjs" "$TARGET:$REMOTE_ROOT/serve.mjs"

# --- verify before swapping ----------------------------------------------------

ssh "$TARGET" bash -euo pipefail -s <<REMOTE
  test -f '$RELEASE/index.html' || { echo 'upload incomplete'; exit 1; }
  count=\$(find '$RELEASE' -type f | wc -l)
  echo "  \$count files on the origin"
REMOTE

# --- swap ----------------------------------------------------------------------
#
# `ln -sfn` followed by `mv -T` is the atomic form. Writing the symlink in place
# with `ln -sfn current` alone is not atomic and can be observed mid-change.

ssh "$TARGET" bash -euo pipefail -s <<REMOTE
  ln -sfn '$RELEASE' '$REMOTE_ROOT/.next'
  mv -T '$REMOTE_ROOT/.next' '$REMOTE_ROOT/current'
  echo "  current -> \$(readlink '$REMOTE_ROOT/current')"

  # Keep the last $KEEP releases so a rollback is a rename, not a rebuild.
  cd '$REMOTE_ROOT/releases'
  ls -1t | tail -n +$((KEEP + 1)) | xargs -r rm -rf
  echo "  \$(ls -1 | wc -l) releases retained"
REMOTE

# --- prove it is live ------------------------------------------------------------
#
# Against the origin over loopback, not against the public URL: this checks what
# was deployed, without Cloudflare's cache in the way.

ssh "$TARGET" bash -euo pipefail -s <<'REMOTE'
  code=$(curl -so /dev/null -w '%{http_code}' http://127.0.0.1:8787/)
  echo "  origin returns HTTP $code"
  [ "$code" = "200" ] || exit 1
  curl -sI http://127.0.0.1:8787/ | grep -i 'content-security-policy' >/dev/null \
    || { echo '  no CSP on the origin response'; exit 1; }
  echo '  CSP present'
REMOTE

echo "done. Public check: curl -sI https://leastgrant.xyz | head -20"
