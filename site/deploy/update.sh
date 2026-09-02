#!/usr/bin/env bash
#
# Rebuild leastgrant.xyz from main, if main has moved.
#
# Run by a systemd timer on the origin. Pull, not push: the origin fetches a
# public repository over HTTPS and needs no credential of any kind. Nothing has
# to be given to GitHub Actions, and in particular the Cloudflare Tunnel token
# stays where it belongs, on this machine and nowhere else.
#
# Idempotent by design. If main has not moved, this exits having done nothing,
# which is what it does on almost every run.
#
#   /srv/leastgrant/src        a clone of the public repo, only ever fast-forwarded
#   /srv/leastgrant/releases   one directory per built site
#   /srv/leastgrant/current    symlink to the live one
#
# The swap is a symlink rename, which is atomic. The previous release stays on
# disk, so a rollback is one rename and needs no network.

set -euo pipefail

ROOT=/srv/leastgrant
SRC="$ROOT/src"
REPO=https://github.com/leastgrant/leastgrant.git
BRANCH=main
KEEP=5

log() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

# --- get the source -----------------------------------------------------------

if [ ! -d "$SRC/.git" ]; then
  log "cloning $REPO"
  git clone --branch "$BRANCH" --single-branch "$REPO" "$SRC"
fi

cd "$SRC"

# Pin the remote. If it ever points somewhere else, this machine would rebuild
# its public website from a stranger's repository.
actual=$(git remote get-url origin)
[ "$actual" = "$REPO" ] || die "origin is $actual, expected $REPO"

before=$(git rev-parse HEAD)
git fetch --quiet --no-tags origin "$BRANCH"
after=$(git rev-parse "origin/$BRANCH")

if [ "$before" = "$after" ]; then
  log "main is unchanged at ${before:0:8}; nothing to do"
  exit 0
fi

# Fast-forward only. A force-push upstream should stop the deploy and be looked
# at by a person, not be applied silently to the live site.
git merge-base --is-ancestor "$before" "$after" \
  || die "origin/$BRANCH is not a fast-forward from ${before:0:8}; refusing to deploy"

log "main moved ${before:0:8} -> ${after:0:8}"
git checkout --quiet --force "$after"
git clean -qfdx -e node_modules

# --- build --------------------------------------------------------------------
#
# `--ignore-scripts`: the only dependencies are TypeScript and its types, and
# neither needs a lifecycle script to install. This is the machine that serves
# the site, so it runs as little foreign code as it can.

log "installing dependencies"
npm ci --ignore-scripts --no-audit --no-fund --silent

log "building"
npm run site:build --silent

DIST="$SRC/site/dist"
[ -f "$DIST/index.html" ] || die "the build produced no index.html"

# Sanity, not a full test run: the site build already asserts its own invariants
# and fails loudly. This catches the case where it succeeded but produced
# something obviously unusable.
for required in index.html 404.html robots.txt sitemap.xml og.png favicon.ico; do
  [ -f "$DIST/$required" ] || die "the build is missing $required"
done

# --- publish -------------------------------------------------------------------

STAMP="$(date -u +%Y%m%dT%H%M%SZ)-${after:0:8}"
RELEASE="$ROOT/releases/$STAMP"

mkdir -p "$RELEASE"
cp -a "$DIST/." "$RELEASE/"

ln -sfn "$RELEASE" "$ROOT/.next"
mv -T "$ROOT/.next" "$ROOT/current"
log "current -> $STAMP"

# The server reads from the symlink per request, so there is nothing to restart
# — not this service, and not cloudflared, whose local port never changes.
code=$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/ || echo 000)
[ "$code" = "200" ] || die "the origin returned $code after the swap"
log "origin returns 200"

cd "$ROOT/releases"
ls -1t | tail -n "+$((KEEP + 1))" | xargs -r rm -rf
log "$(ls -1 | wc -l) releases retained"
