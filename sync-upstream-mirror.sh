#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/GlobalNOC/wsc-python.git}"
DEST_URL="${DEST_URL:-https://github.grnoc.iu.edu/Shared/wsc-python.git}"
REPO_DIR="/tmp/wsc-python.git"

mkdir -p "$REPO_DIR"

pushd "$REPO_DIR" >/dev/null

if [[ "$(git rev-parse --is-bare-repository 2>/dev/null || true)" != "true" ]]; then
  git init --bare . >/dev/null
  git remote add origin "$UPSTREAM_URL"
  git config remote.origin.fetch '+refs/*:refs/*'
  git config --add remote.origin.fetch '^refs/pull/*'
fi

git fetch --prune origin
git push --mirror "$DEST_URL"

popd >/dev/null

echo "Mirrored $UPSTREAM_URL to $DEST_URL"
