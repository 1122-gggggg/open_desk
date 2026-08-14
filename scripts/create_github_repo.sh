#!/usr/bin/env bash
set -euo pipefail

OWNER="${GITHUB_OWNER:-1122-gggggg}"
REPO="${GITHUB_REPO:-latencydesk}"
VISIBILITY="${GITHUB_VISIBILITY:-public}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is not installed" >&2
  exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "gh CLI is not authenticated" >&2
  exit 3
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git init -b main
fi

git add .
if ! git diff --cached --quiet; then
  git -c user.name="$OWNER" -c user.email="$OWNER@users.noreply.github.com" \
    commit -m "chore: establish audited LatencyDesk M0 architecture"
fi

if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  git remote remove origin >/dev/null 2>&1 || true
  git remote add origin "https://github.com/$OWNER/$REPO.git"
else
  gh repo create "$OWNER/$REPO" \
    --"$VISIBILITY" \
    --description "Latency-first open-source Windows↔Linux remote desktop engine with native Wayland support" \
    --source . \
    --remote origin
fi

git push -u origin main

gh repo edit "$OWNER/$REPO" \
  --description "Latency-first open-source Windows↔Linux remote desktop engine with native Wayland support" \
  --add-topic remote-desktop \
  --add-topic rust \
  --add-topic wayland \
  --add-topic windows \
  --add-topic pipewire \
  --add-topic quic \
  --add-topic low-latency

echo "https://github.com/$OWNER/$REPO"
