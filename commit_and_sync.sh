#!/usr/bin/env bash
# Commit, pull, push, then optionally deploy the vault. Linux port of
# commit_and_sync.bat. The deploy question is asked first so the git sync
# is not sitting on an unanswered prompt.

set -u
cd "$(dirname "$0")"

T0="$(date +%s)"
stamp() {
  local label="$1" e
  e="$(( $(date +%s) - T0 ))"
  printf '%s in %dm %ds · done %s\n' "$label" "$((e / 60))" "$((e % 60))" "$(date +'%-I:%M %p')"
}
fail() {
  echo
  echo "ERROR: a command failed. See output above."
  exit 1
}
ask() {
  local prompt="$1" answer
  while true; do
    read -r -p "$prompt [y/n] " answer
    case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
    esac
    echo "Please answer y or n."
  done
}

if ask "Run deploy.sh after the sync"; then DO_DEPLOY=1; else DO_DEPLOY=0; fi

# Rebuild dist/ before looking for changes, so a source edit is always
# committed together with the vault build and SHA256SUMS it produces.
if [[ ! -d node_modules ]]; then
  npm ci || fail
fi
echo "Rebuilding vault..."
npm run build:vault || fail

if [[ -z "$(git status --porcelain)" ]]; then
  echo "No changes to commit."
else
  read -r -p "Commit message: " MSG
  if [[ -z "${MSG}" ]]; then
    echo "Commit message cannot be empty. Aborting."
    exit 1
  fi

  echo
  echo "Staging all changes..."
  git add -A || fail

  echo "Committing..."
  git commit -m "$MSG" || fail

  echo "Syncing (pull then push)..."
  git pull || fail
  git push || fail

  echo
  echo "Commit and sync complete."
  stamp "Committed and synced"
fi

if [[ "$DO_DEPLOY" -eq 0 ]]; then
  echo "Skipping deploy."
else
  echo
  echo "Running deploy.sh (chosen at start)..."
  ./deploy.sh || exit 1
fi

stamp "Finished"
exit 0
