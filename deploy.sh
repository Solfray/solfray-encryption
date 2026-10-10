#!/usr/bin/env bash
# Deploy the key vault (keys.solfray.com) as its own static-assets Worker
# (wrangler.jsonc, no script). Linux port of deploy.bat. See README
# "Deploy keys.solfray.com". Not connected to git: this script and
# deploy.bat are the only way in. The main Solfray deploy.sh does not
# touch this hostname.
#
# Deploy this BEFORE the Solfray Worker and web app whenever src/ or vault/
# changed: the web app pins this build's vault.js hash, and the Worker
# refuses epoch bodies an older vault would produce.

set -u
cd "$(dirname "$0")"

# Node resolves registry.npmjs.org to IPv6 first and, on some machines, a
# TLS request over that path never completes. Wrangler's post-command
# update check then keeps the process alive. Prefer IPv4 everywhere.
export NODE_OPTIONS="--dns-result-order=ipv4first"
# The login can see two Cloudflare accounts. solfray-keys and the
# solfray.com zone live on Larry's, the same one the main deploy.sh uses.
export CLOUDFLARE_ACCOUNT_ID="0d67ca7f916519e7f339c1a232d4794a"

node_major="$(node -p "Number(process.versions.node.split('.')[0])" 2>/dev/null || echo 0)"
if [[ "$node_major" -lt 22 ]]; then
  echo "Node $(node -v 2>/dev/null || echo missing) is too old. Wrangler 4 needs Node 22 or newer."
  exit 1
fi

T0="$(date +%s)"
stamp() {
  local label="$1" e
  e="$(( $(date +%s) - T0 ))"
  printf '%s in %dm %ds · done %s\n' "$label" "$((e / 60))" "$((e % 60))" "$(date +'%-I:%M %p')"
}
fail() {
  echo
  echo "*** DEPLOY FAILED. See the error above. Nothing after the failed step ran. ***"
  stamp "Failed"
  exit 1
}

echo "=== 1/6 Installing exact locked dependencies ==="
# Always a clean install from package-lock.json, never whatever happens to
# be sitting in node_modules: a stale or tampered tree cannot ship.
npm ci || fail

echo
echo "=== 2/6 Patching known vulnerabilities ==="
# Patch first, then gate: nothing deploys while npm audit still reports an
# advisory, and nothing deploys from a lockfile that is not committed (the
# public must be able to rebuild this commit byte for byte).
npm audit fix
if ! npm audit; then
  echo
  echo "npm audit still reports vulnerabilities (or could not reach the"
  echo "registry). Resolve them before deploying."
  fail
fi
if [[ -n "$(git status --porcelain -- package.json package-lock.json)" ]]; then
  git status --short -- package.json package-lock.json
  echo
  echo "Dependencies were patched or differ from what is committed. Commit"
  echo "them first (commit_and_sync.sh), then deploy again."
  fail
fi

echo
echo "=== 3/6 Typecheck and crypto self-test ==="
npm run typecheck || fail
npm test || fail

echo
echo "=== 4/6 Building vault ==="
npm run build:vault || fail

echo
echo "=== 5/6 Checking dist matches the commit ==="
# The public repo's SHA256SUMS is the promise: the live vault must be byte
# for byte what anyone gets by rebuilding this commit. Refuse to ship a
# dist/ that is not committed.
if [[ -n "$(git status --porcelain -- dist SHA256SUMS)" ]]; then
  git status --short -- dist SHA256SUMS
  echo
  echo "The rebuilt dist/ differs from what is committed. Commit it first"
  echo "(commit_and_sync.sh) so the public hashes match the live vault."
  fail
fi

echo
echo "=== 6/6 Deploying Worker static assets (solfray-keys) ==="
npx wrangler deploy || fail

echo
echo "=== Deploy complete. The Keyring page's vaultHash.ts must say: ==="
cat SHA256SUMS
stamp "Deployed"
exit 0
