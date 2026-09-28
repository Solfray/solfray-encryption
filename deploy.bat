@echo off
rem Deploy the key vault (keys.solfray.com) as its own static-assets Worker
rem (wrangler.jsonc, no script). See README "Deploy keys.solfray.com".
rem Not connected to git: this script is the only way in.

rem Node resolves registry.npmjs.org to IPv6 first and, on this machine, a
rem TLS request over that IPv6 path never completes. Wrangler's post-command
rem "newer version available?" check then keeps the process alive forever.
rem Prefer IPv4 for every node process this script spawns.
set NODE_OPTIONS=--dns-result-order=ipv4first
rem Wall-clock stamp: seconds since the epoch at start, so the last line can
rem read "done in 2m 44s . done 2:52 PM" the way Claude Code signs off.
for /f %%t in ('powershell -NoProfile -Command "[int][double](Get-Date -UFormat %%s)"') do set "T0=%%t"

cd /d "%~dp0"

if not exist node_modules (
    echo === Installing dependencies ===
    call npm ci
    if errorlevel 1 goto :fail
    echo.
)

echo === 1/4 Typecheck and crypto self-test ===
call npm run typecheck
if errorlevel 1 goto :fail
call npm test
if errorlevel 1 goto :fail

echo.
echo === 2/4 Building vault ===
call npm run build:vault
if errorlevel 1 goto :fail

echo.
echo === 3/4 Checking dist matches the commit ===
rem The public repo's SHA256SUMS is the promise: the live vault must be
rem byte-for-byte what anyone gets by rebuilding this commit. Refuse to
rem ship a dist/ that is not committed.
git status --porcelain -- dist SHA256SUMS | findstr . >nul
if not errorlevel 1 (
    git status --short -- dist SHA256SUMS
    echo.
    echo The rebuilt dist/ differs from what is committed. Commit it first
    echo ^(commit_and_sync.bat^) so the public hashes match the live vault.
    goto :fail
)

echo.
echo === 4/4 Deploying Worker static assets (solfray-keys) ===
call npx.cmd wrangler deploy
if errorlevel 1 goto :fail

echo.
echo === Deploy complete. Keyring page should show: ===
type SHA256SUMS
powershell -NoProfile -Command "$e=[int][double](Get-Date -UFormat %%s)-%T0%; $d=[char]0x00B7; 'Deployed in {0}m {1}s {2} done {3}' -f [math]::Floor($e/60),($e %% 60),$d,(Get-Date -Format 'h:mm tt')"
exit /b 0

:fail
echo.
echo *** DEPLOY FAILED — see the error above. Nothing after the failed step ran. ***
powershell -NoProfile -Command "$e=[int][double](Get-Date -UFormat %%s)-%T0%; $d=[char]0x00B7; 'Failed in {0}m {1}s {2} done {3}' -f [math]::Floor($e/60),($e %% 60),$d,(Get-Date -Format 'h:mm tt')"
exit /b 1
