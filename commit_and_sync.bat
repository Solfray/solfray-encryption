@echo off
setlocal
cd /d "%~dp0"
rem Wall-clock stamp: seconds since the epoch at start, so the last line can
rem read "done in 2m 44s . done 2:52 PM" the way Claude Code signs off.
for /f %%t in ('powershell -NoProfile -Command "[int][double](Get-Date -UFormat %%s)"') do set "T0=%%t"

rem Deploy question comes FIRST so you never sit waiting on the git sync
rem before answering — the choice is remembered and applied at the end.
choice /c YN /m "Run deploy.bat after the sync"
set "DO_DEPLOY=%errorlevel%"

rem Rebuild dist/ before looking for changes, so a source edit is always
rem committed together with the vault build and SHA256SUMS it produces.
if not exist node_modules (
    call npm ci
    if errorlevel 1 goto :fail
)
echo Rebuilding vault...
call npm run build:vault
if errorlevel 1 goto :fail

rem Bail out early if there is nothing to commit
git status --porcelain | findstr . >nul
if errorlevel 1 (
    echo No changes to commit.
    goto :maybe_deploy
)

set "MSG="
set /p MSG=Commit message:
if "%MSG%"=="" (
    echo Commit message cannot be empty. Aborting.
    exit /b 1
)

echo.
echo Staging all changes...
git add -A
if errorlevel 1 goto :fail

echo Committing...
git commit -m "%MSG%"
if errorlevel 1 goto :fail

echo Syncing (pull then push)...
git pull
if errorlevel 1 goto :fail
git push
if errorlevel 1 goto :fail

echo.
echo Commit and sync complete.
powershell -NoProfile -Command "$e=[int][double](Get-Date -UFormat %%s)-%T0%; $d=[char]0x00B7; 'Committed and synced in {0}m {1}s {2} done {3}' -f [math]::Floor($e/60),($e %% 60),$d,(Get-Date -Format 'h:mm tt')"

:maybe_deploy
if "%DO_DEPLOY%"=="2" (
    echo Skipping deploy.
    goto :finish
)
echo.
echo Running deploy.bat (chosen at start)...
call deploy.bat
if errorlevel 1 exit /b 1

:finish
powershell -NoProfile -Command "$e=[int][double](Get-Date -UFormat %%s)-%T0%; $d=[char]0x00B7; 'Finished in {0}m {1}s {2} done {3}' -f [math]::Floor($e/60),($e %% 60),$d,(Get-Date -Format 'h:mm tt')"
exit /b 0

:fail
echo.
echo ERROR: a command failed. See output above.
exit /b 1
