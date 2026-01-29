@echo off
REM Quick GitHub Push Script for CTF-AI Ultimate v2.1 (Windows)
REM Double-click this file to push all updates to GitHub

echo.
echo ========================================
echo   CTF-AI Ultimate v2.1 - GitHub Push
echo ========================================
echo.

REM Check if git is installed
where git >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Git is not installed!
    echo Download from: https://git-scm.com/download/win
    pause
    exit /b 1
)

REM Check if we're in a git repository
if not exist .git (
    echo ERROR: Not a git repository!
    echo Run: git init
    pause
    exit /b 1
)

REM Show what will be committed
echo Files to be committed:
echo.
git status --short
echo.

REM Ask for confirmation
set /p CONFIRM="Push these changes to GitHub? (y/n): "
if /i not "%CONFIRM%"=="y" (
    echo Push cancelled
    pause
    exit /b 0
)

echo.
echo [1/4] Adding files...
git add .

echo [2/4] Committing changes...
git commit -m "Release v2.1: Interactive Menu Mode + AI Guidance + Beautiful Colors" -m "New Features:" -m "- Interactive menu with 9 challenge categories" -m "- AI-powered guidance for each challenge type" -m "- Beautiful colorful interface with 40+ emojis" -m "- File type detection and analysis" -m "- Challenge description support" -m "- Fixed Kali Linux update script"

echo [3/4] Pushing to GitHub...
git push origin main
if %ERRORLEVEL% NEQ 0 (
    echo Trying master branch...
    git push origin master
)

echo [4/4] Creating version tag...
git tag -a v2.1 -m "Version 2.1: Interactive Menu Mode + AI Guidance"
git push origin v2.1

echo.
echo ========================================
echo   SUCCESS! Pushed to GitHub
echo ========================================
echo.
echo Tell your friends to update:
echo   git pull origin main
echo   ./update.sh
echo.
echo Done!
echo.
pause
