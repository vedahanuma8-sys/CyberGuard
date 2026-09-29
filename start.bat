@echo off
title CyberGuard Threat Intelligence Platform
cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0start.ps1"
pause
