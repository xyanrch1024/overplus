@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "%~dp0tun_route.ps1 -Action cleanup"
pause
