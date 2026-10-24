@echo off
rem Removes expired certificates and CryptoPro key containers.
rem Shows the list first; deletes only after you type "да".
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0udalit-prosrochennye-ep.ps1" -Delete -Containers
pause
