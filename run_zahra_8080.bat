@echo off
cd /d "%~dp0"
python main.py serve --port 8080 --host 0.0.0.0
pause
