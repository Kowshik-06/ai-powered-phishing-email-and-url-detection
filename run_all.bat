@echo off
setlocal
start "ML Service" cmd /k "cd /d %~dp0ml-service && if not exist .venv python -m venv .venv && call .venv\Scripts\activate && pip install -r requirements.txt && python api.py"
timeout /t 3 >nul
start "Backend" cmd /k "cd /d %~dp0backend && npm install && npm start"
timeout /t 3 >nul
start "Frontend" cmd /k "cd /d %~dp0 && npm install && npm start"
endlocal
