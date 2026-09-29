#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo -e "\033[1;36m============================================================\033[0m"
echo -e "\033[1;36m   CyberGuard Threat Intelligence SOC - Launch Orchestrator\033[0m"
echo -e "\033[1;36m============================================================\033[0m"

# Trap signals for graceful shutdown
cleanup() {
    echo -e "\n\033[1;33mStopping CyberGuard services...\033[0m"
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    echo -e "\033[1;32m[OK] All CyberGuard services terminated.\033[0m"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Activate backend environment if available
if [ -d "$DIR/backend/venv" ]; then
    source "$DIR/backend/venv/bin/activate"
fi

# 2. Launch FastAPI backend
echo -e "\033[1;32m[+] Starting FastAPI ML Engine on http://127.0.0.1:8000...\033[0m"
cd "$DIR/backend"
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!

# 3. Check and launch Next.js frontend
echo -e "\033[1;32m[+] Starting Next.js SOC Dashboard on http://localhost:3000...\033[0m"
cd "$DIR/frontend"
if [ ! -d "node_modules" ]; then
    echo -e "\033[1;33m[INFO] Installing frontend dependencies...\033[0m"
    npm install
fi

npm run dev &
FRONTEND_PID=$!

sleep 2

echo -e "\n\033[1;36m============================================================\033[0m"
echo -e "\033[1;32m           CYBERGUARD SERVICES ACTIVE & RUNNING             \033[0m"
echo -e "\033[1;36m============================================================\033[0m"
echo -e "  * SOC Web Console:       \033[1;34mhttp://localhost:3000\033[0m"
echo -e "  * FastAPI Swagger Docs:  \033[1;34mhttp://127.0.0.1:8000/docs\033[0m"
echo -e "  * System Health Probe:   \033[1;34mhttp://127.0.0.1:8000/health\033[0m"
echo -e "\033[1;36m============================================================\033[0m"
echo -e "\033[1;33mPress [Ctrl+C] to gracefully stop all services.\n\033[0m"

wait
