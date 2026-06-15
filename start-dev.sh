#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

if [ ! -d "$FRONTEND_DIR" ]; then
  FRONTEND_DIR="/Users/vanshmehndiratta/securereview-ai/frontend"
fi

echo "======================================"
echo "  SecureReview AI - Developer Setup"
echo "======================================"
echo ""

echo "[1/6] Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required"; exit 1; }
command -v node >/dev/null 2>&1 || { echo "ERROR: node required"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "ERROR: npm required"; exit 1; }
echo "  Python $(python3 --version | awk '{print $2}') | Node $(node --version)"

echo ""
echo "[2/6] Checking Redis..."
if nc -z localhost 6379 2>/dev/null; then
  echo "  Redis is already running"
else
  echo "  Starting Redis via Docker..."
  docker compose -f "$ROOT_DIR/docker-compose.dev.yml" up -d redis 2>/dev/null || \
  docker run -d --name securereview-redis -p 6379:6379 redis:7-alpine 2>/dev/null || \
  echo "  WARNING: Redis not available"
fi

echo ""
echo "[3/6] Setting up Python virtual environment..."
if [ ! -f "$BACKEND_DIR/venv/bin/activate" ]; then
  python3 -m venv "$BACKEND_DIR/venv"
  echo "  Created virtual environment"
fi
source "$BACKEND_DIR/venv/bin/activate"
pip install -q -r "$BACKEND_DIR/requirements.txt" 2>&1 | tail -1 || true

if grep -q "sqlite" "$BACKEND_DIR/.env" 2>/dev/null; then
  echo "  Using SQLite (no database server needed)"
fi

echo ""
echo "[4/6] Setting up frontend..."
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
  (cd "$FRONTEND_DIR" && npm install --silent)
  echo "  Frontend dependencies installed"
else
  echo "  Frontend dependencies already installed"
fi

if [ ! -f "$FRONTEND_DIR/package-lock.json" ]; then
  (cd "$FRONTEND_DIR" && npm install --package-lock-only --silent)
  echo "  package-lock.json generated"
fi

echo ""
echo "[5/7] Starting backend..."
source "$BACKEND_DIR/venv/bin/activate"
cd "$BACKEND_DIR"
PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo "  Backend starting on http://localhost:8000"

sleep 3

echo ""
echo "[6/7] Seeding database..."
cd "$BACKEND_DIR"
PYTHONPATH=. python3 scripts/seed.py 2>&1 | sed 's/^/  /'
echo "  Seed complete"

echo ""
echo "[7/7] Starting frontend..."
cd "$FRONTEND_DIR"
npx vite --host 0.0.0.0 --port 5173 &
FRONTEND_PID=$!
echo "  Frontend starting on http://localhost:5173"

sleep 2

echo ""
echo "======================================"
echo "  SecureReview AI is running!"
echo "  Frontend: http://localhost:5173"
echo "  Backend:  http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo "======================================"
echo ""
echo "Press Ctrl+C to stop all services"

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM
wait
