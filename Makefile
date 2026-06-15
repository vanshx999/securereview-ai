.PHONY: dev backend frontend redis stop clean

dev: redis
	@echo "Starting backend + frontend..."
	@./start-dev.sh

redis:
	@echo "Starting Redis..."
	@docker compose -f docker-compose.dev.yml up -d redis 2>/dev/null || docker run -d --name securereview-redis -p 6379:6379 redis:7-alpine 2>/dev/null || true

backend:
	@echo "Starting backend..."
	cd backend && ./venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

frontend:
	@echo "Starting frontend..."
	cd ../securereview-frontend && npm run dev

stop:
	@echo "Stopping containers..."
	-docker compose -f docker-compose.dev.yml down 2>/dev/null
	-docker stop securereview-redis 2>/dev/null || true
	-docker rm securereview-redis 2>/dev/null || true

clean:
	@echo "Cleaning up..."
	-rm -rf backend/venv
	-rm -rf ../securereview-frontend/node_modules
	-rm -rf backend/__pycache__ backend/app/__pycache__
	-rm -f backend/securereview.db

setup:
	@echo "Installing Python deps..."
	cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
	@echo "Installing frontend deps..."
	cd ../securereview-frontend && npm install
