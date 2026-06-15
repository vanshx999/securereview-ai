# SecureReview AI

AI-powered code review & security platform for enterprises.

## Quick Start (one command)

```bash
./start-dev.sh
```

This will:
1. Check prerequisites (Python 3, Node.js, npm)
2. Start Redis via Docker (if not already running)
3. Create Python venv and install dependencies
4. Install frontend dependencies
5. Generate package-lock.json
6. Start backend (uvicorn on :8000) and frontend (Vite on :5173)

Then open **http://localhost:5173** in your browser.

## Prerequisites

- **Python 3.12+**
- **Node.js 18+**
- **npm**
- **Docker** (for Redis — optional but recommended)

## Project Structure

```
securereview-ai/
├── backend/                  # FastAPI Python backend
│   ├── app/
│   │   ├── main.py          # Entry point, lifespan, CORS
│   │   ├── config.py        # Settings from env vars
│   │   ├── database.py      # SQLAlchemy async engine
│   │   ├── models/          # SQLAlchemy models
│   │   ├── routers/         # API route handlers
│   │   ├── services/        # Business logic
│   │   └── middleware/      # Auth, rate limit, webhook verification
│   ├── alembic/             # Database migrations
│   ├── .env                 # Environment config
│   └── requirements.txt
├── ../securereview-frontend/ # React + TypeScript + Vite frontend
├── docker-compose.yml       # Full production stack
├── docker-compose.dev.yml   # Redis only (for local dev)
├── Makefile                 # Convenience commands
└── start-dev.sh             # Single-command dev setup
```

## Manual Setup

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Database: uses SQLite by default (no setup needed)
# Tables are auto-created on first startup via init_db()

uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd ../securereview-frontend  # or wherever it is
npm install
npm run dev
```

## Available Commands

```bash
make dev        # Full dev setup + start (same as ./start-dev.sh)
make backend    # Start backend only
make frontend   # Start frontend only
make redis      # Start Redis via Docker
make stop       # Stop Redis container
make clean      # Remove venv, node_modules, db
```

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./securereview.db` | Database connection |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis (rate limiting, celery) |
| `JWT_SECRET` | — | JWT signing key (change in prod) |
| `STRIPE_SECRET_KEY` | — | Stripe billing (optional) |
| `GITHUB_CLIENT_ID` | — | GitHub OAuth app (optional) |

## API Documentation

When the backend is running:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health**: http://localhost:8000/api/health

## Database

**Local dev** uses SQLite — zero configuration. The file `backend/securereview.db` is auto-created.

**Production** should use PostgreSQL. Set `DATABASE_URL` in `.env`:

```
DATABASE_URL=postgresql+asyncpg://user:password@host:5432/securereview
```

### Alembic Migrations

```bash
cd backend
source venv/bin/activate
PYTHONPATH=. alembic upgrade head
```

## Frontend

The frontend proxies `/api/*` requests to `http://localhost:8000` during development (configured in `vite.config.ts`).

## Docker (Production)

```bash
docker compose up --build
```

## Tests

```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest
```
