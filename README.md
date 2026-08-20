# AEGIS

AEGIS is an AI-powered personal cybersecurity dashboard for inspecting common security risks and presenting actionable security information in one place.

## Status

The repository currently contains the initial project scaffold. Feature implementation will be added incrementally by the team.

## Technology Stack

- Frontend: React
- Backend: FastAPI with Python
- Database: MySQL
- AI services: Gemini API
- Authentication: JWT
- Communication: REST APIs

## Repository Structure

```text
frontend/    React application
backend/     FastAPI application and backend tests
database/    MySQL schema, seed data, and migrations
docs/        Requirements, diagrams, research, and reports
tests/       Cross-layer frontend and backend tests
scripts/     Development and maintenance scripts
```

Backend feature modules are organized by responsibility under `backend/app/`, with API routes, core configuration, models, services, and utilities kept separate.

## Requirements

- Python 3.12+
- UV
- Node.js and npm
- MySQL 8+
- A Gemini API key for AI functionality

## Configuration

Copy `.env.example` to `.env` and fill in the local values. Never commit `.env` or other secret files.

## Backend Setup

```powershell
uv venv
.venv\Scripts\Activate.ps1
uv pip install -r backend\requirements.txt
uvicorn backend.app.main:app --reload
```

## Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

The frontend development server will print its local URL. The backend API is available at `http://127.0.0.1:8000` by default.

## Team Workflow

Keep feature work modular, add tests with each increment, and update the relevant documentation when an API or database contract changes.
