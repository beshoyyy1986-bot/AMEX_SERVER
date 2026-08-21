# Base44 Dev Environment

## Overview
Single-file Node.js/Express app (`server.js`) — a Facebook BM card/proxy management tool with an admin dashboard and API-key-gated endpoints. No database; file-based storage in `/data` (JSON files). No build step.

## Run
```
docker compose -f docker-compose.base44.yml up -d
```
- Web service: `node:18`, runs `npm install && npx nodemon server.js` (live reload via nodemon).
- Source bind-mounted at `/app`; edits hot-reload without rebuild.
- Host port 3000 → container 3000.
- Persistent data volume `data` mounted at `/data`.

## Health checks
- `GET /` → JSON status
- `GET /ping` → `{ ok: true }`
- `GET /admin` → admin login page (HTML)

## Environment
- `ADMIN_PASS` — admin panel password. Defaults to `admin123` via `.env.base44-defaults`; override via secrets (`/run/base44/app.env`).
- `BRIGHT_DATA_KEY` / `BRIGHT_DATA_ZONE` / `USE_BRIGHT_DATA` — optional Bright Data proxy service. Off by default; not required to boot.
- `ALLOWED_ORIGINS` — set to `*` for dev so the preview origin is accepted.
- `DATA_DIR` — defaults to `/data`.

## Notes
- CORS is origin-checked; `ALLOWED_ORIGINS=*` is required for the preview to call API endpoints from the browser.
- No external services are required to boot. Bright Data is the only optional external credential.
