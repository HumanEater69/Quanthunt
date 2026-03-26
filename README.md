# QuantumShield MVP

FastAPI + scanner engine + glass/clay neon dashboard for HNDL-focused PQC posture assessment.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Open: `http://localhost:8000`

## Deployment Revamp (Vercel + Backend Hook)

This repo has been cleaned up to remove Netlify/Azure deployment paths.

- Frontend deploy target: Vercel
- Backend deploy target: provider deploy hook (recommended: Koyeb FastAPI service)

### Current Deployment Workflows

- `.github/workflows/frontend-vercel.yml`
- `.github/workflows/backend-deploy.yml`

Both workflows enforce backend regression tests (`tests.test_offline_and_scoring`) before deployment.

### Frontend (Vercel)

The frontend is deployed from the `frontend/` directory. Vercel routing is configured in:

- `frontend/vercel.json`

It rewrites `/api/*` to the backend candidate origin:

- `https://quanthunt-backend.koyeb.app/api/*`

Required GitHub secrets for frontend workflow:

- `VERCEL_TOKEN`
- `VERCEL_ORG_ID`
- `VERCEL_PROJECT_ID`

### Backend (Free Candidate)

Backend workflow triggers a provider deploy hook and probes health on:

- `${BACKEND_ORIGIN}/api/scans`

Optional keepalive workflow:

- `.github/workflows/backend-keepalive.yml` (scheduled ping every 10 minutes)

Required GitHub secrets for backend workflow:

- `BACKEND_DEPLOY_HOOK_URL`
- `BACKEND_ORIGIN`

Recommended backend candidate for current FastAPI codebase:

- Koyeb (container deployment from this repo's Dockerfile)

### Cloudflare vs AWS Free Constraints (Before Finalizing)

Cloudflare Workers (from Workers pricing/docs):

- No credit card needed on free plan
- Free tier includes request/usage limits (for example 100,000 daily requests)
- Best for edge/serverless patterns, but this backend is a stateful FastAPI app and would require a major runtime refactor to fit Workers constraints

AWS Free Tier (from AWS Free page):

- Time/credit constrained for new accounts (up to 6 months with credits model shown)
- Not a clean "forever free" path for an always-on web backend
- Account setup and billing model are less aligned with strict "no card + 24/7 always-on" requirement

Decision for this repo:

- Use Vercel for frontend
- Use Koyeb as backend candidate via deploy hook for a FastAPI-native deployment path with minimal code change

### One-time GitHub Secrets Setup

You can configure required secrets in one command:

```powershell
scripts\setup_github_secrets_vercel_backend.ps1 \
	-Repo "HumanEater69/QuantHunt" \
	-VercelToken "<vercel-token>" \
	-VercelOrgId "<vercel-org-id>" \
	-VercelProjectId "<vercel-project-id>" \
	-BackendDeployHookUrl "<backend-deploy-hook-url>" \
	-BackendOrigin "https://quanthunt-backend.koyeb.app"
```

## Deep Clean Smoke Test (One Command)

Runs a clean temporary server process and executes scripted end-to-end checks for:
- standalone scan completion
- fleet scan completion
- network/VPN status endpoint

```powershell
scripts\deep-clean.cmd
```

Optional flags:

```powershell
scripts\deep-clean.cmd --scan-timeout 300 --port 8014
```

## Optional Production Mode (Celery + Redis)

```powershell
$env:USE_CELERY="true"
$env:REDIS_URL="redis://localhost:6379/0"
celery -A backend.tasks worker --loglevel=info
uvicorn backend.main:app --reload --port 8000
```

## Optional Claude Integration

```powershell
$env:ANTHROPIC_API_KEY="your_key"
$env:ANTHROPIC_MODEL="claude-3-5-sonnet-latest"
```

If `ANTHROPIC_API_KEY` is not set, deterministic fallback recommendations are used.

## Optional QuantHunt (OpenAI)

```powershell
$env:OPENAI_API_KEY="your_openai_api_key"
$env:OPENAI_MODEL="gpt-4.1-mini"
```

QuantHunt endpoint: `POST /api/quanthunt/chat`

## Included Features

- Asset discovery via `crt.sh` + DNS brute-force
- TLS handshake inspection (version/cipher/certificate metadata)
- API endpoint checks (common ports, JWT alg parsing, security headers)
- PQC/HNDL score engine with weighted formula
- CycloneDX 1.6 style CBOM export
- SQL-backed persistence tables: scans, assets, crypto_findings, recommendations, cbom_exports
- Optional Celery + Redis queue execution
- Server-side PDF report export (`/api/scan/{scan_id}/report.pdf`)
- Optional Claude-generated recommendations
- QuantHunt chat assistant tab powered by OpenAI API key (server-side)
- Chart.js radar and leaderboard visuals
- Dashboard tabs: Scanner, Asset Map, Crypto Analysis, CBOM, Roadmap, Docs
