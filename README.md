# RS256 JWT Verifier — Vercel deployment

A FastAPI service for the assigned mock IdP. It verifies the JWT signature using the supplied RS256 public key, enforces the exact issuer and audience, checks expiry, and returns the requested JSON. Every response receives `X-Request-ID` and `X-Process-Time`.

## Routes

- `POST /verify` with JSON `{"token":"<JWT>"}`. A valid token returns HTTP 200 and `valid`, `email`, `sub`, and `aud`. Invalid tokens return HTTP 401 with `{"valid":false}`.
- `GET /health` returns `{"status":"ok"}`.

## Deploy on Vercel

Vercel supports FastAPI and detects an app instance named `app` in a root-level `main.py`; this repository uses that entrypoint. Python 3.12 is selected via `.python-version`.

1. Create a new public or private Git repository on GitHub.
2. Upload the **contents of this folder** to the repository root (so `main.py`, `requirements.txt`, and `.python-version` are at the top level).
3. Open https://vercel.com/new and import the repository.
4. Keep the project root at the repository root, use the default detected settings, and deploy.
5. When deployment is ready, your endpoint is `https://YOUR-PROJECT.vercel.app/verify`.
6. Verify the deployed endpoint with a real freshly minted token from the grader. Do not share valid tokens publicly.

## Local development

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

## Tests

```bash
python -m pytest -q
```

The tests generate a disposable test key locally. The deployed service always uses the assigned public key in `main.py`.

## Hosting behavior

Vercel runs this FastAPI app as a serverless function and automatically scales with traffic. This avoids the exact Render free-web-service idle spin-down behavior, but serverless cold starts and platform limits can still occur; it is not a guarantee of an always-running process.
