"""RS256 JWT verifier for the assigned mock identity provider."""
from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from jwt import InvalidTokenError

EMAIL = "23f2000363@ds.study.iitm.ac.in"
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-kh25jpb4.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI(title="Assigned RS256 JWT Verifier", version="1.0.0")

# Add this middleware after CORSMiddleware so it is outermost and also adds
# metadata to CORS preflight responses and error responses.
@app.middleware("http")
async def request_metadata(request: Request, call_next) -> Response:
    request_id = str(uuid.uuid4())
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        # Keep the required headers even on unexpected server-side failures.
        response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
    elapsed = max(0.0, time.perf_counter() - start)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{elapsed:.6f}"
    return response


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/verify")
async def verify(payload: VerifyRequest) -> JSONResponse:
    try:
        claims: dict[str, Any] = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["iss", "aud", "exp", "email", "sub"]},
        )
        # Enforce exact audience equality (not merely a list containing it).
        if claims.get("aud") != AUDIENCE:
            raise InvalidTokenError("Audience must exactly match the assigned audience")

        return JSONResponse(
            status_code=200,
            content={
                "valid": True,
                "email": claims["email"],
                "sub": claims["sub"],
                "aud": claims["aud"],
            },
        )
    except (InvalidTokenError, TypeError, ValueError, KeyError):
        return JSONResponse(status_code=401, content={"valid": False})
