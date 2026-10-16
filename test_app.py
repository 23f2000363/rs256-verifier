import base64
import json
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import main


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def setup_module():
    # Use a disposable test-only key pair; production still uses the assigned key.
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    main.PUBLIC_KEY = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    main.TEST_PRIVATE_KEY = private


def token(**overrides):
    claims = {
        "iss": main.ISSUER,
        "aud": main.AUDIENCE,
        "exp": int(time.time()) + 300,
        "email": "23f2000363@ds.study.iitm.ac.in",
        "sub": "user-123",
    }
    claims.update(overrides)
    return jwt.encode(claims, main.TEST_PRIVATE_KEY, algorithm="RS256")


client = TestClient(main.app)


def assert_common_headers(response):
    assert response.headers.get("X-Request-ID")
    assert float(response.headers["X-Process-Time"]) >= 0


def test_valid_token_echoes_claims():
    response = client.post("/verify", json={"token": token()})
    assert response.status_code == 200
    assert response.json() == {
        "valid": True,
        "email": "23f2000363@ds.study.iitm.ac.in",
        "sub": "user-123",
        "aud": main.AUDIENCE,
    }
    assert_common_headers(response)


def test_expired_token_rejected():
    response = client.post("/verify", json={"token": token(exp=int(time.time()) - 10)})
    assert response.status_code == 401
    assert response.json() == {"valid": False}
    assert_common_headers(response)


def test_wrong_audience_rejected():
    response = client.post("/verify", json={"token": token(aud="wrong.audience")})
    assert response.status_code == 401
    assert response.json() == {"valid": False}


def test_tampered_payload_rejected():
    original = token()
    header, payload, signature = original.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["sub"] = "tampered-subject"
    tampered = f"{header}.{b64url(json.dumps(claims, separators=(',', ':')).encode())}.{signature}"
    response = client.post("/verify", json={"token": tampered})
    assert response.status_code == 401
    assert response.json() == {"valid": False}


def test_audience_list_rejected_when_not_exact_string():
    response = client.post("/verify", json={"token": token(aud=[main.AUDIENCE, "other"])})
    assert response.status_code == 401
    assert response.json() == {"valid": False}


