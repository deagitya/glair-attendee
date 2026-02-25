import base64
import hashlib
import json
import logging
import secrets
import string
import time

import jwt
import redis
from cryptography.hazmat.primitives import serialization
from django.conf import settings

logger = logging.getLogger(__name__)

OIDC_SIGNING_KID = "attendee-oidc-signing-key"


def _get_redis_client():
    return redis.from_url(settings.REDIS_URL_WITH_PARAMS)


def _get_global_private_key():
    """Load the global OIDC signing private key from settings."""
    pem = settings.OIDC_RSA_PRIVATE_KEY_PEM
    if not pem:
        raise ValueError("OIDC_RSA_PRIVATE_KEY_B64 environment variable is not configured")
    return serialization.load_pem_private_key(pem.encode(), password=None)


def generate_oidc_credentials():
    """
    Generate OIDC client credentials for a new GoogleMeetBotLogin.
    Returns (client_id, client_secret_raw, client_secret_hash).
    No per-login private key — the global signing key is used for id_tokens.
    """
    # Generate client_id with oidc_ prefix
    random_part = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    client_id = f"oidc_{random_part}"

    # Generate client_secret (48-char random)
    client_secret_raw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))
    client_secret_hash = hashlib.sha256(client_secret_raw.encode()).hexdigest()

    return client_id, client_secret_raw, client_secret_hash


def build_oidc_discovery_document(issuer_url):
    """Return an OIDC discovery document dict."""
    return {
        "issuer": issuer_url,
        "authorization_endpoint": f"{issuer_url}/authorize",
        "token_endpoint": f"{issuer_url}/token",
        "jwks_uri": f"{issuer_url}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "email", "iss", "aud", "iat", "exp", "nonce"],
        "code_challenge_methods_supported": ["S256"],
    }


def create_oidc_authorization_code(session_id, client_id, redirect_uri, nonce=None, code_challenge=None, code_challenge_method=None):
    """
    Generate a random authorization code and store metadata in Redis with 5-min TTL.
    Returns the authorization code string.
    """
    code = secrets.token_urlsafe(32)
    redis_client = _get_redis_client()
    code_data = {
        "session_id": session_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }
    if nonce:
        code_data["nonce"] = nonce
    if code_challenge:
        code_data["code_challenge"] = code_challenge
    if code_challenge_method:
        code_data["code_challenge_method"] = code_challenge_method

    redis_key = f"oidc_auth_code:{code}"
    redis_client.setex(redis_key, 300, json.dumps(code_data))  # 5-min TTL
    return code


def exchange_oidc_authorization_code(code):
    """
    Atomically consume an authorization code from Redis (single-use).
    Returns the code data dict or None if invalid/expired/already used.
    """
    redis_client = _get_redis_client()
    redis_key = f"oidc_auth_code:{code}"

    pipe = redis_client.pipeline()
    pipe.get(redis_key)
    pipe.delete(redis_key)
    results = pipe.execute()

    raw_data = results[0]
    if not raw_data:
        return None

    return json.loads(raw_data)


def build_oidc_id_token(email, client_id, issuer_url, nonce):
    """
    Create a signed JWT (RS256) id_token using the global signing key.
    """
    now = int(time.time())
    payload = {
        "iss": issuer_url,
        "sub": email,
        "aud": client_id,
        "email": email,
        "iat": now,
        "exp": now + 3600,  # 1 hour
    }
    if nonce:
        payload["nonce"] = nonce

    private_key = _get_global_private_key()
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": OIDC_SIGNING_KID})
    return token


def build_jwks_response():
    """
    Build a JWKS response containing the single global signing public key.
    """
    private_key = _get_global_private_key()
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    def _int_to_base64url(n, length=None):
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
        if length and len(n_bytes) < length:
            n_bytes = b"\x00" * (length - len(n_bytes)) + n_bytes
        return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": OIDC_SIGNING_KID,
                "n": _int_to_base64url(public_numbers.n),
                "e": _int_to_base64url(public_numbers.e),
            }
        ]
    }


def validate_oidc_redirect_uri(redirect_uri):
    """Validate redirect_uri against allowlist of Google domains."""
    allowed_prefixes = [
        "https://accounts.google.com/",
        "https://auth.google.com/",
    ]
    return any(redirect_uri.startswith(prefix) for prefix in allowed_prefixes)


def validate_pkce_code_verifier(code_verifier, code_challenge, code_challenge_method):
    """Validate PKCE S256 code_verifier against stored code_challenge."""
    if code_challenge_method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed_challenge == code_challenge
