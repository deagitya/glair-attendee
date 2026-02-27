import hmac
import json
import logging
import time
import uuid
from urllib.parse import urlencode

import jwt
import redis
from django.conf import settings
from django.urls import reverse

from bots.bots_api_utils import build_site_url
from bots.models import Bot, GoogleMeetBotLogin
from bots.oidc_keys import get_jwks, get_private_key

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Session management (protocol-agnostic — kept from SAML implementation)
# ---------------------------------------------------------------------------


def get_google_meet_set_cookie_url(session_id):
    base_url = build_site_url(reverse("bot_sso:google_meet_set_cookie"))
    query_params = urlencode({"session_id": session_id})
    return f"{base_url}?{query_params}"


def create_google_meet_sign_in_session(bot, google_meet_bot_login):
    session_id = str(uuid.uuid4())
    redis_key = f"google_meet_sign_in_session:{session_id}"
    redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)

    session_data = {
        "session_id": session_id,
        "bot_object_id": str(bot.object_id),
        "google_meet_bot_login_object_id": str(google_meet_bot_login.object_id),
        "login_email": google_meet_bot_login.email,
    }

    # Set with 5 minute expiry
    redis_client.setex(redis_key, 300, json.dumps(session_data))
    return session_id


def get_bot_login_for_google_meet_sign_in_session(session_id):
    redis_key = f"google_meet_sign_in_session:{session_id}"
    redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)

    session_data_raw = redis_client.get(redis_key)
    if not session_data_raw:
        logger.info(f"No session data found for google_meet_sign_in_session: {session_id}")
        return None

    session_data = json.loads(session_data_raw)
    bot_object_id = session_data.get("bot_object_id")
    google_meet_bot_login_object_id = session_data.get("google_meet_bot_login_object_id")

    bot = Bot.objects.filter(object_id=bot_object_id).first()
    if not bot:
        logger.info(f"No bot found for google_meet_sign_in_session: {session_id}. Data: {session_data}")
        return None

    google_meet_bot_login = GoogleMeetBotLogin.objects.filter(object_id=google_meet_bot_login_object_id, group__project=bot.project).first()
    if not google_meet_bot_login:
        logger.info(f"No google_meet_bot_login found for google_meet_sign_in_session: {session_id}. Data: {session_data}")
        return None

    return google_meet_bot_login


# ---------------------------------------------------------------------------
# OIDC helpers
# ---------------------------------------------------------------------------


def get_issuer_url():
    """Return the OIDC issuer URL (base path for discovery)."""
    return f"https://{settings.SITE_DOMAIN}/bot_sso"


def create_auth_code(email, client_id, redirect_uri, nonce=None, code_challenge=None, code_challenge_method=None):
    """Create a single-use authorization code stored in Redis."""
    code = str(uuid.uuid4())
    redis_key = f"oidc_auth_code:{code}"
    redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
    ttl = getattr(settings, "OIDC_AUTH_CODE_LIFETIME", 300)
    payload = {
        "email": email,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    redis_client.setex(redis_key, ttl, json.dumps(payload))
    return code


def consume_auth_code(code):
    """Atomically retrieve and delete an authorization code (single-use).
    Uses GETDEL (Redis 6.2+) for a single atomic command."""
    redis_key = f"oidc_auth_code:{code}"
    redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
    raw = redis_client.getdel(redis_key)
    if not raw:
        return None
    return json.loads(raw)


def build_id_token(email, client_id, nonce=None):
    """Build a signed OIDC ID token (RS256 JWT)."""
    issuer = get_issuer_url()
    now = int(time.time())
    lifetime = getattr(settings, "OIDC_ID_TOKEN_LIFETIME", 300)
    key_id = getattr(settings, "OIDC_KEY_ID", "attendee-oidc-1")

    payload = {
        "iss": issuer,
        "sub": email,
        "aud": client_id,
        "email": email,
        "iat": now,
        "exp": now + lifetime,
    }
    if nonce:
        payload["nonce"] = nonce

    private_key = get_private_key()
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": key_id})


def validate_client_credentials(client_id, client_secret):
    """
    Check client_id/client_secret against stored GoogleMeetBotLogin credentials.
    Returns True if any active login has matching credentials.
    Uses constant-time comparison for the secret to prevent timing attacks.
    """
    for login in GoogleMeetBotLogin.objects.filter(is_active=True):
        creds = login.get_credentials()
        if not creds:
            continue
        if creds.get("client_id") == client_id and hmac.compare_digest(creds.get("client_secret", ""), client_secret):
            return True
    return False


def get_oidc_discovery():
    """Return the OpenID Connect discovery document."""
    issuer = get_issuer_url()
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "claims_supported": ["sub", "email", "iss", "aud", "exp", "iat", "nonce"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
    }


def get_jwks_document():
    """Return the JWKS document for token verification."""
    return get_jwks()


def store_access_token(access_token, email):
    """Store access_token → email mapping in Redis for userinfo lookups."""
    redis_key = f"oidc_access_token:{access_token}"
    redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
    ttl = getattr(settings, "OIDC_ID_TOKEN_LIFETIME", 300)
    redis_client.setex(redis_key, ttl, email)


def get_email_for_access_token(access_token):
    """Look up the email associated with an access token."""
    redis_key = f"oidc_access_token:{access_token}"
    redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
    email = redis_client.get(redis_key)
    if email:
        return email.decode() if isinstance(email, bytes) else email
    return None
