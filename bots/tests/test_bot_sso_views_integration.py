import json
import os
import uuid

import jwt
import redis
from django.conf import settings
from django.test import Client, TransactionTestCase
from django.urls import reverse

from accounts.models import Organization
from bots.bot_sso_utils import create_auth_code, create_google_meet_sign_in_session, get_issuer_url
from bots.models import Bot, GoogleMeetBotLogin, GoogleMeetBotLoginGroup, Project
from bots.oidc_keys import get_public_key

TEST_CLIENT_ID = "test-client-id-12345"
TEST_CLIENT_SECRET = "test-client-secret-67890"


class BotSsoViewsIntegrationTest(TransactionTestCase):
    """Integration tests for OIDC SSO views"""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Organization")
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.bot = Bot.objects.create(
            project=self.project,
            object_id=uuid.uuid4(),
            meeting_url="https://meet.google.com/abc-defg-hij",
        )

        self.google_meet_bot_login_group = GoogleMeetBotLoginGroup.objects.create(project=self.project)
        self.google_meet_bot_login = GoogleMeetBotLogin.objects.create(
            group=self.google_meet_bot_login_group,
            workspace_domain="test-workspace.com",
            email="test-bot@test-workspace.com",
        )

        self.google_meet_bot_login.set_credentials(
            {
                "client_id": TEST_CLIENT_ID,
                "client_secret": TEST_CLIENT_SECRET,
            }
        )

        if not os.getenv("REDIS_URL"):
            os.environ["REDIS_URL"] = "redis://localhost:6379/0"

        self.client = Client()

    def tearDown(self):
        redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
        for pattern in ["google_meet_sign_in_session:*", "oidc_auth_code:*"]:
            keys = redis_client.keys(pattern)
            if keys:
                redis_client.delete(*keys)

    # -----------------------------------------------------------------------
    # Discovery endpoint
    # -----------------------------------------------------------------------

    def test_discovery_returns_correct_metadata(self):
        url = reverse("bot_sso:oidc_discovery")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")

        data = response.json()
        issuer = get_issuer_url()
        self.assertEqual(data["issuer"], issuer)
        self.assertEqual(data["authorization_endpoint"], f"{issuer}/authorize")
        self.assertEqual(data["token_endpoint"], f"{issuer}/token")
        self.assertEqual(data["jwks_uri"], f"{issuer}/jwks")
        self.assertIn("RS256", data["id_token_signing_alg_values_supported"])

    # -----------------------------------------------------------------------
    # JWKS endpoint
    # -----------------------------------------------------------------------

    def test_jwks_returns_valid_rsa_public_key(self):
        url = reverse("bot_sso:oidc_jwks")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("keys", data)
        self.assertEqual(len(data["keys"]), 1)

        key = data["keys"][0]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["alg"], "RS256")
        self.assertIn("n", key)
        self.assertIn("e", key)

    # -----------------------------------------------------------------------
    # Set cookie (unchanged)
    # -----------------------------------------------------------------------

    def test_set_cookie_view_with_valid_session(self):
        session_id = create_google_meet_sign_in_session(self.bot, self.google_meet_bot_login)

        url = reverse("bot_sso:google_meet_set_cookie")
        response = self.client.get(url, {"session_id": session_id})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "Google Meet Set Cookie")

        self.assertIn("google_meet_sign_in_session_id", response.cookies)
        cookie = response.cookies["google_meet_sign_in_session_id"]
        self.assertEqual(cookie.value, session_id)
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")

    def test_set_cookie_view_without_session_id(self):
        url = reverse("bot_sso:google_meet_set_cookie")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_set_cookie_view_with_invalid_session(self):
        url = reverse("bot_sso:google_meet_set_cookie")
        response = self.client.get(url, {"session_id": "invalid-session-id"})
        self.assertEqual(response.status_code, 400)

    # -----------------------------------------------------------------------
    # Authorize endpoint
    # -----------------------------------------------------------------------

    def test_authorize_redirects_with_code_and_state(self):
        session_id = create_google_meet_sign_in_session(self.bot, self.google_meet_bot_login)
        self.client.cookies["google_meet_sign_in_session_id"] = session_id

        url = reverse("bot_sso:oidc_authorize")
        response = self.client.get(url, {
            "client_id": TEST_CLIENT_ID,
            "redirect_uri": "https://accounts.google.com/callback",
            "state": "test-state-123",
            "nonce": "test-nonce-456",
            "response_type": "code",
        })

        self.assertEqual(response.status_code, 302)
        location = response["Location"]
        self.assertIn("https://accounts.google.com/callback?", location)
        self.assertIn("code=", location)
        self.assertIn("state=test-state-123", location)

    def test_authorize_fails_without_cookie(self):
        url = reverse("bot_sso:oidc_authorize")
        response = self.client.get(url, {
            "client_id": TEST_CLIENT_ID,
            "redirect_uri": "https://accounts.google.com/callback",
        })
        self.assertEqual(response.status_code, 400)

    def test_authorize_fails_with_wrong_client_id(self):
        session_id = create_google_meet_sign_in_session(self.bot, self.google_meet_bot_login)
        self.client.cookies["google_meet_sign_in_session_id"] = session_id

        url = reverse("bot_sso:oidc_authorize")
        response = self.client.get(url, {
            "client_id": "wrong-client-id",
            "redirect_uri": "https://accounts.google.com/callback",
        })
        self.assertEqual(response.status_code, 400)

    def test_authorize_fails_with_invalid_session(self):
        self.client.cookies["google_meet_sign_in_session_id"] = "invalid-session"

        url = reverse("bot_sso:oidc_authorize")
        response = self.client.get(url, {
            "client_id": TEST_CLIENT_ID,
            "redirect_uri": "https://accounts.google.com/callback",
        })
        self.assertEqual(response.status_code, 400)

    # -----------------------------------------------------------------------
    # Token endpoint
    # -----------------------------------------------------------------------

    def test_token_exchange_returns_valid_signed_jwt(self):
        redirect_uri = "https://accounts.google.com/callback"
        nonce = "test-nonce-789"
        code = create_auth_code(
            email="test-bot@test-workspace.com",
            client_id=TEST_CLIENT_ID,
            redirect_uri=redirect_uri,
            nonce=nonce,
        )

        url = reverse("bot_sso:oidc_token")
        response = self.client.post(url, {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
        })

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id_token", data)
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "Bearer")

        # Verify the JWT
        public_key = get_public_key()
        decoded = jwt.decode(data["id_token"], public_key, algorithms=["RS256"], audience=TEST_CLIENT_ID)
        self.assertEqual(decoded["email"], "test-bot@test-workspace.com")
        self.assertEqual(decoded["sub"], "test-bot@test-workspace.com")
        self.assertEqual(decoded["aud"], TEST_CLIENT_ID)
        self.assertEqual(decoded["nonce"], nonce)
        self.assertEqual(decoded["iss"], get_issuer_url())

    def test_token_fails_with_invalid_code(self):
        url = reverse("bot_sso:oidc_token")
        response = self.client.post(url, {
            "grant_type": "authorization_code",
            "code": "invalid-code",
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")

    def test_token_fails_with_wrong_client_secret(self):
        code = create_auth_code(
            email="test-bot@test-workspace.com",
            client_id=TEST_CLIENT_ID,
            redirect_uri="https://accounts.google.com/callback",
        )

        url = reverse("bot_sso:oidc_token")
        response = self.client.post(url, {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": TEST_CLIENT_ID,
            "client_secret": "wrong-secret",
        })

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "invalid_client")

    def test_code_is_single_use(self):
        """Second token exchange with the same code should fail."""
        redirect_uri = "https://accounts.google.com/callback"
        code = create_auth_code(
            email="test-bot@test-workspace.com",
            client_id=TEST_CLIENT_ID,
            redirect_uri=redirect_uri,
        )

        url = reverse("bot_sso:oidc_token")
        post_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
        }

        # First exchange should succeed
        response1 = self.client.post(url, post_data)
        self.assertEqual(response1.status_code, 200)

        # Second exchange should fail
        response2 = self.client.post(url, post_data)
        self.assertEqual(response2.status_code, 400)
        self.assertEqual(response2.json()["error"], "invalid_grant")

    def test_token_fails_with_wrong_grant_type(self):
        url = reverse("bot_sso:oidc_token")
        response = self.client.post(url, {
            "grant_type": "client_credentials",
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "unsupported_grant_type")

    # -----------------------------------------------------------------------
    # End-to-end flow
    # -----------------------------------------------------------------------

    def test_full_oidc_flow_end_to_end(self):
        """Test the complete OIDC flow: set cookie -> authorize -> token -> verify JWT"""
        # Step 1: Create session and set cookie
        session_id = create_google_meet_sign_in_session(self.bot, self.google_meet_bot_login)

        redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
        redis_key = f"google_meet_sign_in_session:{session_id}"
        self.assertTrue(redis_client.exists(redis_key))

        set_cookie_url = reverse("bot_sso:google_meet_set_cookie")
        set_cookie_response = self.client.get(set_cookie_url, {"session_id": session_id})
        self.assertEqual(set_cookie_response.status_code, 200)
        self.assertIn("google_meet_sign_in_session_id", set_cookie_response.cookies)

        # Step 2: Authorize — get an auth code
        redirect_uri = "https://accounts.google.com/callback"
        nonce = f"nonce-{uuid.uuid4()}"
        state = f"state-{uuid.uuid4()}"

        authorize_url = reverse("bot_sso:oidc_authorize")
        authorize_response = self.client.get(authorize_url, {
            "client_id": TEST_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "response_type": "code",
        })
        self.assertEqual(authorize_response.status_code, 302)

        # Extract code from redirect
        location = authorize_response["Location"]
        self.assertIn("code=", location)
        self.assertIn(f"state={state}", location)

        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        code = params["code"][0]

        # Step 3: Exchange code for tokens
        token_url = reverse("bot_sso:oidc_token")
        token_response = self.client.post(token_url, {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
        })
        self.assertEqual(token_response.status_code, 200)

        token_data = token_response.json()
        self.assertIn("id_token", token_data)
        self.assertEqual(token_data["token_type"], "Bearer")

        # Step 4: Verify the JWT
        public_key = get_public_key()
        decoded = jwt.decode(token_data["id_token"], public_key, algorithms=["RS256"], audience=TEST_CLIENT_ID)
        self.assertEqual(decoded["email"], "test-bot@test-workspace.com")
        self.assertEqual(decoded["sub"], "test-bot@test-workspace.com")
        self.assertEqual(decoded["nonce"], nonce)
        self.assertEqual(decoded["iss"], get_issuer_url())
