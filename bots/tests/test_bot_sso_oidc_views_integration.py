import base64
import hashlib
import json
import secrets
import string

import jwt
import redis
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.test import Client, TransactionTestCase
from django.urls import reverse

from accounts.models import Organization
from bots.bot_sso_oidc_utils import OIDC_SIGNING_KID, generate_oidc_credentials
from bots.bot_sso_utils import create_google_meet_sign_in_session
from bots.models import Bot, GoogleMeetBotLogin, GoogleMeetBotLoginGroup, Project


def _create_oidc_bot_login(group):
    """Helper to create an OIDC-configured GoogleMeetBotLogin with generated credentials."""
    client_id, client_secret_raw, client_secret_hash = generate_oidc_credentials()
    login = GoogleMeetBotLogin.objects.create(
        group=group,
        workspace_domain="test-workspace.com",
        email="oidc-bot@test-workspace.com",
        auth_protocol=GoogleMeetBotLogin.AUTH_PROTOCOL_OIDC,
        oidc_client_id=client_id,
        oidc_client_secret_hash=client_secret_hash,
    )
    return login, client_id, client_secret_raw


def _get_global_public_key():
    """Get the global OIDC signing public key for JWT verification in tests."""
    private_key = serialization.load_pem_private_key(settings.OIDC_RSA_PRIVATE_KEY_PEM.encode(), password=None)
    return private_key.public_key()


class OIDCDiscoveryTest(TransactionTestCase):
    """Tests for the OIDC discovery endpoint."""

    def setUp(self):
        self.client = Client()

    def test_oidc_discovery_endpoint(self):
        """Test that the discovery endpoint returns proper OIDC configuration."""
        url = reverse("bot_sso:oidc_discovery")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)

        # Verify required fields
        self.assertIn("issuer", data)
        self.assertIn("authorization_endpoint", data)
        self.assertIn("token_endpoint", data)
        self.assertIn("jwks_uri", data)
        self.assertIn("response_types_supported", data)
        self.assertIn("id_token_signing_alg_values_supported", data)
        self.assertIn("code", data["response_types_supported"])
        self.assertIn("RS256", data["id_token_signing_alg_values_supported"])
        self.assertIn("openid", data["scopes_supported"])
        self.assertIn("S256", data["code_challenge_methods_supported"])

        # Verify endpoints are relative to issuer
        self.assertTrue(data["authorization_endpoint"].startswith(data["issuer"]))
        self.assertTrue(data["token_endpoint"].startswith(data["issuer"]))
        self.assertTrue(data["jwks_uri"].startswith(data["issuer"]))


class OIDCAuthorizeTest(TransactionTestCase):
    """Tests for the OIDC authorize endpoint."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Organization", centicredits=10000)
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.bot = Bot.objects.create(
            project=self.project,
            name="Test Bot",
            meeting_url="https://meet.google.com/abc-defg-hij",
        )
        self.google_meet_bot_login_group = GoogleMeetBotLoginGroup.objects.create(project=self.project)
        self.login, self.client_id, self.client_secret = _create_oidc_bot_login(self.google_meet_bot_login_group)

        self.http_client = Client()

    def tearDown(self):
        redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
        for pattern in ["google_meet_sign_in_session:*", "oidc_auth_code:*"]:
            keys = redis_client.keys(pattern)
            if keys:
                redis_client.delete(*keys)

    def test_oidc_authorize_valid_session(self):
        """Test OIDC authorize with a valid session returns 302 redirect with code + state."""
        session_id = create_google_meet_sign_in_session(self.bot, self.login)
        self.http_client.cookies["google_meet_sign_in_session_id"] = session_id

        url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(
            url,
            {
                "client_id": self.client_id,
                "redirect_uri": "https://accounts.google.com/o/oauth2/auth/callback",
                "response_type": "code",
                "scope": "openid email",
                "state": "test_state_123",
                "nonce": "test_nonce_456",
            },
        )

        self.assertEqual(response.status_code, 302)
        redirect_url = response["Location"]
        self.assertTrue(redirect_url.startswith("https://accounts.google.com/o/oauth2/auth/callback"))
        self.assertIn("code=", redirect_url)
        self.assertIn("state=test_state_123", redirect_url)

    def test_oidc_authorize_missing_cookie(self):
        """Test OIDC authorize without session cookie returns 400."""
        url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(
            url,
            {
                "client_id": self.client_id,
                "redirect_uri": "https://accounts.google.com/callback",
                "response_type": "code",
                "scope": "openid",
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_oidc_authorize_invalid_client_id(self):
        """Test OIDC authorize with wrong client_id returns 400."""
        session_id = create_google_meet_sign_in_session(self.bot, self.login)
        self.http_client.cookies["google_meet_sign_in_session_id"] = session_id

        url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(
            url,
            {
                "client_id": "wrong_client_id",
                "redirect_uri": "https://accounts.google.com/callback",
                "response_type": "code",
                "scope": "openid",
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_oidc_authorize_invalid_redirect_uri(self):
        """Test OIDC authorize with disallowed redirect_uri returns 400."""
        session_id = create_google_meet_sign_in_session(self.bot, self.login)
        self.http_client.cookies["google_meet_sign_in_session_id"] = session_id

        url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(
            url,
            {
                "client_id": self.client_id,
                "redirect_uri": "https://evil.example.com/callback",
                "response_type": "code",
                "scope": "openid",
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_oidc_authorize_missing_openid_scope(self):
        """Test OIDC authorize without openid scope returns 400."""
        session_id = create_google_meet_sign_in_session(self.bot, self.login)
        self.http_client.cookies["google_meet_sign_in_session_id"] = session_id

        url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(
            url,
            {
                "client_id": self.client_id,
                "redirect_uri": "https://accounts.google.com/callback",
                "response_type": "code",
                "scope": "email",
            },
        )

        self.assertEqual(response.status_code, 400)


class OIDCTokenTest(TransactionTestCase):
    """Tests for the OIDC token endpoint."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Organization", centicredits=10000)
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.bot = Bot.objects.create(
            project=self.project,
            name="Test Bot",
            meeting_url="https://meet.google.com/abc-defg-hij",
        )
        self.google_meet_bot_login_group = GoogleMeetBotLoginGroup.objects.create(project=self.project)
        self.login, self.client_id, self.client_secret = _create_oidc_bot_login(self.google_meet_bot_login_group)

        self.http_client = Client()
        self.redirect_uri = "https://accounts.google.com/o/oauth2/auth/callback"

    def tearDown(self):
        redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
        for pattern in ["google_meet_sign_in_session:*", "oidc_auth_code:*"]:
            keys = redis_client.keys(pattern)
            if keys:
                redis_client.delete(*keys)

    def _get_auth_code(self, nonce=None, code_challenge=None, code_challenge_method=None):
        """Helper to get an authorization code through the authorize endpoint."""
        session_id = create_google_meet_sign_in_session(self.bot, self.login)
        self.http_client.cookies["google_meet_sign_in_session_id"] = session_id

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "openid email",
            "state": "test_state",
        }
        if nonce:
            params["nonce"] = nonce
        if code_challenge:
            params["code_challenge"] = code_challenge
        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method

        url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(url, params)
        self.assertEqual(response.status_code, 302)

        # Extract code from redirect URL
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(response["Location"])
        query = parse_qs(parsed.query)
        return query["code"][0]

    def test_oidc_token_exchange_valid(self):
        """Test valid token exchange returns 200 with id_token."""
        code = self._get_auth_code(nonce="test_nonce")

        url = reverse("bot_sso:oidc_token")
        response = self.http_client.post(
            url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("id_token", data)
        self.assertEqual(data["token_type"], "Bearer")
        self.assertIn("expires_in", data)

        # Decode and verify the JWT using the global public key
        public_key = _get_global_public_key()
        decoded = jwt.decode(data["id_token"], public_key, algorithms=["RS256"], audience=self.client_id)
        self.assertEqual(decoded["sub"], self.login.email)
        self.assertEqual(decoded["email"], self.login.email)
        self.assertEqual(decoded["aud"], self.client_id)
        self.assertEqual(decoded["nonce"], "test_nonce")

    def test_oidc_token_invalid_code(self):
        """Test token exchange with invalid code returns error."""
        url = reverse("bot_sso:oidc_token")
        response = self.http_client.post(
            url,
            {
                "grant_type": "authorization_code",
                "code": "invalid_code",
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data["error"], "invalid_grant")

    def test_oidc_token_invalid_client_secret(self):
        """Test token exchange with wrong client_secret returns 401."""
        code = self._get_auth_code()

        url = reverse("bot_sso:oidc_token")
        response = self.http_client.post(
            url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": "wrong_secret",
            },
        )

        self.assertEqual(response.status_code, 401)
        data = json.loads(response.content)
        self.assertEqual(data["error"], "invalid_client")

    def test_oidc_token_code_single_use(self):
        """Test that authorization code can only be used once."""
        code = self._get_auth_code()

        url = reverse("bot_sso:oidc_token")
        post_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        # First exchange should succeed
        response1 = self.http_client.post(url, post_data)
        self.assertEqual(response1.status_code, 200)

        # Second exchange with same code should fail
        response2 = self.http_client.post(url, post_data)
        self.assertEqual(response2.status_code, 400)
        data = json.loads(response2.content)
        self.assertEqual(data["error"], "invalid_grant")

    def test_oidc_token_redirect_uri_mismatch(self):
        """Test token exchange with mismatched redirect_uri returns error."""
        code = self._get_auth_code()

        url = reverse("bot_sso:oidc_token")
        response = self.http_client.post(
            url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://accounts.google.com/different/callback",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data["error"], "invalid_grant")
        self.assertIn("redirect_uri", data["error_description"])

    def test_oidc_token_client_secret_basic(self):
        """Test token exchange with client_secret_basic auth method."""
        code = self._get_auth_code()

        url = reverse("bot_sso:oidc_token")
        basic_auth = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        response = self.http_client.post(
            url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
            },
            HTTP_AUTHORIZATION=f"Basic {basic_auth}",
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("id_token", data)


class OIDCJWKSTest(TransactionTestCase):
    """Tests for the OIDC JWKS endpoint."""

    def setUp(self):
        self.http_client = Client()

    def test_oidc_jwks_endpoint(self):
        """Test JWKS endpoint returns the single global signing key with cache headers."""
        url = reverse("bot_sso:oidc_jwks")
        response = self.http_client.get(url)

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)

        self.assertIn("keys", data)
        self.assertEqual(len(data["keys"]), 1)

        key = data["keys"][0]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["alg"], "RS256")
        self.assertEqual(key["kid"], OIDC_SIGNING_KID)
        self.assertIn("n", key)
        self.assertIn("e", key)

        # Verify cache headers
        self.assertIn("max-age=300", response["Cache-Control"])


class OIDCPKCETest(TransactionTestCase):
    """Tests for OIDC PKCE flow."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Organization", centicredits=10000)
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.bot = Bot.objects.create(
            project=self.project,
            name="Test Bot",
            meeting_url="https://meet.google.com/abc-defg-hij",
        )
        self.google_meet_bot_login_group = GoogleMeetBotLoginGroup.objects.create(project=self.project)
        self.login, self.client_id, self.client_secret = _create_oidc_bot_login(self.google_meet_bot_login_group)

        self.http_client = Client()
        self.redirect_uri = "https://accounts.google.com/o/oauth2/auth/callback"

    def tearDown(self):
        redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
        for pattern in ["google_meet_sign_in_session:*", "oidc_auth_code:*"]:
            keys = redis_client.keys(pattern)
            if keys:
                redis_client.delete(*keys)

    def test_oidc_pkce_flow(self):
        """Test OIDC PKCE flow with S256 code_challenge."""
        # Generate PKCE code_verifier and code_challenge
        code_verifier = "".join(secrets.choice(string.ascii_letters + string.digits + "-._~") for _ in range(64))
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")

        # Get auth code with code_challenge
        session_id = create_google_meet_sign_in_session(self.bot, self.login)
        self.http_client.cookies["google_meet_sign_in_session_id"] = session_id

        authorize_url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(
            authorize_url,
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "scope": "openid email",
                "state": "pkce_test",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(response.status_code, 302)

        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(response["Location"])
        query = parse_qs(parsed.query)
        code = query["code"][0]

        # Exchange with code_verifier
        token_url = reverse("bot_sso:oidc_token")
        response = self.http_client.post(
            token_url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": code_verifier,
            },
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("id_token", data)

    def test_oidc_pkce_invalid_verifier(self):
        """Test that invalid code_verifier is rejected."""
        code_verifier = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")

        session_id = create_google_meet_sign_in_session(self.bot, self.login)
        self.http_client.cookies["google_meet_sign_in_session_id"] = session_id

        authorize_url = reverse("bot_sso:oidc_authorize")
        response = self.http_client.get(
            authorize_url,
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "scope": "openid email",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(response.status_code, 302)

        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(response["Location"])
        query = parse_qs(parsed.query)
        code = query["code"][0]

        # Exchange with WRONG code_verifier
        token_url = reverse("bot_sso:oidc_token")
        response = self.http_client.post(
            token_url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": "wrong_verifier_value",
            },
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data["error"], "invalid_grant")


class OIDCFullFlowE2ETest(TransactionTestCase):
    """End-to-end test for the complete OIDC flow."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Organization", centicredits=10000)
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.bot = Bot.objects.create(
            project=self.project,
            name="Test Bot",
            meeting_url="https://meet.google.com/abc-defg-hij",
        )
        self.google_meet_bot_login_group = GoogleMeetBotLoginGroup.objects.create(project=self.project)
        self.login, self.client_id, self.client_secret = _create_oidc_bot_login(self.google_meet_bot_login_group)

        self.http_client = Client()
        self.redirect_uri = "https://accounts.google.com/o/oauth2/auth/callback"

    def tearDown(self):
        redis_client = redis.from_url(settings.REDIS_URL_WITH_PARAMS)
        for pattern in ["google_meet_sign_in_session:*", "oidc_auth_code:*"]:
            keys = redis_client.keys(pattern)
            if keys:
                redis_client.delete(*keys)

    def test_oidc_full_flow_e2e(self):
        """Test the complete OIDC flow: set_cookie -> authorize -> token -> verify JWT against JWKS."""
        # Step 1: Create session and set cookie
        session_id = create_google_meet_sign_in_session(self.bot, self.login)

        set_cookie_url = reverse("bot_sso:google_meet_set_cookie")
        set_cookie_response = self.http_client.get(set_cookie_url, {"session_id": session_id})
        self.assertEqual(set_cookie_response.status_code, 200)
        self.assertIn("google_meet_sign_in_session_id", set_cookie_response.cookies)

        # Step 2: Authorize
        authorize_url = reverse("bot_sso:oidc_authorize")
        nonce = "e2e_test_nonce_789"
        authorize_response = self.http_client.get(
            authorize_url,
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "scope": "openid email",
                "state": "e2e_state",
                "nonce": nonce,
            },
        )
        self.assertEqual(authorize_response.status_code, 302)

        # Extract code from redirect
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(authorize_response["Location"])
        query = parse_qs(parsed.query)
        self.assertIn("code", query)
        self.assertEqual(query["state"][0], "e2e_state")
        code = query["code"][0]

        # Step 3: Token exchange
        token_url = reverse("bot_sso:oidc_token")
        token_response = self.http_client.post(
            token_url,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        self.assertEqual(token_response.status_code, 200)

        token_data = json.loads(token_response.content)
        id_token = token_data["id_token"]

        # Step 4: Get JWKS and verify JWT
        jwks_url = reverse("bot_sso:oidc_jwks")
        jwks_response = self.http_client.get(jwks_url)
        self.assertEqual(jwks_response.status_code, 200)

        jwks_data = json.loads(jwks_response.content)
        self.assertEqual(len(jwks_data["keys"]), 1)

        # Find the key by the global kid
        jwk = jwks_data["keys"][0]
        self.assertEqual(jwk["kid"], OIDC_SIGNING_KID)

        # Reconstruct public key from JWK and verify JWT
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        def _base64url_decode(s):
            s += "=" * (4 - len(s) % 4)
            return base64.urlsafe_b64decode(s)

        n = int.from_bytes(_base64url_decode(jwk["n"]), byteorder="big")
        e = int.from_bytes(_base64url_decode(jwk["e"]), byteorder="big")
        public_key = RSAPublicNumbers(e, n).public_key()

        decoded = jwt.decode(id_token, public_key, algorithms=["RS256"], audience=self.client_id)
        self.assertEqual(decoded["sub"], self.login.email)
        self.assertEqual(decoded["email"], self.login.email)
        self.assertEqual(decoded["aud"], self.client_id)
        self.assertEqual(decoded["nonce"], nonce)
        self.assertIn("iss", decoded)
        self.assertIn("iat", decoded)
        self.assertIn("exp", decoded)
