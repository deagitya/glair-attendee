import base64
import json
import logging
from urllib.parse import urlencode, urlparse

from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from bots.bot_sso_utils import (
    build_id_token,
    consume_auth_code,
    create_auth_code,
    get_bot_login_for_google_meet_sign_in_session,
    get_email_for_access_token,
    get_oidc_discovery,
    get_jwks_document,
    store_access_token,
    validate_client_credentials,
)

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class GoogleMeetSetCookieView(View):
    """
    GET endpoint that sets a cookie for the Google Meet SSO flow based on the session id.
    The cookie is used to identify the session when we receive an OIDC authorization request.
    """

    def get(self, request):
        session_id = request.GET.get("session_id")
        if not session_id:
            logger.warning("GoogleMeetSetCookieView could not set cookie: session_id is missing")
            return HttpResponseBadRequest("Could not set cookie")

        if not get_bot_login_for_google_meet_sign_in_session(session_id):
            logger.warning("GoogleMeetSetCookieView could not set cookie: no bot login found for session_id")
            return HttpResponseBadRequest("Could not set cookie")

        response = HttpResponse("Google Meet Set Cookie")
        response.set_cookie(
            "google_meet_sign_in_session_id",
            session_id,
            secure=True,
            httponly=True,
            samesite="None",
        )
        logger.info("GoogleMeetSetCookieView successfully set cookie")
        return response


@method_decorator(csrf_exempt, name="dispatch")
class OIDCDiscoveryView(View):
    """GET /.well-known/openid-configuration — OpenID Connect discovery document."""

    def get(self, request):
        return JsonResponse(get_oidc_discovery())


@method_decorator(csrf_exempt, name="dispatch")
class OIDCAuthorizeView(View):
    """
    GET /authorize — OIDC authorization endpoint.
    Validates session cookie + client_id, generates an authorization code,
    and redirects to Google's redirect_uri with ?code=X&state=Y.
    """

    def get(self, request):
        session_id = request.COOKIES.get("google_meet_sign_in_session_id")
        if not session_id:
            logger.warning("OIDCAuthorizeView: missing session cookie")
            return HttpResponseBadRequest("Missing session cookie")

        google_meet_bot_login = get_bot_login_for_google_meet_sign_in_session(session_id)
        if not google_meet_bot_login:
            logger.warning("OIDCAuthorizeView: no bot login found for session")
            return HttpResponseBadRequest("Invalid session")

        client_id = request.GET.get("client_id")
        redirect_uri = request.GET.get("redirect_uri")
        state = request.GET.get("state")
        nonce = request.GET.get("nonce")
        code_challenge = request.GET.get("code_challenge")
        code_challenge_method = request.GET.get("code_challenge_method", "S256")

        if not client_id or not redirect_uri:
            logger.warning("OIDCAuthorizeView: missing client_id or redirect_uri")
            return HttpResponseBadRequest("Missing required parameters")

        # Validate redirect_uri is a Google domain (prevent open redirect)
        parsed_uri = urlparse(redirect_uri)
        if not parsed_uri.hostname or not parsed_uri.hostname.endswith(".google.com"):
            logger.warning(f"OIDCAuthorizeView: redirect_uri not a Google domain: {parsed_uri.hostname}")
            return HttpResponseBadRequest("Invalid redirect_uri")

        # Validate client_id against stored credentials
        creds = google_meet_bot_login.get_credentials()
        if not creds or creds.get("client_id") != client_id:
            logger.warning("OIDCAuthorizeView: client_id mismatch")
            return HttpResponseBadRequest("Invalid client_id")

        # Generate authorization code (with optional PKCE params)
        code = create_auth_code(
            email=google_meet_bot_login.email,
            client_id=client_id,
            redirect_uri=redirect_uri,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        # Build redirect URL
        params = {"code": code}
        if state:
            params["state"] = state
        redirect_url = f"{redirect_uri}?{urlencode(params)}"

        response = HttpResponse(status=302)
        response["Location"] = redirect_url
        return response


@method_decorator(csrf_exempt, name="dispatch")
class OIDCTokenView(View):
    """
    POST /token — OIDC token endpoint.
    Exchanges an authorization code for an ID token.
    """

    def post(self, request):
        # Accept both form-encoded and JSON bodies
        content_type = request.content_type or ""
        if "application/json" in content_type:
            try:
                body = json.loads(request.body)
            except (json.JSONDecodeError, ValueError):
                return JsonResponse({"error": "invalid_request"}, status=400)
        else:
            body = request.POST

        grant_type = body.get("grant_type")
        code = body.get("code")
        client_id = body.get("client_id")
        client_secret = body.get("client_secret")
        redirect_uri = body.get("redirect_uri")
        code_verifier = body.get("code_verifier")

        # Support client_secret_basic (HTTP Basic Auth header)
        if not client_id or not client_secret:
            auth_header = request.META.get("HTTP_AUTHORIZATION", "")
            if auth_header.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                    client_id, client_secret = decoded.split(":", 1)
                except Exception:
                    pass

        if grant_type != "authorization_code":
            return JsonResponse({"error": "unsupported_grant_type"}, status=400)

        if not code or not client_id or not client_secret:
            return JsonResponse({"error": "invalid_request"}, status=400)

        # Validate client credentials
        if not validate_client_credentials(client_id, client_secret):
            logger.warning("OIDCTokenView: invalid client credentials")
            return JsonResponse({"error": "invalid_client"}, status=401)

        # Consume the authorization code (single-use)
        code_data = consume_auth_code(code)
        if not code_data:
            logger.warning("OIDCTokenView: invalid or expired authorization code")
            return JsonResponse({"error": "invalid_grant"}, status=400)

        # Verify code was issued for this client and redirect_uri
        if code_data["client_id"] != client_id:
            logger.warning("OIDCTokenView: client_id mismatch in code")
            return JsonResponse({"error": "invalid_grant"}, status=400)

        if redirect_uri and code_data["redirect_uri"] != redirect_uri:
            logger.warning("OIDCTokenView: redirect_uri mismatch in code")
            return JsonResponse({"error": "invalid_grant"}, status=400)

        # Verify PKCE code_verifier if code_challenge was stored
        stored_challenge = code_data.get("code_challenge")
        if stored_challenge:
            if not code_verifier:
                logger.warning("OIDCTokenView: missing code_verifier for PKCE")
                return JsonResponse({"error": "invalid_grant"}, status=400)

            method = code_data.get("code_challenge_method", "S256")
            if method == "S256":
                import hashlib
                computed = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode("ascii")).digest()
                ).rstrip(b"=").decode("ascii")
            else:  # plain
                computed = code_verifier

            if computed != stored_challenge:
                logger.warning("OIDCTokenView: PKCE code_verifier mismatch")
                return JsonResponse({"error": "invalid_grant"}, status=400)

        # Build ID token
        id_token = build_id_token(
            email=code_data["email"],
            client_id=client_id,
            nonce=code_data.get("nonce"),
        )

        # Generate opaque access_token and store the email mapping for userinfo
        import secrets

        access_token = secrets.token_urlsafe(32)
        store_access_token(access_token, code_data["email"])

        return JsonResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "id_token": id_token,
        })


@method_decorator(csrf_exempt, name="dispatch")
class OIDCJWKSView(View):
    """GET /jwks — JSON Web Key Set for ID token verification."""

    def get(self, request):
        return JsonResponse(get_jwks_document())


@method_decorator(csrf_exempt, name="dispatch")
class OIDCUserInfoView(View):
    """GET /userinfo — OIDC UserInfo endpoint.
    Returns claims about the authenticated user based on the access token."""

    def get(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            email = get_email_for_access_token(token)
            if email:
                return JsonResponse({"sub": email, "email": email})

        return JsonResponse({"error": "invalid_token"}, status=401)
