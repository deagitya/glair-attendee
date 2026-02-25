import base64
import logging
from urllib.parse import urlencode

from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt

from bots.bot_sso_oidc_utils import build_jwks_response, build_oidc_discovery_document, build_oidc_id_token, create_oidc_authorization_code, exchange_oidc_authorization_code, validate_oidc_redirect_uri, validate_pkce_code_verifier
from bots.bot_sso_utils import _build_sign_in_saml_response, _html_auto_post_form, get_bot_login_for_google_meet_sign_in_session
from bots.bots_api_utils import build_site_url
from bots.models import GoogleMeetBotLogin

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class GoogleMeetSetCookieView(View):
    """
    GET endpoint that sets a cookie for the Google Meet SSO flow based on the session id.
    The cookie is used to identify the session when we receive a SAML AuthnRequest.
    """

    def get(self, request):
        # There should be a query parameter called "session_id"
        session_id = request.GET.get("session_id")
        if not session_id:
            logger.warning("GoogleMeetSetCookieView could not set cookie: session_id is missing")
            return HttpResponseBadRequest("Could not set cookie")

        # Check in redis store to confirm that a key with the id "google_meet_sign_in_session:<session_id>" exists
        if not get_bot_login_for_google_meet_sign_in_session(session_id):
            logger.warning("GoogleMeetSetCookieView could not set cookie: no bot login found for session_id")
            return HttpResponseBadRequest("Could not set cookie")

        # Set a cookie with the session_id
        response = HttpResponse("Google Meet Set Cookie")
        response.set_cookie(
            "google_meet_sign_in_session_id",
            session_id,
            secure=True,
            httponly=True,
            samesite="Lax",
        )
        logger.info("GoogleMeetSetCookieView successfully set cookie")
        return response


@method_decorator(csrf_exempt, name="dispatch")
class GoogleMeetSignInView(View):
    """
    GET endpoint that receives a SAML AuthnRequest via HTTP-Redirect binding and
    returns an auto-submitting HTML form that POSTs a signed SAMLResponse to the ACS.
    """

    def get(self, request):
        # Get the session_id from the cookie
        session_id = request.COOKIES.get("google_meet_sign_in_session_id")
        if not session_id:
            logger.warning("GoogleMeetSignInView could not sign in: session_id is missing")
            return HttpResponseBadRequest("Could not sign in")

        # Get the google meet bot login to use from the session id
        google_meet_bot_login = get_bot_login_for_google_meet_sign_in_session(session_id)
        if not google_meet_bot_login:
            logger.warning("GoogleMeetSignInView could not sign in: no bot login found for session_id")
            return HttpResponseBadRequest("Could not sign in")

        saml_request_b64 = request.GET.get("SAMLRequest")
        relay_state = request.GET.get("RelayState")

        if not saml_request_b64:
            logger.warning("GoogleMeetSignInView could not sign in: SAMLRequest is missing")
            return HttpResponseBadRequest("Missing SAMLRequest")

        # Create and sign the SAMLResponse
        try:
            saml_response_b64, acs_url = _build_sign_in_saml_response(
                saml_request_b64=saml_request_b64,
                email_to_sign_in=google_meet_bot_login.email,
                cert=google_meet_bot_login.cert,
                private_key=google_meet_bot_login.private_key,
            )
        except Exception as e:
            logger.exception(f"Failed to create SAMLResponse: {e}")
            return HttpResponseBadRequest("Failed to create SAMLResponse. Private Key or Cert may be invalid.")

        # 6) Return auto-posting HTML to the ACS
        html = _html_auto_post_form(acs_url, saml_response_b64, relay_state)
        return HttpResponse(html, content_type="text/html")


@method_decorator(csrf_exempt, name="dispatch")
class GoogleMeetSignOutView(View):
    """
    GET endpoint that receives a SAML LogoutRequest via HTTP-Redirect binding
    """

    def get(self, request):
        logger.info("GoogleMeetSignOutView GET request received")
        # For now, we'll do nothing here. In the future may be useful keeping track of active sessions more rigorously.
        return HttpResponse("Signed Out Successfully")


@method_decorator(csrf_exempt, name="dispatch")
class OIDCDiscoveryView(View):
    """
    GET /.well-known/openid-configuration
    Returns the OIDC discovery document.
    """

    def get(self, request):
        issuer_url = build_site_url("/bot_sso")
        discovery = build_oidc_discovery_document(issuer_url)
        return JsonResponse(discovery)


@method_decorator(csrf_exempt, name="dispatch")
class OIDCAuthorizeView(View):
    """
    GET /authorize
    Reads the google_meet_sign_in_session_id cookie, validates OIDC params,
    generates an authorization code, and redirects to redirect_uri with code + state.
    """

    def get(self, request):
        session_id = request.COOKIES.get("google_meet_sign_in_session_id")
        if not session_id:
            logger.warning("OIDCAuthorizeView: session_id cookie is missing")
            return HttpResponseBadRequest("Missing session cookie")

        google_meet_bot_login = get_bot_login_for_google_meet_sign_in_session(session_id)
        if not google_meet_bot_login:
            logger.warning("OIDCAuthorizeView: no bot login found for session_id")
            return HttpResponseBadRequest("Invalid session")

        # Validate required OIDC params
        client_id = request.GET.get("client_id")
        redirect_uri = request.GET.get("redirect_uri")
        response_type = request.GET.get("response_type")
        scope = request.GET.get("scope", "")
        state = request.GET.get("state")
        nonce = request.GET.get("nonce")

        if not client_id or not redirect_uri or not response_type:
            logger.warning("OIDCAuthorizeView: missing required parameters")
            return HttpResponseBadRequest("Missing required parameters: client_id, redirect_uri, response_type")

        if response_type != "code":
            logger.warning(f"OIDCAuthorizeView: unsupported response_type={response_type}")
            return HttpResponseBadRequest("Unsupported response_type. Only 'code' is supported.")

        if "openid" not in scope.split():
            logger.warning("OIDCAuthorizeView: scope must include 'openid'")
            return HttpResponseBadRequest("Scope must include 'openid'")

        # Validate client_id matches the login's oidc_client_id
        if google_meet_bot_login.auth_protocol != GoogleMeetBotLogin.AUTH_PROTOCOL_OIDC:
            logger.warning("OIDCAuthorizeView: bot login is not configured for OIDC")
            return HttpResponseBadRequest("Bot login is not configured for OIDC")

        if google_meet_bot_login.oidc_client_id != client_id:
            logger.warning("OIDCAuthorizeView: client_id does not match bot login")
            return HttpResponseBadRequest("Invalid client_id")

        # Validate redirect_uri
        if not validate_oidc_redirect_uri(redirect_uri):
            logger.warning(f"OIDCAuthorizeView: invalid redirect_uri={redirect_uri}")
            return HttpResponseBadRequest("Invalid redirect_uri")

        # Capture optional PKCE params
        code_challenge = request.GET.get("code_challenge")
        code_challenge_method = request.GET.get("code_challenge_method")

        # Generate authorization code
        code = create_oidc_authorization_code(
            session_id=session_id,
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

        logger.info(f"OIDCAuthorizeView: issuing authorization code for client_id={client_id}")
        return HttpResponseRedirect(redirect_url)


@method_decorator(csrf_exempt, name="dispatch")
class OIDCTokenView(View):
    """
    POST /token
    Exchanges an authorization code for an id_token.
    Supports client_secret_post and client_secret_basic authentication.
    """

    def post(self, request):
        # Extract client credentials - support both client_secret_post and client_secret_basic
        client_id = None
        client_secret = None

        # Try client_secret_basic (Authorization header)
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                client_id, client_secret = decoded.split(":", 1)
            except Exception:
                return JsonResponse({"error": "invalid_client", "error_description": "Invalid Authorization header"}, status=401)

        # Try client_secret_post (form body) - overrides basic if both present
        post_client_id = request.POST.get("client_id")
        post_client_secret = request.POST.get("client_secret")
        if post_client_id and post_client_secret:
            client_id = post_client_id
            client_secret = post_client_secret

        if not client_id or not client_secret:
            return JsonResponse({"error": "invalid_client", "error_description": "Client authentication required"}, status=401)

        # Look up the bot login by oidc_client_id
        google_meet_bot_login = GoogleMeetBotLogin.objects.filter(oidc_client_id=client_id, auth_protocol=GoogleMeetBotLogin.AUTH_PROTOCOL_OIDC, is_active=True).first()
        if not google_meet_bot_login:
            return JsonResponse({"error": "invalid_client", "error_description": "Unknown client_id"}, status=401)

        # Verify client_secret
        if not google_meet_bot_login.verify_client_secret(client_secret):
            return JsonResponse({"error": "invalid_client", "error_description": "Invalid client_secret"}, status=401)

        # Validate grant_type
        grant_type = request.POST.get("grant_type")
        if grant_type != "authorization_code":
            return JsonResponse({"error": "unsupported_grant_type", "error_description": "Only 'authorization_code' is supported"}, status=400)

        # Exchange the authorization code
        code = request.POST.get("code")
        if not code:
            return JsonResponse({"error": "invalid_request", "error_description": "Missing 'code' parameter"}, status=400)

        code_data = exchange_oidc_authorization_code(code)
        if not code_data:
            return JsonResponse({"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}, status=400)

        # Validate client_id matches
        if code_data.get("client_id") != client_id:
            return JsonResponse({"error": "invalid_grant", "error_description": "Authorization code was not issued to this client"}, status=400)

        # Validate redirect_uri matches
        redirect_uri = request.POST.get("redirect_uri")
        if redirect_uri and code_data.get("redirect_uri") != redirect_uri:
            return JsonResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status=400)

        # Validate PKCE if code_challenge was present in the authorization request
        if code_data.get("code_challenge"):
            code_verifier = request.POST.get("code_verifier")
            if not code_verifier:
                return JsonResponse({"error": "invalid_request", "error_description": "Missing code_verifier for PKCE"}, status=400)
            if not validate_pkce_code_verifier(code_verifier, code_data["code_challenge"], code_data.get("code_challenge_method", "S256")):
                return JsonResponse({"error": "invalid_grant", "error_description": "Invalid code_verifier"}, status=400)

        # Build the id_token using the global signing key
        issuer_url = build_site_url("/bot_sso")

        id_token = build_oidc_id_token(
            email=google_meet_bot_login.email,
            client_id=client_id,
            issuer_url=issuer_url,
            nonce=code_data.get("nonce"),
        )

        logger.info(f"OIDCTokenView: issued id_token for client_id={client_id}")
        response = JsonResponse(
            {
                "access_token": "not_applicable",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token,
            }
        )
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        return response


@method_decorator(csrf_exempt, name="dispatch")
class OIDCJWKSView(View):
    """
    GET /jwks
    Returns the JSON Web Key Set containing the single global signing key.
    """

    @method_decorator(cache_page(300))
    def get(self, request):
        jwks = build_jwks_response()
        response = JsonResponse(jwks)
        response["Cache-Control"] = "public, max-age=300"
        return response
