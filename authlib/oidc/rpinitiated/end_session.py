"""OpenID Connect RP-Initiated Logout 1.0 implementation.

https://openid.net/specs/openid-connect-rpinitiated-1_0.html
"""

from typing import Optional
from urllib.parse import urlencode

from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.errors import InvalidRequestError


class EndSessionEndpoint:
    """OpenID Connect RP-Initiated Logout Endpoint.

    This endpoint allows a Relying Party to request that an OpenID Provider
    log out the End-User. It must be subclassed and several methods need to
    be implemented::

        class MyEndSessionEndpoint(EndSessionEndpoint):
            def get_client_by_id(self, client_id):
                return Client.query.filter_by(client_id=client_id).first()

            def validate_id_token_hint(self, id_token_hint):
                # Decode and verify the ID token was issued by this OP
                # Return the claims dict if valid, None otherwise
                try:
                    claims = jwt.decode(id_token_hint, public_key)
                    return claims
                except JoseError:
                    return None

            def end_session(self, request, id_token_claims):
                # Perform actual session termination
                # id_token_claims may be None if no valid id_token_hint
                logout_user()

            def create_end_session_response(self, request, redirect_uri, state):
                # Return redirect response or confirmation page
                if redirect_uri:
                    return 302, "", [("Location", redirect_uri)]
                return 200, "Logged out", []

    Register the endpoint with the authorization server::

        server.register_endpoint(MyEndSessionEndpoint())

    And plug it into your application::

        @app.route("/oauth/end_session", methods=["GET", "POST"])
        def end_session():
            return server.create_endpoint_response("end_session")

    """

    ENDPOINT_NAME = "end_session"

    def __init__(self, server=None):
        self.server = server

    def create_endpoint_request(self, request: OAuth2Request):
        return self.server.create_oauth2_request(request)

    def __call__(self, request: OAuth2Request):
        # Extract parameters from GET or POST
        data = request.payload.data
        id_token_hint = data.get("id_token_hint")
        logout_hint = data.get("logout_hint")
        client_id = data.get("client_id")
        post_logout_redirect_uri = data.get("post_logout_redirect_uri")
        state = data.get("state")
        ui_locales = data.get("ui_locales")

        # Validate id_token_hint if present
        id_token_claims = None
        if id_token_hint:
            id_token_claims = self.validate_id_token_hint(id_token_hint)

        # Determine the client
        client = None
        if client_id:
            client = self.get_client_by_id(client_id)
        elif id_token_claims:
            # Extract client_id from aud claim
            aud = id_token_claims.get("aud")
            if isinstance(aud, list):
                # TODO:  When an id_token_hint parameter is present, 
                # the OP MUST validate that it was the issuer of the ID Token. 
                # The OP SHOULD accept ID Tokens when the RP identified by the 
                # ID Token's aud claim and/or sid claim has a current session or 
                # had a recent session at the OP, even when the exp time has passed. 
                # If the ID Token's sid claim does not correspond to the RP's current 
                # session or a recent session at the OP, the OP SHOULD treat the logout 
                # request as suspect, and MAY decline to act upon it.

                # The user should specify how to define from the audience list if a client was recently logged in
                # They should return the client in question
                aud = aud[0] if aud else None
            if aud:
                client = self.get_client_by_id(aud)

        # Validate client_id matches aud claim if both present
        if client_id and id_token_claims:
            aud = id_token_claims.get("aud")
            aud_list = [aud] if isinstance(aud, str) else (aud or [])
            if client_id not in aud_list:
                raise InvalidRequestError("'client_id' does not match 'aud' claim")

        redirect_uri = None
        if post_logout_redirect_uri:
            if not self._validate_post_logout_redirect_uri(
                client, post_logout_redirect_uri
            ):
                raise InvalidRequestError(
                    "Invalid 'post_logout_redirect_uri' for client"
                )

            # If id_token_hint is missing or invalid, require confirmation
            
            # TODO: This should be in all cases, not just the case where post_logout_redirect_uri is provided
            if not id_token_claims:
                if not self.confirm_logout_without_id_token(
                    request, client, logout_hint
                ):
                    return self.create_confirmation_response(
                        request, client, post_logout_redirect_uri, state, ui_locales
                    )

            redirect_uri = post_logout_redirect_uri
            if state:
                separator = "&" if "?" in redirect_uri else "?"
                redirect_uri = f"{redirect_uri}{separator}{urlencode({'state': state})}"

        # Perform logout
        self.end_session(request, id_token_claims)

        return self.create_end_session_response(request, redirect_uri, state)

    def _validate_post_logout_redirect_uri(
        self, client, post_logout_redirect_uri: str
    ) -> bool:
        """Check that post_logout_redirect_uri exactly matches a registered URI."""
        if not client:
            return False

        registered_uris = client.client_metadata.get("post_logout_redirect_uris", [])

        return post_logout_redirect_uri in registered_uris

    def get_client_by_id(self, client_id: str):
        """Get a client by its client_id.

        This method must be implemented by developers::

            def get_client_by_id(self, client_id):
                return Client.query.filter_by(client_id=client_id).first()

        :param client_id: The client identifier.
        :return: The client object or None.
        """
        raise NotImplementedError()

    def validate_id_token_hint(self, id_token_hint: str) -> Optional[dict]:
        """Validate an ID token hint and return its claims.

        This method must be implemented by developers. It should verify that
        the token was issued by this OP. The OP should accept tokens with
        expired ``exp`` claims if the session is still active::

            def validate_id_token_hint(self, id_token_hint):
                try:
                    claims = jwt.decode(
                        id_token_hint,
                        public_key,
                        claims_options={"exp": {"validate": False}},
                    )
                    claims.validate()
                    return claims
                except JoseError:
                    return None

        :param id_token_hint: The ID token string.
        :return: The token claims dict if valid, None otherwise.
        """
        raise NotImplementedError()

    def end_session(self, request: OAuth2Request, id_token_claims: Optional[dict]):
        """Perform the actual session termination.

        This method must be implemented by developers::

            def end_session(self, request, id_token_claims):
                # id_token_claims may be None if no valid id_token_hint
                if id_token_claims:
                    user_id = id_token_claims.get("sub")
                    # Terminate session for specific user
                logout_current_user()

        :param request: The OAuth2Request object.
        :param id_token_claims: The validated ID token claims, or None.
        """
        raise NotImplementedError()

    def create_end_session_response(
        self,
        request: OAuth2Request,
        redirect_uri: Optional[str],
        state: Optional[str],
    ):
        """Create the response after successful logout.

        This method must be implemented by developers::

            def create_end_session_response(self, request, redirect_uri, state):
                if redirect_uri:
                    return 302, "", [("Location", redirect_uri)]
                return 200, "You have been logged out.", []

        :param request: The OAuth2Request object.
        :param redirect_uri: The URI to redirect to (with state appended), or None.
        :param state: The state parameter from the request, or None.
        :return: A tuple of (status_code, body, headers).
        """
        raise NotImplementedError()

    def confirm_logout_without_id_token(
        self,
        request: OAuth2Request,
        client,
        logout_hint: Optional[str],
    ) -> bool:
        """Determine if logout can proceed without a valid id_token_hint.

        When post_logout_redirect_uri is provided but id_token_hint is missing
        or invalid, the OP should require user confirmation to prevent DoS.
        Override this method if you have alternative confirmation mechanisms.

        By default, returns False to require confirmation.

        :param request: The OAuth2Request object.
        :param client: The client object, or None.
        :param logout_hint: The logout_hint parameter, or None.
        :return: True if logout can proceed, False to require confirmation.
        """
        return False

    def create_confirmation_response(
        self,
        request: OAuth2Request,
        client,
        post_logout_redirect_uri: str,
        state: Optional[str],
        ui_locales: Optional[str],
    ):
        """Create a response asking the user to confirm logout.

        This is called when post_logout_redirect_uri is provided but
        id_token_hint is missing or invalid. Override to provide a
        confirmation UI::

            def create_confirmation_response(
                self, request, client, post_logout_redirect_uri, state, ui_locales
            ):
                return (
                    200,
                    render_confirmation_page(
                        client=client,
                        redirect_uri=post_logout_redirect_uri,
                        state=state,
                    ),
                    [("Content-Type", "text/html")],
                )

        :param request: The OAuth2Request object.
        :param client: The client object, or None.
        :param post_logout_redirect_uri: The requested redirect URI.
        :param state: The state parameter, or None.
        :param ui_locales: The ui_locales parameter, or None.
        :return: A tuple of (status_code, body, headers).
        """
        return 400, "Logout confirmation required", []

    def create_invalid_request_response(self, error_description: str):
        """Create an error response for invalid requests.

        Override to customize error responses::

            def create_invalid_request_response(self, error_description):
                return (
                    400,
                    json.dumps(
                        {
                            "error": "invalid_request",
                            "error_description": error_description,
                        }
                    ),
                    [("Content-Type", "application/json")],
                )

        :param error_description: Description of the error.
        :return: A tuple of (status_code, body, headers).
        """
        return 400, error_description, []
