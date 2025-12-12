"""OpenID Connect RP-Initiated Logout 1.0 implementation.

https://openid.net/specs/openid-connect-rpinitiated-1_0.html
"""

from typing import Optional

from authlib.common.urls import add_params_to_uri
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
        data = request.payload.data
        id_token_hint = data.get("id_token_hint")
        logout_hint = data.get("logout_hint")
        client_id = data.get("client_id")
        post_logout_redirect_uri = data.get("post_logout_redirect_uri")
        state = data.get("state")
        ui_locales = data.get("ui_locales")

        id_token_claims = None
        if id_token_hint:
            id_token_claims = self.validate_id_token_hint(id_token_hint)

        client = None
        if client_id:
            client = self.get_client_by_id(client_id)
        elif id_token_claims:
            client = self.resolve_client_from_id_token_claims(id_token_claims)

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
            redirect_uri = post_logout_redirect_uri
            if state:
                redirect_uri = add_params_to_uri(redirect_uri, dict(state=state))

        if not id_token_claims and not self.confirm_logout_without_id_token(
            request, client, logout_hint
        ):
            # An id_token_hint carring an ID Token for the RP is also RECOMMENDED
            # when requesting post-logout redirection; if it is not supplied with
            # post_logout_redirect_uri, the OP MUST NOT perform post-logout
            # redirection unless the OP has other means of confirming the legitimacy
            # of the post-logout redirection target.
            redirect_uri = None

            return self.create_confirmation_response(
                request, client, redirect_uri, ui_locales
            )

        # Perform logout
        self.end_session(request, id_token_claims)

        return self.create_end_session_response(request, redirect_uri)

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

    def resolve_client_from_id_token_claims(self, id_token_claims: dict):
        """Resolve the client from ID token claims when client_id is not provided.

        When an id_token_hint is provided without an explicit client_id parameter,
        this method determines which client initiated the logout request based on
        the token claims. The ``aud`` claim may be a single string or an array of
        client identifiers.

        Override this method to implement custom logic for determining the client,
        for example by checking which client the user has an active session with::

            def resolve_client_from_id_token_claims(self, id_token_claims):
                aud = id_token_claims.get("aud")
                if isinstance(aud, str):
                    return self.get_client_by_id(aud)
                # Check which client has an active session
                for client_id in aud:
                    if self.has_active_session_for_client(client_id):
                        return self.get_client_by_id(client_id)
                return None

        By default, returns None requiring the client_id parameter to be provided
        explicitly when the ``aud`` claim is an array.

        :param id_token_claims: The validated ID token claims dictionary.
        :return: The client object or None.
        """
        aud = id_token_claims.get("aud")
        if isinstance(aud, str):
            return self.get_client_by_id(aud)
        return None

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
                        claims_options={"exp": {"validate": lambda c: True}},
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
        self, request: OAuth2Request, redirect_uri: Optional[str]
    ):
        """Create the response after successful logout.

        This method must be implemented by developers::

            def create_end_session_response(self, request, redirect_uri):
                if redirect_uri:
                    return 302, "", [("Location", redirect_uri)]
                return 200, "You have been logged out.", []

        :param request: The OAuth2Request object.
        :param redirect_uri: The URI to redirect to, or None.
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
        redirect_uri: Optional[str],
        ui_locales: Optional[str],
    ):
        """Create a response asking the user to confirm logout.

        This is called when id_token_hint is missing or invalid.
        Override to provide a confirmation UI::

            def create_confirmation_response(
                self, request, client, redirect_uri, ui_locales
            ):
                return (
                    200,
                    render_confirmation_page(
                        client=client,
                        redirect_uri=redirect_uri,
                        state=state,
                    ),
                    [("Content-Type", "text/html")],
                )

        :param request: The OAuth2Request object.
        :param client: The client object, or None.
        :param redirect_uri: The requested redirect URI, or None.
        :param ui_locales: The ui_locales parameter, or None.
        :return: A tuple of (status_code, body, headers).
        """
        return 400, "Logout confirmation required", []
