from authlib.oidc.rpinitiated import EndSessionEndpoint


class MockClient:
    def __init__(self, client_id, post_logout_redirect_uris=None):
        self.client_id = client_id
        self._metadata = {"post_logout_redirect_uris": post_logout_redirect_uris or []}

    @property
    def client_metadata(self):
        return self._metadata


class MockPayload:
    def __init__(self, data=None):
        self.data = data or {}


class MockRequest:
    def __init__(self, data=None):
        self.payload = MockPayload(data)


class MockEndSessionEndpoint(EndSessionEndpoint):
    def __init__(self, clients=None, valid_tokens=None):
        super().__init__()
        self.clients = {c.client_id: c for c in (clients or [])}
        self.valid_tokens = valid_tokens or {}
        self.ended_sessions = []
        self.confirmation_requested = False

    def get_client_by_id(self, client_id):
        return self.clients.get(client_id)

    def validate_id_token_hint(self, id_token_hint):
        return self.valid_tokens.get(id_token_hint)

    def end_session(self, request, id_token_claims):
        self.ended_sessions.append(id_token_claims)

    def create_end_session_response(self, request, redirect_uri, state):
        if redirect_uri:
            return 302, "", [("Location", redirect_uri)]
        return 200, "Logged out", []

    def create_confirmation_response(
        self, request, client, post_logout_redirect_uri, state, ui_locales
    ):
        self.confirmation_requested = True
        return 200, "Confirm logout", []


def test_end_session_without_parameters():
    """Logout without any parameters should succeed."""
    endpoint = MockEndSessionEndpoint()
    request = MockRequest()

    status, body, headers = endpoint(request)

    assert status == 200
    assert body == "Logged out"
    assert len(endpoint.ended_sessions) == 1
    assert endpoint.ended_sessions[0] is None


def test_end_session_with_valid_id_token_hint():
    """Logout with valid id_token_hint should pass claims to end_session."""
    client = MockClient("client-1")
    claims = {"sub": "user-1", "aud": "client-1"}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest({"id_token_hint": "valid-token"})

    status, body, headers = endpoint(request)

    assert status == 200
    assert len(endpoint.ended_sessions) == 1
    assert endpoint.ended_sessions[0] == claims


def test_end_session_with_invalid_id_token_hint():
    """Logout with invalid id_token_hint should still succeed but without claims."""
    endpoint = MockEndSessionEndpoint()
    request = MockRequest({"id_token_hint": "invalid-token"})

    status, body, headers = endpoint(request)

    assert status == 200
    assert len(endpoint.ended_sessions) == 1
    assert endpoint.ended_sessions[0] is None


def test_end_session_with_post_logout_redirect_uri():
    """Logout with valid redirect URI and id_token_hint should redirect."""
    client = MockClient(
        "client-1", post_logout_redirect_uris=["https://client.test/logout"]
    )
    claims = {"sub": "user-1", "aud": "client-1"}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "post_logout_redirect_uri": "https://client.test/logout",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 302
    assert ("Location", "https://client.test/logout") in headers


def test_end_session_with_redirect_uri_and_state():
    """State parameter should be appended to redirect URI."""
    client = MockClient(
        "client-1", post_logout_redirect_uris=["https://client.test/logout"]
    )
    claims = {"sub": "user-1", "aud": "client-1"}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "post_logout_redirect_uri": "https://client.test/logout",
            "state": "abc123",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 302
    location = dict(headers).get("Location")
    assert location == "https://client.test/logout?state=abc123"


def test_end_session_with_redirect_uri_containing_query():
    """State should be appended with & if redirect URI already has query params."""
    client = MockClient(
        "client-1", post_logout_redirect_uris=["https://client.test/logout?foo=bar"]
    )
    claims = {"sub": "user-1", "aud": "client-1"}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "post_logout_redirect_uri": "https://client.test/logout?foo=bar",
            "state": "abc123",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 302
    location = dict(headers).get("Location")
    assert location == "https://client.test/logout?foo=bar&state=abc123"


def test_end_session_invalid_redirect_uri():
    """Unregistered redirect URI should return error."""
    client = MockClient(
        "client-1", post_logout_redirect_uris=["https://client.test/logout"]
    )
    claims = {"sub": "user-1", "aud": "client-1"}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "post_logout_redirect_uri": "https://attacker.test/logout",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 400
    assert "invalid post_logout_redirect_uri" in body
    assert len(endpoint.ended_sessions) == 0


def test_end_session_redirect_uri_without_id_token_requires_confirmation():
    """Redirect URI without id_token_hint should require confirmation."""
    client = MockClient(
        "client-1", post_logout_redirect_uris=["https://client.test/logout"]
    )
    endpoint = MockEndSessionEndpoint(clients=[client])
    request = MockRequest(
        {
            "client_id": "client-1",
            "post_logout_redirect_uri": "https://client.test/logout",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 200
    assert body == "Confirm logout"
    assert endpoint.confirmation_requested
    assert len(endpoint.ended_sessions) == 0


def test_end_session_redirect_uri_without_client():
    """Redirect URI without client should return error."""
    endpoint = MockEndSessionEndpoint()
    request = MockRequest({"post_logout_redirect_uri": "https://client.test/logout"})

    status, body, headers = endpoint(request)

    assert status == 400
    assert "invalid post_logout_redirect_uri" in body


def test_end_session_client_id_mismatch():
    """client_id not matching aud claim should return error."""
    client1 = MockClient("client-1")
    client2 = MockClient("client-2")
    claims = {"sub": "user-1", "aud": "client-1"}
    endpoint = MockEndSessionEndpoint(
        clients=[client1, client2], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "client_id": "client-2",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 400
    assert "does not match" in body
    assert len(endpoint.ended_sessions) == 0


def test_end_session_client_id_matches_aud():
    """client_id matching aud claim should succeed."""
    client = MockClient("client-1")
    claims = {"sub": "user-1", "aud": "client-1"}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "client_id": "client-1",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 200
    assert len(endpoint.ended_sessions) == 1


def test_end_session_with_aud_as_list():
    """aud claim as array should be handled correctly."""
    client = MockClient(
        "client-1", post_logout_redirect_uris=["https://client.test/logout"]
    )
    claims = {"sub": "user-1", "aud": ["client-1", "client-2"]}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "post_logout_redirect_uri": "https://client.test/logout",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 302


def test_end_session_client_id_in_aud_list():
    """client_id in aud array should succeed."""
    client = MockClient("client-2")
    claims = {"sub": "user-1", "aud": ["client-1", "client-2"]}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "client_id": "client-2",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 200
    assert len(endpoint.ended_sessions) == 1


def test_end_session_client_id_not_in_aud_list():
    """client_id not in aud array should fail."""
    client = MockClient("client-3")
    claims = {"sub": "user-1", "aud": ["client-1", "client-2"]}
    endpoint = MockEndSessionEndpoint(
        clients=[client], valid_tokens={"valid-token": claims}
    )
    request = MockRequest(
        {
            "id_token_hint": "valid-token",
            "client_id": "client-3",
        }
    )

    status, body, headers = endpoint(request)

    assert status == 400
    assert "does not match" in body
