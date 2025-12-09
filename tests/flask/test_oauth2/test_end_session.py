import pytest

from authlib.jose import jwt
from authlib.oidc.rpinitiated import EndSessionEndpoint
from tests.util import read_file_path

from .models import Client


class MockFlaskEndSessionEndpoint(EndSessionEndpoint):
    """EndSessionEndpoint implementation for testing."""

    def __init__(self, db_session, issuer="https://provider.test"):
        super().__init__()
        self.db_session = db_session
        self.issuer = issuer
        self.ended_sessions = []

    def get_client_by_id(self, client_id):
        return self.db_session.query(Client).filter_by(client_id=client_id).first()

    def validate_id_token_hint(self, id_token_hint):
        try:
            pub_key = read_file_path("jwks_public.json")
            claims = jwt.decode(id_token_hint, pub_key)
            # Accept expired tokens per spec
            claims.options = {"exp": {"validate": False}}
            claims.validate()
            # Verify issuer matches
            if claims.get("iss") != self.issuer:
                return None
            return dict(claims)
        except Exception:
            return None

    def end_session(self, request, id_token_claims):
        self.ended_sessions.append(id_token_claims)

    def create_end_session_response(self, request, redirect_uri, state):
        if redirect_uri:
            return 302, "", [("Location", redirect_uri)]
        return 200, "Logged out", [("Content-Type", "text/plain")]


def create_id_token(claims):
    """Create a signed ID token for testing."""
    priv_key = read_file_path("jwks_private.json")
    header = {"alg": "RS256"}
    token = jwt.encode(header, claims, priv_key)
    # jwt.encode returns bytes, convert to string for use in URLs
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


@pytest.fixture(autouse=True)
def setup_endpoint(server, app, db):
    endpoint = MockFlaskEndSessionEndpoint(db.session)
    server.register_endpoint(endpoint)

    @app.route("/oauth/end_session", methods=["GET", "POST"])
    def end_session():
        return server.create_endpoint_response("end_session")

    yield endpoint

    endpoint.ended_sessions.clear()


@pytest.fixture(autouse=True)
def client(db):
    client = Client(
        user_id=1,
        client_id="client-id",
        client_secret="client-secret",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "post_logout_redirect_uris": [
                "https://client.test/logout",
                "https://client.test/logged-out",
            ],
            "scope": "openid profile",
        }
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


def test_end_session_get(test_client, setup_endpoint):
    """End session endpoint should support GET requests."""
    rv = test_client.get("/oauth/end_session")

    assert rv.status_code == 200
    assert rv.data == b"Logged out"
    assert len(setup_endpoint.ended_sessions) == 1


def test_end_session_post(test_client, setup_endpoint):
    """End session endpoint should support POST requests."""
    rv = test_client.post("/oauth/end_session")

    assert rv.status_code == 200
    assert rv.data == b"Logged out"
    assert len(setup_endpoint.ended_sessions) == 1


def test_end_session_with_valid_id_token(test_client, setup_endpoint, client):
    """Logout with valid id_token_hint should pass claims to end_session."""
    id_token = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.get(f"/oauth/end_session?id_token_hint={id_token}")

    assert rv.status_code == 200
    assert len(setup_endpoint.ended_sessions) == 1
    claims = setup_endpoint.ended_sessions[0]
    assert claims["sub"] == "user-1"
    assert claims["aud"] == "client-id"


def test_end_session_with_redirect_uri(test_client, setup_endpoint, client):
    """Logout with valid redirect URI should redirect."""
    id_token = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout"


def test_end_session_with_redirect_uri_and_state(test_client, setup_endpoint, client):
    """State parameter should be appended to redirect URI."""
    id_token = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
        "&state=xyz123"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout?state=xyz123"


def test_end_session_invalid_redirect_uri(test_client, setup_endpoint, client):
    """Unregistered redirect URI should return error."""
    id_token = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://attacker.test/logout"
    )

    assert rv.status_code == 400
    assert b"invalid post_logout_redirect_uri" in rv.data
    assert len(setup_endpoint.ended_sessions) == 0


def test_end_session_redirect_without_id_token(test_client, setup_endpoint, client):
    """Redirect URI without id_token_hint should require confirmation."""
    rv = test_client.get(
        "/oauth/end_session?client_id=client-id"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    # Default implementation returns 400 for confirmation required
    assert rv.status_code == 400
    assert len(setup_endpoint.ended_sessions) == 0


def test_end_session_client_id_mismatch(test_client, setup_endpoint, client):
    """client_id not matching aud claim should return error."""
    id_token = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}&client_id=other-client"
    )

    assert rv.status_code == 400
    assert b"does not match" in rv.data
    assert len(setup_endpoint.ended_sessions) == 0


def test_end_session_with_wrong_issuer(test_client, setup_endpoint, client):
    """ID token from different issuer should be treated as invalid."""
    id_token = create_id_token(
        {
            "iss": "https://other-provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.get(f"/oauth/end_session?id_token_hint={id_token}")

    assert rv.status_code == 200
    # ID token should be treated as invalid, claims should be None
    assert len(setup_endpoint.ended_sessions) == 1
    assert setup_endpoint.ended_sessions[0] is None


def test_end_session_alternative_redirect_uri(test_client, setup_endpoint, client):
    """Should work with any registered post_logout_redirect_uri."""
    id_token = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logged-out"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logged-out"


def test_end_session_post_with_form_data(test_client, setup_endpoint, client):
    """End session should support POST with form-encoded data."""
    id_token = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )

    rv = test_client.post(
        "/oauth/end_session",
        data={
            "id_token_hint": id_token,
            "post_logout_redirect_uri": "https://client.test/logout",
            "state": "abc",
        },
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout?state=abc"
