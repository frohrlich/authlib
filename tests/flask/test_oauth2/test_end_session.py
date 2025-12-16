import pytest

from authlib.jose import jwt
from authlib.oidc.rpinitiated import EndSessionEndpoint
from tests.util import read_file_path

from .models import Client
from .models import db


class FlaskEndSessionEndpoint(EndSessionEndpoint):
    def __init__(self, issuer="https://provider.test"):
        super().__init__()
        self.issuer = issuer

    def get_client_by_id(self, client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    def validate_id_token_claims(self, id_token_hint):
        try:
            pub_key = read_file_path("jwks_public.json")
            claims = jwt.decode(id_token_hint, pub_key)
            # Accept expired tokens per spec
            claims.options = {"exp": {"validate": False}}
            claims.validate()
            if claims.get("iss") != self.issuer:
                return None
            return dict(claims)
        except Exception:
            return None

    def end_session(self, request, id_token_claims):
        pass

    def create_end_session_response(self, request, redirect_uri):
        if redirect_uri:
            return 302, "", [("Location", redirect_uri)]
        return 200, "Logged out", [("Content-Type", "text/plain")]

    def create_confirmation_response(self, request, client, redirect_uri, ui_locales):
        return 200, "Confirm logout", [("Content-Type", "text/plain")]


class ConfirmingEndSessionEndpoint(FlaskEndSessionEndpoint):
    """Endpoint that auto-confirms logout without id_token_hint."""

    def is_post_logout_redirect_uri_legitimate(self, request, client, logout_hint):
        return True


@pytest.fixture
def confirming_server(server, app, db):
    endpoint = ConfirmingEndSessionEndpoint()
    server.register_endpoint(endpoint)

    @app.route("/oauth/end_session", methods=["GET", "POST"])
    def end_session():
        return server.create_endpoint_response("end_session")

    return server


@pytest.fixture
def base_server(server, app, db):
    endpoint = FlaskEndSessionEndpoint()
    server.register_endpoint(endpoint)

    @app.route("/oauth/end_session_base", methods=["GET", "POST"])
    def end_session_base():
        return server.create_endpoint_response("end_session")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
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

    return client


def test_end_session_with_valid_id_token(
    test_client, confirming_server, client, id_token
):
    """Logout with valid id_token_hint should succeed."""
    rv = test_client.get(f"/oauth/end_session?id_token_hint={id_token}")

    assert rv.status_code == 200
    assert rv.data == b"Logged out"


def test_end_session_with_redirect_uri(
    test_client, confirming_server, client, id_token
):
    """Logout with valid redirect URI should redirect."""
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout"


def test_end_session_with_redirect_uri_and_state(
    test_client, confirming_server, client, id_token
):
    """State parameter should be appended to redirect URI."""
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
        "&state=xyz123"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout?state=xyz123"


def test_end_session_invalid_redirect_uri(test_client, base_server, client, id_token):
    """Unregistered redirect URI should result in no redirection."""
    rv = test_client.get(
        f"/oauth/end_session_base?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://attacker.test/logout"
    )

    assert rv.status_code == 200


def test_end_session_redirect_without_id_token(test_client, confirming_server, client):
    """Redirect URI without id_token_hint succeeds when confirmation is granted."""
    rv = test_client.get(
        "/oauth/end_session?client_id=client-id"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    # Test endpoint has confirm_logout_without_id_token returning True
    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout"


def test_end_session_client_id_mismatch(
    test_client, confirming_server, client, id_token
):
    """client_id not matching aud claim should return error."""
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}&client_id=other-client"
    )

    assert rv.status_code == 400


def test_end_session_post_with_form_data(
    test_client, confirming_server, client, id_token
):
    """End session should support POST with form-encoded data."""
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


def test_no_id_token_requires_confirmation(test_client, base_server, client):
    """Logout without id_token_hint should show confirmation page."""
    rv = test_client.get("/oauth/end_session_base")

    assert rv.status_code == 200
    assert rv.data == b"Confirm logout"


def test_redirect_without_id_token_requires_confirmation(
    test_client, base_server, client
):
    """Redirect URI without id_token_hint should show confirmation without redirect."""
    rv = test_client.get(
        "/oauth/end_session_base?client_id=client-id"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 200
    assert rv.data == b"Confirm logout"


def test_invalid_id_token_requires_confirmation(
    test_client, base_server, client, id_token_wrong_issuer
):
    """Invalid id_token_hint should show confirmation page."""
    rv = test_client.get(
        f"/oauth/end_session_base?id_token_hint={id_token_wrong_issuer}"
    )

    assert rv.status_code == 200
    assert rv.data == b"Confirm logout"


def test_valid_id_token_succeeds_without_confirmation(
    test_client, base_server, client, id_token
):
    """Valid id_token_hint should succeed without confirmation."""
    rv = test_client.get(f"/oauth/end_session_base?id_token_hint={id_token}")

    assert rv.status_code == 200
    assert rv.data == b"Logged out"


def test_valid_id_token_with_redirect_succeeds_without_confirmation(
    test_client, base_server, client, id_token
):
    """Valid id_token_hint with redirect URI should succeed."""
    rv = test_client.get(
        f"/oauth/end_session_base?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout"
