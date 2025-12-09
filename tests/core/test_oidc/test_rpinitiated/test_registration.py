import pytest

from authlib.jose.errors import InvalidClaimError
from authlib.oidc.rpinitiated import ClientMetadataClaims


def test_post_logout_redirect_uris():
    claims = ClientMetadataClaims(
        {"post_logout_redirect_uris": ["https://client.test/logout"]}, {}
    )
    claims.validate()

    claims = ClientMetadataClaims(
        {
            "post_logout_redirect_uris": [
                "https://client.test/logout",
                "https://client.test/logged-out",
            ]
        },
        {},
    )
    claims.validate()

    claims = ClientMetadataClaims({"post_logout_redirect_uris": ["invalid"]}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_post_logout_redirect_uris_empty():
    """Empty list should be valid."""
    claims = ClientMetadataClaims({"post_logout_redirect_uris": []}, {})
    claims.validate()


def test_post_logout_redirect_uris_missing():
    """Missing claim should be valid (optional)."""
    claims = ClientMetadataClaims({}, {})
    claims.validate()
