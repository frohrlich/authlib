import pytest

from authlib.oidc.rpinitiated import OpenIDProviderMetadata


def test_validate_end_session_endpoint():
    metadata = OpenIDProviderMetadata()
    metadata.validate_end_session_endpoint()

    metadata = OpenIDProviderMetadata(
        {"end_session_endpoint": "http://provider.test/end_session"}
    )
    with pytest.raises(ValueError, match="https"):
        metadata.validate_end_session_endpoint()

    metadata = OpenIDProviderMetadata(
        {"end_session_endpoint": "https://provider.test/end_session"}
    )
    metadata.validate_end_session_endpoint()


def test_end_session_endpoint_missing():
    """Missing end_session_endpoint should be valid (optional)."""
    metadata = OpenIDProviderMetadata({})
    metadata.validate_end_session_endpoint()
