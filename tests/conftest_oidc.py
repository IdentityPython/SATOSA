import pytest


@pytest.fixture
def oidc_backend_config():
    data = {
        "module": "satosa.backends.openid_connect.OpenIDConnectBackend",
        "name": "OIDCBackend",
        "config": {
            "provider_metadata": {
                "issuer": "https://op.example.com",
                "authorization_endpoint": "https://example.com/authorization"
            },
            "client": {
                "auth_req_params": {
                    "response_type": "code",
                    "scope": "openid, profile, email, address, phone"
                },
                "client_metadata": {
                    "client_id": "backend_client",
                    "application_name": "SATOSA",
                    "application_type": "web",
                    "contacts": ["suppert@example.com"],
                    "redirect_uris": ["http://example.com/OIDCBackend"],
                    "subject_type": "public",
                }
            },
            "entity_info": {
                "contact_person": [{
                    "contact_type": "technical",
                    "email_address": ["technical_test@example.com", "support_test@example.com"],
                    "given_name": "Test",
                    "sur_name": "OP"
                }, {
                    "contact_type": "support",
                    "email_address": ["support_test@example.com"],
                    "given_name": "Support_test"
                }],
                "organization": {
                    "display_name": ["OP Identities", "en"],
                    "name": [["En test-OP", "se"], ["A test OP", "en"]],
                    "url": [["http://www.example.com", "en"], ["http://www.example.se", "se"]],
                    "ui_info": {
                        "description": [["This is a test OP", "en"]],
                        "display_name": [["OP - TEST", "en"]]
                    }
                }
            }
        }
    }

    return data

