"""
A static dictionary with SAML testusers that can be used as response.
"""

from satosa.frontends.openid_connect import combine_claim_values

USERS = {
    "testuser1": {
        "sn": ["Testsson 1"],
        "givenName": ["Test 1"],
        "eduPersonAffiliation": ["student"],
        "eduPersonScopedAffiliation": ["student@example.com"],
        "eduPersonPrincipalName": ["test@example.com"],
        "uid": ["testuser1"],
        "eduPersonTargetedID": ["one!for!all"],
        "c": ["SE"],
        "o": ["Example Co."],
        "ou": ["IT"],
        "initials": ["P"],
        "schacHomeOrganization": ["example.com"],
        "email": ["test@example.com"],
        "displayName": ["Test Testsson"],
        "norEduPersonNIN": ["SE199012315555"]
    }
}

OIDC_USERS = {
    id: dict(combine_claim_values(attributes.items()))
    for id, attributes in USERS.items()
}
