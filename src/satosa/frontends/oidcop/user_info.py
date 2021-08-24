from oidcop.user_info import UserInfo


class UserInfoDict:
    def __init__(self, claims: dict):
        self.claims = claims

    def __getitem__(self, key):
        return self.claims


class SatosaOidcUserInfo(UserInfo):
    """Read only interface to a user info store"""

    def __init__(self, user_claims: dict = None):
        self.user_claims = user_claims
        self.load(user_claims)

    def load(self, user_claims):
        self.db = UserInfoDict(user_claims or {})

    def flush(self):
        self.db = UserInfoDict(claims={})
