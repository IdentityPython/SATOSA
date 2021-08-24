import datetime
import pytest

CLIENT_1_ID = 'jbxedfmfyc'
CLIENT_1_PASSWD = '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1'
CLIENT_1_RAT = 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY'
CLIENT_1_SESLOGOUT = 'https://127.0.0.1:8090/session_logout/satosa'
CLIENT = {
        'client_id': CLIENT_1_ID,
        'client_salt': '6flfsj0Z',
        'registration_access_token': CLIENT_1_RAT,
        'registration_client_uri': 'https://127.0.0.1:8000/registration_api?client_id=jbxedfmfyc',
        'client_id_issued_at': datetime.datetime.utcnow(),
        'client_secret': CLIENT_1_PASSWD,
        'client_secret_expires_at': (datetime.datetime.utcnow() + datetime.timedelta(days=1)).timestamp(),
        'application_type': 'web',
        'contacts': ['ops@example.com'],
        'token_endpoint_auth_method': 'client_secret_basic',
        # 'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
        'redirect_uris': [('https://127.0.0.1:8090/authz_cb/satosa', {})],
        'post_logout_redirect_uris': [(CLIENT_1_SESLOGOUT, None)],
        'response_types': ['code'],
        'grant_types': ['authorization_code'],
        'allowed_scopes': ['openid', 'profile', 'email', 'offline_access']
}
