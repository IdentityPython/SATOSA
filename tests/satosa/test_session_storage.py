from unittest import TestCase
from unittest.mock import patch

from satosa.plugin_loader import load_session_storage
from satosa.session_storage import FrontendSession


class TestInMemorySessionStorage(TestCase):
    def test_inmemory_store_frontend_session(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        assert session_storage.frontend_sessions

    def test_inmemory_get_frontend_session(self):
        config = {}
        session_storage = load_session_storage(config)
        assert not session_storage.get_frontend_session("sid-1FE")
        session_storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        assert session_storage.get_frontend_session("sid-1FE")

    def test_inmemory_delete_frontend_session(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        session_storage.delete_frontend_session("sid-1FE")
        assert not session_storage.get_frontend_session("sid-1FE")

    def test_inmemory_store_backend_session(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_backend_session("sid-1BE", "OIDC")
        assert session_storage.backend_sessions

    def test_inmemory_get_backend_session(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_backend_session("sid-1BE", "OIDC")
        backend_session = session_storage.get_backend_session("sid-1BE", "OIDC")
        assert backend_session

    def test_inmemory_get_unique_backend_session_from_multiple_same_sid_backends(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_backend_session("sid-1BE", "OIDC")
        session_storage.store_backend_session("sid-1BE", "OIDC2")
        backend_session = session_storage.get_backend_session("sid-1BE", "OIDC2")
        assert backend_session.get("issuer") == "OIDC2"

    def test_inmemory_get_backend_session_doesnot_exist(self):
        config = {}
        session_storage = load_session_storage(config)
        backend_session = session_storage.get_backend_session("sid-1BE", "OIDC2")
        assert not backend_session

    def test_inmemory_delete_backend_session(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_backend_session("sid-1BE", "OIDC")
        session_storage.delete_backend_session(
            session_storage.get_backend_session("sid-1BE")["id"]
        )
        backend_session = session_storage.get_backend_session("sid-1BE")
        assert not backend_session

    def test_inmemory_store_session_map(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_session_map("sid-1FE", "sid-1BE")
        assert session_storage.session_maps

    def test_inmemory_delete_session_map(self):
        config = {}
        session_storage = load_session_storage(config)
        session_storage.store_session_map("sid-1FE", "sid-1BE")
        session_storage.delete_session_map("sid-1FE")
        assert not session_storage.session_maps

    def test_inmemory_get_frontend_sessions_by_backend_session_id(self):
        config = {}
        session_storage = load_session_storage(config)
        assert not session_storage.get_frontend_sessions_by_backend_session_id(
            "sid-1BE"
        )
        session_storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        session_storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-2FE"
        )
        session_storage.store_session_map("sid-1FE", "sid-1BE")
        session_storage.store_session_map("sid-2FE", "sid-1BE")
        backend_sessions = session_storage.get_frontend_sessions_by_backend_session_id(
            "sid-1BE"
        )
        assert len(backend_sessions) == 2


class TestPostgreSQLSessionStorage(TestCase):
    @patch("sqlalchemy.orm.session.Session.query")
    @patch("sqlalchemy.orm.session.Session.commit")
    @patch("satosa.session_storage.Base")
    def test_postgresql_store_frontend_session(
        self, mock_base, mock_session_commit, mock_frontend_session_query
    ):
        config = {
            "SESSION_STORAGE": {
                "type": "postgresql",
                "host": "127.0.0.1",
                "port": 5432,
                "db_name": "satosa",
                "user": "postgres",
                "password": "secret",
            }
        }
        mock_base.return_value.metadata.return_value.create_all.return_value = None
        mock_session_commit.return_value = None
        session_storage = load_session_storage(config)
        session_storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )

        frontend_session_mock = FrontendSession()
        frontend_session_mock.sid = "sid"
        frontend_session_mock.frontend_name = "frontend_name"
        frontend_session_mock.requester = "requester"
        frontend_session_mock.subject_id = "subject_id"
        mock_frontend_session_query.return_value.filter.return_value.first.return_value = (
            frontend_session_mock
        )

        frontend_session = session_storage.get_frontend_session("sid-1FE")
        assert frontend_session
