import base64
import copy
import datetime
import logging
import pymongo

from .base import SatosaOidcStorage
from oidcop.session.manager import SessionManager

logger = logging.getLogger(__name__)


class Mongodb(SatosaOidcStorage):
    session_attr_map = {
        "oidcop.session.info.UserSessionInfo": "sub",
        "oidcop.session.info.ClientSessionInfo": "client_id",
        "oidcop.session.grant.Grant": "grant_id",
    }
    token_attr_map = {
        "oidcop.session.token.AuthorizationCode": "authorization_code",
        "oidcop.session.token.AccessToken": "access_token",
        "oidcop.session.token.RefreshToken": "refresh_token",
        "oidcop.session.token.IDToken": "id_token",
    }

    def __init__(self, storage_conf: dict, url: str, connection_params: dict = None):
        self.storage_conf = storage_conf
        self.url = url
        self.connection_params = connection_params

        # this must be fork safe :)
        self.client = None
        self.db = None
        self.client_db = None
        self.session_db = None


    def _connect(self):
        if not self.client or not self.client.server_info():
            self.client = pymongo.MongoClient(self.url, **self.connection_params)
            self.db = getattr(self.client, self.storage_conf["db_name"])
            self.client_db = self.db[self.storage_conf["collections"]["client"]]
            self.session_db = self.db[self.storage_conf["collections"]["session"]]

    def get_client_by_id(self, client_id: str):
        self._connect()
        res = self.client_db.find({"client_id": client_id})

        # improvement: unique index on client_id in client collection
        if res.count():
            # it returns the first one
            return res.next()
        else:
            return {}

    def store_session_to_db(self, session_manager: SessionManager, claims: dict):
        ses_man_dump = session_manager.dump()
        _db = ses_man_dump["db"]
        data = {
            "expires_at": 0,
            "sub": "",
            "client_id": "",
            "grant_id": "",
            "sid": "",
            "sid_encrypted": "",
            "authorization_code": "",
            "access_token": "",
            "id_token": "",
            "refresh_token": "",
            "claims": claims or {},
            "dump": _db,
            "key": ses_man_dump["key"],
            "salt": ses_man_dump["salt"],
        }

        for k, v in _db.items():
            # TODO: ask to roland to have something better than this
            if len(k) > 128 and ";;" not in k and v[0] == "oidcop.session.grant.Grant":
                data["sid_encrypted"] = k
                continue

            classname = v[0]
            field_name = self.session_attr_map[classname]
            if field_name == "sub":
                data["client_id"] = v[1]["subordinate"][0]
                data[field_name] = v[1]["user_id"]
            elif field_name == "client_id":
                data["grant_id"] = v[1]["subordinate"][0]
            elif field_name == "grant_id":
                _exp_time = datetime.datetime.fromtimestamp(v[1]["expires_at"])
                data["expires_at"] = _exp_time
                data["revoked"] = v[1]["revoked"]
                # data['sub'] = v[1]['sub']
                data["sid"] = k

                iss_tokens = {}
                for i in v[1]["issued_token"]:
                    k = list(i.keys())[0]
                    iss_tokens[k] = i[k]["value"]

                for token_type, attr in self.token_attr_map.items():
                        data[attr] = iss_tokens.get(token_type)

        logger.debug(f"Stored oidcop session data to MongoDB: {data}")

        self._connect()
        q = {"grant_id": data["grant_id"]}
        grant = self.session_db.find(q)
        if grant.count():
            # if update preserve the claims
            data["claims"] = grant.next()["claims"]
            self.session_db.update_one(q, {"$set": data})
        else:
            self.session_db.insert(data, check_keys=False)

    def load_session_from_db(
        self, parse_req, http_headers: dict, session_manager: SessionManager, **kwargs
    ) -> dict:
        """
        This method detects some usefull elements for doing a lookup in the session storage
        then loads the session inmemory

        It doesn't want to do any validation but only loading a session inmemory
        Security validation will be made later by oidcop in process_request
        """
        data = {}
        _q = {}
        http_authz = http_headers.get("headers", {}).get("authorization", {})
        if "Basic " in http_authz:
            # we want only bearer and dpop here!
            http_authz = None

        if parse_req.get("grant_type") == "authorization_code":
            # here for auth code flow and token endpoint only
            _q = {
                "authorization_code": parse_req["code"],
                "client_id": parse_req.get("client_id"),
            }
        elif http_authz:
            # here for userinfo endpoint
            _q = {
                "access_token": http_authz.replace("Bearer ", ""),
            }
        elif parse_req.get('token'):
            _q = {
                "access_token": parse_req['token'],
            }
        elif parse_req.get('grant_type') == 'refresh_token':
            _q = {
                "refresh_token": parse_req['refresh_token'],
            }
        else:
            logger.warning(
                f"load_session_from_db can't find any active session from: {parse_req}"
            )
            return data

        self._connect()
        res = self.session_db.find(_q)
        if res.count():
            _data = res.next()
            data["key"] = _data["key"]
            data["salt"] = _data["salt"]
            data["db"] = _data["dump"]
            session_manager.flush()
            session_manager.load(data)
        return data

    def get_claims_from_sid(self, sid: str):
        self._connect()
        res = self.session_db.find({"sid": sid})
        if res.count():
            return res.next()["claims"]

    def insert_client(self, client_data:dict):
        _client_data = copy.deepcopy(client_data)
        self._connect()
        client_id = _client_data['client_id']
        if self.get_client_by_id(client_id):
            logger.warning(f"OIDC Client {client_id} already present in the client db")
            return
        self.client_db.insert(_client_data)

    def get_client_by_basic_auth(self, request_authorization:str):
        cred = base64.b64decode(
                request_authorization.replace('Basic ', '').encode()
        )
        if not cred:
            return

        cred = cred.decode().split(':')
        if len(cred) == 2:
            client_id = cred[0]
            client_secret = cred[1]

            self._connect()
            res = self.client_db.find(
                {"client_id": client_id,
                 "client_secret": client_secret}
            )
            if res.count():
                return res.next()

    def get_registered_clients_id(self):
        self._connect()
        res = self.client_db.distinct('client_id')
        return res
