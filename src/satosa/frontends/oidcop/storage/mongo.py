import json
import logging
import pymongo

from . base import SatosaOidcStorage


logger = logging.getLogger(__name__)


class Mongodb(SatosaOidcStorage):
    session_attr_map = {
        'oidcop.session.info.UserSessionInfo': 'sub',
        'oidcop.session.info.ClientSessionInfo': 'client_id',
        'oidcop.session.grant.Grant': 'grant_id'
    }
    token_attr_map = {
        'oidcop.session.token.AuthorizationCode': 'authorization_code',
        'oidcop.session.token.AccessToken': 'access_token',
        'oidcop.session.token.RefreshToken': 'refresh_token',
        'oidcop.session.token.IDToken': 'id_token'
    }

    def __init__(self, storage_conf:dict, url:str, connection_params: dict = None):
        self.storage_conf = storage_conf
        self.url = url
        self.connection_params = connection_params
        self.client = None
        self._connect()

        self.db = getattr(self.client, storage_conf['db_name'])
        self.client_db = self.db[storage_conf['collections']['client']]
        self.session_db = self.db[storage_conf['collections']['session']]

    def _connect(self):
        if not self.client or not self.client.server_info():
            self.client = pymongo.MongoClient(
                self.url, **self.connection_params)

    def get_client_by_id(self, client_id):
        self._connect()
        res = self.client_db.find(
            {'client_id': client_id}
        )

        # improvement: unique index on client_id in client collection
        if res.count():
            # it returns the first one
            return res.next()

    def store_session_to_db(self, session_manager, claims):
        ses_man_dump = session_manager.dump()
        _db = ses_man_dump["db"]
        data = {
            'sub': "",
            'client_id': "",
            'grant_id': "",
            'sid': "",
            'sid_encrypted': "",
            'authorization_code': "",
            'access_token': "",
            'id_token': "",
            'refresh_token': "",
            'expires_at': 0,
            'claims' : claims or {},
            'dump': _db,
            'key': ses_man_dump["key"],
            'salt': ses_man_dump["salt"]
        }

        for k, v in _db.items():
            # TODO: ask to roland to have something better than this
            if (
                len(k) > 128
                and ';;' not in k
                and v[0] == 'oidcop.session.grant.Grant'
            ):
                data['sid_encrypted'] = k
                continue

            classname = v[0]
            field_name = self.session_attr_map[classname]
            if field_name == 'sub':
                data['client_id'] = v[1]['subordinate'][0]
                data[field_name] = v[1]['user_id']
            elif field_name == 'client_id':
                data['grant_id'] = v[1]['subordinate'][0]
            elif field_name == 'grant_id':
                data['expires_at'] = v[1]['expires_at']
                data['revoked'] = v[1]['revoked']
                # data['sub'] = v[1]['sub']
                data['sid'] = k

                iss_tokens = {}
                for i in v[1]['issued_token']:
                    k = list(i.keys())[0]
                    iss_tokens[k] = i[k]['value']

                for token_type,attr in self.token_attr_map.items():
                    data[attr] = iss_tokens.get(token_type, "")

        logger.debug(data)
        self._connect()

        # TODO: get/update or create
        q = {'grant_id': data['grant_id']}
        grant = self.session_db.find(q)
        if grant.count():
            # if update preserve the claims
            data['claims'] = grant.next()['claims']
            self.session_db.update_one(q, {"$set": data} )
        else:
            self.session_db.insert(data, check_keys=False)


    def load_session_from_db(self, parse_req, http_headers, session_manager, **kwargs):
        data = {}
        _q = {}
        res = None
        http_authz = http_headers.get('headers', {}).get('authorization')

        if parse_req.get('grant_type') == 'authorization_code':
            _q = {
                "authorization_code": parse_req['code'],
                'client_id': parse_req.get('client_id')
            }
        elif parse_req.get('access_token'):
            _q = {
                "access_token": parse_req['access_token'],
                'client_id': parse_req.get('client_id')
            }
        elif http_authz:
            _q = {
                "access_token": http_authz.replace('Bearer ', ""),
            }

        if not _q:
            logger.info(
                f"load_session_from_db can't find any active session from: {parse_req}"
            )
            return

        res = self.session_db.find(_q)
        if res.count():
            _data = res.next()
            data['key'] = _data['key']
            data['salt'] = _data['salt']
            data['db'] = _data['dump']
            session_manager.flush()
            session_manager.load(data)
            return data

    def get_claims_from_sid(self, sid):
        res = self.session_db.find({'sid': sid})
        if res.count():
            return res.next()['claims']
