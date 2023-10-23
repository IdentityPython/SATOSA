from sqlalchemy.ext.declarative import declarative_base


class SessionStorage:
    def __init__(self, config):
        self.db_config = config["SESSION_STORAGE"]


class SessionStorageInMemory(SessionStorage):
    """
    In-memory storage
    """

    def __init__(self, config):
        super().__init__(config)
        self.frontend_sessions = []
        self.backend_sessions = []
        self.session_maps = []

    def store_frontend_session(self, frontend_name, requester, subject_id, sid):
        self.frontend_sessions.append({"frontend_name": frontend_name,
                                       "requester": requester,
                                       "subject_id": subject_id,
                                       "sid": sid
                                       })

    def store_backend_session(self, sid, issuer):
        self.backend_sessions.append({"sid": sid,
                                      "issuer": issuer})

    def get_backend_session(self, sid, issuer=None):
        for session in self.backend_sessions:
            if issuer and session.get("sid") == sid and session.get("issuer") == issuer:
                return session
            elif session.get("sid") == sid:
                return session

    def delete_backend_session(self, sid):
        for session in self.backend_sessions:
            if session.get("sid") == sid:
                self.backend_sessions.remove(session)
                return session

    def store_session_map(self, frontend_sid, backend_sid, issuer):
        self.session_maps.append({"frontend_sid": frontend_sid,
                                  "backend_sid": backend_sid,
                                  "issuer": issuer
                                  })

    def delete_session_map(self, frontend_sid, backend_sid, issuer):
        for session_map in self.session_maps:
            if session_map.get("frontend_sid") == frontend_sid and session_map.get("issuer") == issuer and \
                    session_map.get("backend_sid") == backend_sid:
                self.session_maps.remove(session_map)

    def get_frontend_session(self, sid):
        for session in self.frontend_sessions:
            if session.get("sid") == sid:
                return session

    def delete_frontend_session(self, sid):
        for session in self.frontend_sessions:
            if session.get("sid") == sid:
                self.frontend_sessions.remove(session)

    def get_frontend_sessions_by_backend_sid_and_issuer(self, backend_sid, issuer):
        sessions = list()
        for session_map in self.session_maps:
            if session_map.get("backend_sid") == backend_sid and session_map.get("issuer") == issuer:
                frontend_sid = session_map.get("frontend_sid")
                for session in self.frontend_sessions:
                    if session.get("sid") == frontend_sid:
                        sessions.append(session)
                break
        return sessions


Base = declarative_base()


class FrontendSession(Base):
    from sqlalchemy import Column, Integer, String

    __tablename__ = 'frontend_session'
    id = Column(Integer, primary_key=True, autoincrement=True)
    frontend_name = Column(String)
    requester = Column(String)
    subject_id = Column(String)
    sid = Column(String)


class BackendSession(Base):
    from sqlalchemy import Column, Integer, String

    __tablename__ = 'backend_session'
    id = Column(Integer, primary_key=True, autoincrement=True)
    sid = Column(String)
    issuer = Column(String)


class FrontendBackendSession(Base):
    from sqlalchemy import Column, Integer, String

    __tablename__ = 'frontend_backend_session'
    id = Column(Integer, primary_key=True, autoincrement=True)
    frontend_sid = Column(String)
    backend_sid = Column(String)


class SessionStoragePostgreSQL(SessionStorage):
    """
    PostgreSQL storage
    """

    def __init__(self, config):
        super().__init__(config)

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        HOST = self.db_config["host"]
        PORT = self.db_config["port"]
        DB_NAME = self.db_config["db_name"]
        USER = self.db_config["user"]
        PWD = self.db_config["password"]

        engine = create_engine("postgresql://{USER}:{PWD}@{HOST}:{PORT}/{DB_NAME}".format(
            USER=USER,
            PWD=PWD,
            HOST=HOST,
            PORT=PORT,
            DB_NAME=DB_NAME
        ))
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)

    def store_frontend_session(self, frontend_name, requester, subject_id, sid):
        session = self.Session()
        frontend_session = FrontendSession(
            frontend_name=frontend_name,
            requester=requester,
            subject_id=subject_id,
            sid=sid
        )
        session.add(frontend_session)
        session.commit()
        session.close()

    def store_backend_session(self, sid, issuer):
        session = self.Session()
        backend_session = FrontendSession(
            sid=sid,
            issuer=issuer
        )
        session.add(backend_session)
        session.commit()
        session.close()

    def store_session_map(self, frontend_sid, backend_sid):
        session = self.Session()
        frontend_backend_session = FrontendBackendSession(
            frontend_sid=frontend_sid,
            backend_sid=backend_sid
        )
        session.add(frontend_backend_session)
        session.commit()
        session.close()
