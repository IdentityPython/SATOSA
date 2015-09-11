#!/usr/bin/env python
__author__ = 'rolandh'

import os
import sys
from urllib.parse import urlparse
import traceback
import logging
from six import string_types
from urllib.parse import parse_qs

from saml2 import saml, mcache, samlp, BINDING_HTTP_ARTIFACT, BINDING_URI
from saml2 import s_utils
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT

from saml2.httputil import BadRequest
from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.httputil import Unauthorized
from saml2.httputil import Redirect
from saml2.httputil import NotFound

from saml2.httputil import unpack_any
from saml2.httputil import unpack_artifact

from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def not_authn_2(environ, start_response, state, req_info):
    return bad_request(environ, start_response, "Unimplemented")


# ----------------------------------------------------------------------------


def exception_log():
    for line in traceback.format_exception(*sys.exc_info()):
        logger.info("## %s" % line.strip("\n"))


def cgi_field_storage_to_dict(field_storage):
    """Get a plain dictionary, rather than the '.value' system used by the
    cgi module."""

    params = {}
    for key in field_storage.keys():
        try:
            params[key] = field_storage[key].value
        except AttributeError:
            if isinstance(field_storage[key], string_types):
                params[key] = field_storage[key]

    return params


# ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def logout_response(server_env, req_info, status=None):
    logger.info("LOGOUT of '%s' by '%s'" % (req_info.subject_id(),
                                            req_info.sender()))

    _idp = server_env["idp"]
    if req_info.binding != BINDING_SOAP:
        bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        binding, destination = _idp.pick_binding("single_logout_service",
                                                 bindings,
                                                 entity_id=req_info.sender())
        bindings = [binding]
    else:
        bindings = [BINDING_SOAP]
        destination = ""

    response = _idp.create_logout_response(req_info.message, bindings,
                                           status, sign=server_env["SIGN"])

    ht_args = _idp.apply_binding(bindings[0], "%s" % response,
                                 destination, req_info.relay_state,
                                 response=True)

    return Response(**ht_args)


def err_response(server_env, req_info, info,
                 endpoint="assertion_consumer_service"):
    """
    :param info: Either an exception or and 2-tuple (SAML error code, txt)
    """

    _idp = server_env["idp"]

    if req_info.binding != BINDING_SOAP:
        bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        binding, destination = _idp.pick_binding(endpoint, bindings,
                                                 entity_id=req_info.sender())
        bindings = [binding]
    else:
        bindings = [BINDING_SOAP]
        destination = ""

    err_resp = _idp.create_error_response(req_info.message.id, destination,
                                          info, issuer=req_info.sender())

    logger.info("ErrResponse: %s" % err_resp)

    ht_args = _idp.apply_binding(bindings[0], "%s" % err_resp,
                                 destination, req_info.relay_state,
                                 response=True)

    return Response(**ht_args)


def authn_response(server_env, req_info, userid, identity,
                   authn=None, authn_decl=None, service=""):
    # base 64 encoded request

    logger.debug("User info: %s" % identity)

    if service:
        issuer = "%s%s" % (server_env["base_url"], service)
    else:
        issuer = None

    logger.info("ISSUER: %s" % issuer)
    _idp = server_env["idp"]

    binding, destination = _idp.pick_binding("assertion_consumer_service",
                                             entity_id=req_info.sender())

    logger.debug("binding: %s, destination: %s" % (binding, destination))

    authn_resp = _idp.create_authn_response(identity, req_info.message.id,
                                            destination,
                                            req_info.sender(),
                                            req_info.message.name_id_policy,
                                            str(userid), authn=authn,
                                            sign_assertion=server_env["SIGN"],
                                            authn_decl=authn_decl,
                                            issuer=issuer)

    logger.info("LOGIN success: sp_entity_id=%s#authn=%s" % (req_info.sender(),
                                                             authn))
    logger.debug("AuthNResponse: %s" % authn_resp)

    ht_args = _idp.apply_binding(binding, "%s" % authn_resp, destination,
                                 req_info.relay_state, response=True)

    logger.debug("ht_args: %s" % ht_args)

    if "status" in ht_args and ht_args["status"] == 302:
        return Redirect(ht_args["data"], headers=ht_args["headers"])
    else:
        return Response(ht_args["data"], headers=ht_args["headers"])


# -----------------------------------------------------------------------------


def get_eptid(server_env, req_info, session):
    return server_env["eptid"].get(server_env["idp"].config.entityid,
                                   req_info.sender(), session["permanent_id"],
                                   session["authn_auth"])


# noinspection PyUnusedLocal
def do_req_response(server_env, req_info, response, environ, source,
                    session, service=""):
    if session["status"] == "FAILURE":
        info = (samlp.STATUS_AUTHN_FAILED, response)
        return err_response(server_env, req_info, info)

    identity = response
    if identity:
        userid = identity["uid"]
        if "eduPersonTargetedID" not in identity:
            identity["eduPersonTargetedID"] = get_eptid(server_env, req_info,
                                                        session)
    else:
        userid = "anonymous"

    logger.debug("[do_req_response] identity: %s" % (identity,))

    session["identity"] = identity
    session["eptid"] = identity["eduPersonTargetedID"]
    _authn_info = {"class_ref": saml.AUTHN_PASSWORD, "authn_auth": source}
    return authn_response(server_env, req_info, userid, identity,
                          authn=_authn_info, service=service)


def do_logout_response(req_info, status=None):
    if status:
        status = s_utils.error_status_factory((status, "Logout failed"))

    return logout_response(req_info, status)


# -----------------------------------------------------------------------------


def return_active_info(environ, start_response, server_env, state):
    logger.debug("[return_active_info]")

    try:
        req_info = get_authn_request(environ, server_env)
    except UnknownPrincipal:
        resp = BadRequest("Don't know the SP that referred you here")
        return resp(environ, start_response)
    except UnsupportedBinding:
        resp = BadRequest(
            "Don't know how to reply to the SP that referred you here")
        return resp(environ, start_response)
    except Exception:
        resp = BadRequest("Exception while parsing the AuthnRequest")
        return resp(environ, start_response)

    if req_info is None:
        # return error message
        resp = BadRequest("Missing SAMLRequest")
        return resp(environ, start_response)

    if req_info:
        session = state.old_session(req_info.sender())
        if session:
            if req_info.message.force_authn:  # even if active session
                session.reset()
                session["req_info"] = req_info
                start_response("302 Found", [("Location", "/")])
                return [""]

            identity = session["identity"]
            if not identity:
                return not_authn_2(environ, start_response, state, req_info)
        if not session or not session.active():
            return not_authn_2(environ, start_response, state, req_info)
    else:
        return not_authn_2(environ, start_response, state, req_info)

    logger.debug("[return_active_info] Old session: %s" % session)
    identity = session["identity"]
    try:
        _eptid = session["eptid"]
    except KeyError:
        _eptid = get_eptid(server_env, req_info, session)
        session["eptid"] = _eptid

    identity["eduPersonTargetedID"] = _eptid
    authn_auth = session["authn_auth"]
    # def do_req_response(req_info, response, _environ, source, session,
    # service):

    resp = do_req_response(server_env, req_info, identity, environ, authn_auth,
                           session)
    return resp(environ, start_response)


# ----------------------------------------------------------------------------


def do_logout(environ, start_response, server_env, state):
    """ Get a request """
    logger.info("--- LOGOUT ---")

    _dict, binding = unpack_any(environ)
    logger.debug("Binding: %s, _dict: %s" % (binding, _dict))
    resp = None
    if binding == BINDING_HTTP_ARTIFACT:
        resp = ServiceError("Artifact support not yet implemented")
    elif binding == BINDING_URI:
        resp = BadRequest("Binding not applicable")

    if resp:
        return resp(environ, start_response)

    try:
        request = _dict["SAMLRequest"]
    except KeyError:
        resp = BadRequest("Request missing")
        return resp(environ, start_response)

    try:
        req_info = server_env["idp"].parse_logout_request(request)
        req_info.binding = binding
        try:
            req_info.relay_state = _dict["relay_state"]
        except KeyError:
            pass

        logger.debug("LOGOUT request parsed OK")
        logger.debug("REQ_INFO: %s" % req_info.message)
    except KeyError as exc:
        logger.error("logout request error: %s" % (exc,))
        resp = BadRequest("Erroneous logout request")
        return resp(environ, start_response)

    if not state.known_session(req_info.issuer()):
        resp = BadRequest("Logout request from someone I know nothing about")
        return resp(environ, start_response)

    # look for the subject
    subject = req_info.subject_id()
    logger.debug("Logout subject: %s" % (subject.text.strip(),))
    status = None

    session = state.old_session(req_info.sender())
    if session:
        session["authentication"] = "OFF"

    resp = do_logout_response(req_info, status)
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

def authentication_state(info):
    try:
        return info["authentication"]
    except KeyError:
        return ""


def get_session_id(environ):
    try:
        parres = urlparse.urlparse(environ["HTTP_REFERER"])
        qdict = parse_qs(parres.query)
        return qdict["sessionid"][0]
    except KeyError:
        qdict = parse_qs(environ["QUERY_STRING"])
        return qdict["sessionid"][0]


def bad_request(environ, start_response, msg):
    resp = BadRequest(msg)
    return resp(environ, start_response)


# noinspection PyUnusedLocal
def base(environ, start_response, _user):
    resp = Response("PLACEHOLDER !!!")
    return resp(environ, start_response)


# =============================================================================


def get_authn_request(environ, server_env):
    """
    Tries to pry and parse the AuthnRequest from the query.

    :param environ: The environ variables
    :param server_env: Server environment
    :return: The request info if no error was encountered while parsing the
        AuthnRequest. None if an error was encountered. None if there was no
        AuthnRequest.
    """

    # Redirect or POST bindings supported
    _dict = unpack_artifact(environ)

    if not _dict:
        return None

    req = _dict["SAMLRequest"]
    logger.debug("[get_authn_request] query: %s" % req)
    if req:
        try:
            _req = server_env["idp"].parse_authn_request(req)
            logger.debug("[get_authn_request] AUTHN request parsed OK")
            if environ["REQUEST_METHOD"] == "GET":
                _req.binding = BINDING_HTTP_REDIRECT
            else:
                _req.binding = BINDING_HTTP_POST
            try:
                _req.relay_state = _dict["RelayState"]
            except KeyError:
                pass
            return _req
        except KeyError:
            return None
        except (UnknownPrincipal, UnsupportedBinding):
            logger.error(
                "[get_authn_request] Unknown principal or unknown binding")
            raise

    return None


# noinspection PyUnusedLocal
def authn_init(environ, start_response, server_env, state, _debug,
               _service):
    """ Initialize an authentication session. Creates a session instance
    and adds it to the server state information.

    :param environ:
    :param start_response:
    :param server_env:
    :param state:
    :param _debug:
    :param _service:
    :return:
    """
    logger.debug("[%s]" % _service)

    try:
        req, relay_state = get_authn_request(environ, server_env)
    except Exception:
        raise Exception("Exception while parsing the AuthnRequest")

    if req:
        logger.debug("[%s]req: %s" % (_service, req.message))
        session = state.get_session(req.sender())
        state.add_session(session.session_id)
        _ = session.remember(req)
        sidd = session.sid_digest
    else:
        session = None
        sidd = 0

    logger.debug("[%s]SESSION[%s]: %s" % (_service, sidd, session))

    return session, sidd


# ----------------------------------------------------------------------------


def static_file(server_env, path):
    try:
        os.stat(server_env["STATIC_DIR"] + path)
        return True
    except OSError:
        return False


def metadata_file(server_env, path):
    try:
        os.stat(server_env["METADATA_DIR"] + path)
        return True
    except OSError:
        return False


def static(environ, start_response, path):
    try:
        text = open(path).read()
        if path.endswith(".ico"):
            resp = Response(text, headers=[('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            resp = Response(text, headers=[('Content-Type', 'text/html')])
        elif path.endswith(".txt"):
            resp = Response(text, headers=[('Content-Type', 'text/plain')])
        else:
            resp = Response(text, headers=[('Content-Type', 'text/xml')])
    except IOError:
        resp = NotFound()
    return resp(environ, start_response)


# ----------------------------------------------------------------------------
#


def _dict_to_table(dic, border=""):
    result = ["<table border=\"%s\">" % border]
    for key, val in dic.items():
        result.append("<tr><td>%s</td><td>%s</td></tr>" % (key, val))
    result.append("</table>")
    return "\n".join(result)


SOCIAL_SRV = ["twitter", "openid", "google", "facebook", "liveid"]


# noinspection PyUnusedLocal
def status(environ, start_response, state):
    """ Return the status of the users SSO sessions """
    result = []
    for session in state.sessions():
        for typ in SOCIAL_SRV:
            if session[typ]:
                result.append("<h2>%s</h2>" % typ.upper())
                break

        result.append("<table border=\"1\">")
        for prop in ["authentication", "identity"]:
            val = session[prop]
            if isinstance(val, dict):
                val = _dict_to_table(val)
            result.append("<tr><td>%s</td><td>%s</td></tr>" % (prop, val))
        result.append("</table>")
        result.append("<br>")

    resp = Response(result)
    return resp(environ, start_response)


# ----------------------------------------------------------------------------


def active_session(session):
    try:
        info = session.get()
        if "authentication" in info and info["authentication"] == "OK":
            return True
    except mcache.ToOld:
        pass

    return False


def login_attempt(environ):
    try:
        query = parse_qs(environ["QUERY_STRING"])
        if query and "SAMLRequest" in query:
            return True
    except KeyError:
        pass

    return False


# ----------------------------------------------------------------------------


def not_found(environ, start_response):
    resp = NotFound()
    return resp(environ, start_response)


def not_authn(environ, start_response):
    resp = Unauthorized()
    return resp(environ, start_response)
