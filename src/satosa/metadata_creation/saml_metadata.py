import copy
import logging
from collections import defaultdict

from saml2.config import Config
from saml2.metadata import entity_descriptor, entities_descriptor, sign_entity_descriptor
from saml2.time_util import in_a_while
from saml2.validate import valid_instance

from ..backends.saml2 import SAMLBackend
from ..backends.saml2 import SAMLMirrorBackend
from ..backends.openid_connect import OpenIDConnectBackend
from ..frontends.saml2 import SAMLFrontend
from ..frontends.saml2 import SAMLMirrorFrontend
from ..frontends.openid_connect import OpenIDConnectFrontend
from ..plugin_loader import load_frontends, load_backends

from ..metadata_creation.description import MetadataDescription
from base64 import urlsafe_b64encode, urlsafe_b64decode

logger = logging.getLogger(__name__)

def urlenc(s):
    enc = urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')
    return enc

def _create_entity_descriptor(entity_config):
    cnf = Config().load(copy.deepcopy(entity_config), metadata_construction=True)
    return entity_descriptor(cnf)

def _create_mirrored_sp_entity_config(backend_instance, target_metadata_info, frontend_name):
    def _merge_dicts(a, b):
        for key, value in b.items():
            #if key in ["organization", "contact_person"]:
                # avoid copying contact info from the target provider
                #continue
            if key in a and isinstance(value, dict):
                a[key] = _merge_dicts(a[key], b[key])
            else:
                a[key] = value

        return a

    if "service" in target_metadata_info:
        if not "sp" in target_metadata_info["service"]:
            target_metadata_info["service"]["sp"] = dict()
        target_metadata_info["service"]["sp"]["ui_info"] = target_metadata_info["service"].pop("ui_info")
    merged_conf = _merge_dicts(copy.deepcopy(backend_instance.config["sp_config"]), target_metadata_info)
    proxy_entity_id = backend_instance.config["sp_config"]["entityid"]
    merged_conf["entityid"] = "{}/{}/{}".format(proxy_entity_id, frontend_name, target_metadata_info["entityid"])
    return merged_conf

def _create_mirrored_idp_entity_config(frontend_instance, target_metadata_info, backend_name):
    def _merge_dicts(a, b):
        for key, value in b.items():
            if key in ["organization", "contact_person"]:
                # avoid copying contact info from the target provider
                continue
            if key in a and isinstance(value, dict):
                a[key] = _merge_dicts(a[key], b[key])
            else:
                a[key] = value

        return a

    if "service" in target_metadata_info:
        if not "idp" in target_metadata_info["service"]:
            target_metadata_info["service"]["idp"] = dict()
        target_metadata_info["service"]["idp"]["ui_info"] = target_metadata_info["service"].pop("ui_info")
    merged_conf = _merge_dicts(copy.deepcopy(frontend_instance.config["idp_config"]), target_metadata_info)
    full_config = frontend_instance._load_endpoints_to_config(backend_name, target_metadata_info["entityid"],
                                                              config=merged_conf)

    proxy_entity_id = frontend_instance.config["idp_config"]["entityid"]
    full_config["entityid"] = "{}/{}/{}".format(proxy_entity_id, backend_name, target_metadata_info["entityid"])
    return full_config

def _create_backend_metadata(backend_modules, frontend_modules):
    backend_metadata = defaultdict(list)

    for backend in backend_modules:
        if isinstance(backend, SAMLMirrorBackend):
            backend_entityid = backend.config["sp_config"]["entityid"]
            frontend_metadata = defaultdict(list)
            for frontend in frontend_modules:
                if isinstance(frontend, SAMLFrontend):
                    logger.info("Creating SAML backend Mirror metadata for '{}' and frontend '{}'".format(backend.name, frontend.name))
                    frontend.register_endpoints([backend.name])
                    meta_desc = frontend.get_metadata_desc()
                    for desc in meta_desc:
                        logger.info("Backend %s EntityID %s" % (backend.name, urlsafe_b64decode(desc.to_dict()["entityid"]).decode("utf-8")))
                        mirrored_sp_entity_config = _create_mirrored_sp_entity_config(backend, desc.to_dict(), frontend.name)
                        entity_desc = _create_entity_descriptor(mirrored_sp_entity_config)
                        backend_metadata[backend.name].append(entity_desc)
                elif isinstance(frontend, OpenIDConnectFrontend):
                    logger.info("Creating SAML backend Mirror metadata for '{}' and OIDC frontend '{}'".format(backend.name, frontend.name))
                    frontend.register_endpoints([backend.name])
                    for client_id, client in frontend.provider.clients.items():
                        logger.info("OIDC client_id %s %s" % (client_id, client.get("client_name")))
                        backend.config["sp_config"]["entityid"] = backend_entityid + "/" + frontend.name + "/" + urlenc(client_id)
                        backend_metadata[backend.name].append(_create_entity_descriptor(backend.config["sp_config"]))
        elif isinstance(backend, SAMLBackend):
            logger.info("Creating SAML backend '%s' metadata", backend.name)
            logger.info("Backend %s EntityID %s" % (backend.name, backend.config["sp_config"]["entityid"]))
            backend_metadata[backend.name].append(_create_entity_descriptor(backend.config["sp_config"]))

    return backend_metadata


def _create_frontend_metadata(frontend_modules, backend_modules):
    frontend_metadata = defaultdict(list)

    for frontend in frontend_modules:
        if isinstance(frontend, SAMLMirrorFrontend):
            for backend in backend_modules:
                if isinstance(backend, SAMLBackend):
                    logger.info("Creating SAML Mirrored metadata for frontend '{}' and backend '{}'".format(frontend.name, backend.name))
                    meta_desc = backend.get_metadata_desc()
                    for desc in meta_desc:
                        mirrored_idp_entity_config = _create_mirrored_idp_entity_config(frontend, desc.to_dict(), backend.name)
                        entity_desc = _create_entity_descriptor(mirrored_idp_entity_config)
                        frontend_metadata[frontend.name].append(entity_desc)
                if isinstance(backend, OpenIDConnectBackend):
                    logger.info("Creating SAML Mirrored metadata for frontend '{}' and OIDC backend '{}'".format(frontend.name, backend.name))
                    meta_desc = backend.get_metadata_desc()
                    for desc in meta_desc:
                        mirrored_idp_entity_config = _create_mirrored_idp_entity_config(frontend, desc.to_dict(), backend.name)
                        entity_desc = _create_entity_descriptor(mirrored_idp_entity_config)
                        frontend_metadata[frontend.name].append(entity_desc)
        elif isinstance(frontend, SAMLFrontend):
            logger.info("Creating SAML frontend '%s' metadata" % frontend.name)
            frontend.register_endpoints([backend.name for backend in backend_modules])
            entity_desc = _create_entity_descriptor(frontend.config["idp_config"])
            frontend_metadata[frontend.name].append(entity_desc)

    return frontend_metadata


def create_entity_descriptors(satosa_config):
    """
    Creates SAML metadata strings for the configured front- and backends.
    :param satosa_config: configuration of the proxy
    :return: a tuple of the frontend metadata (containing IdP entities) and the backend metadata (containing SP
             entities).

    :type satosa_config: satosa.satosa_config.SATOSAConfig
    :rtype: Tuple[str, str]
    """
    frontend_modules = load_frontends(satosa_config, None, satosa_config["INTERNAL_ATTRIBUTES"])
    backend_modules = load_backends(satosa_config, None, satosa_config["INTERNAL_ATTRIBUTES"])
    logger.info("Loaded frontend plugins: {}".format([frontend.name for frontend in frontend_modules]))
    logger.info("Loaded backend plugins: {}".format([backend.name for backend in backend_modules]))

    backend_metadata = _create_backend_metadata(backend_modules, frontend_modules)
    frontend_metadata = _create_frontend_metadata(frontend_modules, backend_modules)

    return frontend_metadata, backend_metadata


def create_signed_entities_descriptor(entity_descriptors, security_context, valid_for=None):
    """
    :param entity_descriptors: the entity descriptors to put in in an EntitiesDescriptor tag and sign
    :param security_context: security context for the signature
    :param valid_for: number of hours the metadata should be valid
    :return: the signed XML document

    :type entity_descriptors: Sequence[saml2.md.EntityDescriptor]]
    :type security_context: saml2.sigver.SecurityContext
    :type valid_for: Optional[int]
    """
    entities_desc, xmldoc = entities_descriptor(entity_descriptors, valid_for=valid_for, name=None, ident=None,
                                                sign=True, secc=security_context)
    if not valid_instance(entities_desc):
        raise ValueError("Could not construct valid EntitiesDescriptor tag")

    return xmldoc


def create_signed_entity_descriptor(entity_descriptor, security_context, valid_for=None):
    """
    :param entity_descriptor: the entity descriptor to sign
    :param security_context: security context for the signature
    :param valid_for: number of hours the metadata should be valid
    :return: the signed XML document

    :type entity_descriptor: saml2.md.EntityDescriptor]
    :type security_context: saml2.sigver.SecurityContext
    :type valid_for: Optional[int]
    """
    if valid_for:
        entity_descriptor.valid_until = in_a_while(hours=valid_for)

    entity_desc, xmldoc = sign_entity_descriptor(entity_descriptor, None, security_context)

    if not valid_instance(entity_desc):
        raise ValueError("Could not construct valid EntityDescriptor tag")

    return xmldoc
