import copy
import logging
from collections import defaultdict

from saml2.config import Config
from saml2.metadata import entity_descriptor, entities_descriptor, sign_entity_descriptor
from saml2.time_util import in_a_while
from saml2.validate import valid_instance

from ..backends.saml2 import SAMLBackend
from ..frontends.saml2 import SAMLFrontend
from ..frontends.saml2 import SAMLMirrorFrontend
from ..plugin_loader import load_frontends, load_backends

logger = logging.getLogger(__name__)


def _create_entity_descriptor(entity_config):
    cnf = Config().load(copy.deepcopy(entity_config), metadata_construction=True)
    return entity_descriptor(cnf)


def _create_backend_metadata(backend_modules):
    backend_metadata = {}

    for plugin_module in backend_modules:
        if isinstance(plugin_module, SAMLBackend):
            logger.info("Generating SAML backend '%s' metadata", plugin_module.name)
            backend_metadata[plugin_module.name] = [_create_entity_descriptor(plugin_module.config["sp_config"])]

    return backend_metadata


def _create_mirrored_entity_config(frontend_instance, target_metadata_info, backend_name):
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

    merged_conf = _merge_dicts(copy.deepcopy(frontend_instance.config["idp_config"]), target_metadata_info)
    full_config = frontend_instance._load_endpoints_to_config(backend_name, target_metadata_info["entityid"],
                                                              config=merged_conf)

    proxy_entity_id = frontend_instance.config["idp_config"]["entityid"]
    full_config["entityid"] = "{}/{}".format(proxy_entity_id, target_metadata_info["entityid"])
    return full_config


def _create_frontend_metadata(frontend_modules, backend_modules):
    frontend_metadata = defaultdict(list)

    for frontend in frontend_modules:
        if isinstance(frontend, SAMLMirrorFrontend):
            for backend in backend_modules:
                logger.info("Creating metadata for frontend '%s' and backend '%s'".format(frontend.name, backend.name))
                meta_desc = backend.get_metadata_desc()
                for desc in meta_desc:
                    entity_desc = _create_entity_descriptor(
                        _create_mirrored_entity_config(frontend, desc.to_dict(), backend.name))
                    frontend_metadata[frontend.name].append(entity_desc)
        elif isinstance(frontend, SAMLFrontend):
            frontend.register_endpoints([backend.name for backend in backend_modules])
            entity_desc = _create_entity_descriptor(frontend.idp_config)
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

    backend_metadata = _create_backend_metadata(backend_modules)
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