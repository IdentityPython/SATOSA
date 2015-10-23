#!/usr/bin/env python
import argparse
import copy
import os
import sys

from saml2.metadata import entity_descriptor, metadata_tostring_fix
from saml2.metadata import entities_descriptor
from saml2.metadata import sign_entity_descriptor
from saml2.sigver import security_context
from saml2.validate import valid_instance
from saml2.config import Config
from satosa.backends.saml2 import SamlBackend
from satosa.frontends.saml2 import SamlFrontend
from satosa.plugin_loader import _load_plugins, backend_filter, frontend_filter
from satosa.satosa_config import SATOSAConfig

# =============================================================================
# Script that creates SAML2 metadata files from
# SATOSA Saml2 frontends and backends
# =============================================================================

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='valid', help="How long, in days, the metadata is valid from the time of creation")
parser.add_argument('-c', dest='cert', help='certificate')
parser.add_argument('-i', dest='id', help="The ID of the entities descriptor")
parser.add_argument('-k', dest='keyfile', help="A file with a key to sign the metadata with")
parser.add_argument('-n', dest='name', default="")
parser.add_argument('-s', dest='sign', action='store_true', help="sign the metadata")
parser.add_argument('-x', dest='xmlsec', help="xmlsec binaries to be used for the signing")
parser.add_argument('-f', dest="frontend", help='generate frontend metadata', action="store_true")
parser.add_argument('-b', dest="backend", help='generate backend metadata', action="store_true")
parser.add_argument(dest="config", nargs="+")
args = parser.parse_args()

generate_frontend = args.frontend
generate_backend = args.backend

# If no generate frontend/backend option, generate both
if not (args.frontend or args.backend):
    generate_frontend = True
    generate_backend = True

valid_for = 0
nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}

if args.valid:
    # translate into hours
    valid_for = int(args.valid) * 24

def _make_metadata(config_dict):
    eds = []
    cnf = Config()
    cnf.load(copy.deepcopy(config_dict), metadata_construction=True)

    if valid_for:
        cnf.valid_for = valid_for
    eds.append(entity_descriptor(cnf))

    conf = Config()
    conf.key_file = args.keyfile
    conf.cert_file = args.cert
    conf.debug = 1
    conf.xmlsec_binary = args.xmlsec
    secc = security_context(conf)

    if args.id:
        desc, xmldoc = entities_descriptor(eds, valid_for, args.name, args.id,
                                           args.sign, secc)
        valid_instance(desc)
        print(desc.to_string(nspair))
    else:
        for eid in eds:
            if args.sign:
                assert conf.key_file
                assert conf.cert_file
                eid, xmldoc = sign_entity_descriptor(eid, args.id, secc)
            else:
                xmldoc = None

            valid_instance(eid)
            xmldoc = metadata_tostring_fix(eid, nspair, xmldoc).decode()
            return xmldoc


for filespec in args.config:
    bas, fil = os.path.split(filespec)
    if bas != "":
        sys.path.insert(0, bas)

    config = SATOSAConfig(fil)
    metadata = {"backends": {}, "frontends": {}}
    backend_plugins = _load_plugins(config.PLUGIN_PATH, config.BACKEND_MODULES, backend_filter, config.BASE)
    frontend_plugins = _load_plugins(config.PLUGIN_PATH, config.FRONTEND_MODULES, frontend_filter, config.BASE)

    providers = []
    for plugin in backend_plugins:
        providers.append(plugin.name)
        if issubclass(plugin.module, SamlBackend) and generate_backend:
            metadata["backends"][plugin.name] = _make_metadata(plugin.config["config"])

    if generate_frontend:
        for plugin in frontend_plugins:
            if issubclass(plugin.module, SamlFrontend):
                module = plugin.module(None, plugin.config)
                module.register_endpoints(providers)
                metadata["frontends"][plugin.name] = _make_metadata(module.config)

    if generate_backend:
        for backend, data in metadata["backends"].items():
            file = open("%s_backend_metadata.xml" % backend, "w")
            file.write(data)
            file.close()
    if generate_frontend:
        for frontend, data in metadata["frontends"].items():
            file = open("%s_frontend_metadata.xml" % frontend, "w")
            file.write(data)
            file.close()
