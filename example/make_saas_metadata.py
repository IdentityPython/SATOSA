#!/usr/bin/env python
import argparse
import copy
import os
import sys
from future.backports.test.support import import_module
from pluginbase import PluginBase
from saml2.mdstore import MetaDataFile, MetadataStore
from saml2.metadata import entity_descriptor, metadata_tostring_fix
from saml2.metadata import entities_descriptor
from saml2.metadata import sign_entity_descriptor

from saml2.sigver import security_context
from saml2.validate import valid_instance
from saml2.config import Config

from saml2 import saml
from saml2 import md
from saml2.attribute_converter import ac_factory
from saml2.extension import dri
from saml2.extension import idpdisc
from saml2.extension import mdattr
from saml2.extension import mdrpi
from saml2.extension import mdui
from saml2.extension import shibmd
from saml2.extension import ui
from saml2 import xmldsig
from saml2 import xmlenc

# =============================================================================
# Script that creates a SAML2 metadata file from a pysaml2 entity configuration
# file
# =============================================================================
from repoze.who.plugins.sql import make_metadata_plugin

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='valid',
                    help="How long, in days, the metadata is valid from the time of creation")
parser.add_argument('-c', dest='cert', help='certificate')
parser.add_argument('-e', dest='ed', action='store_true',
                    help="Wrap the whole thing in an EntitiesDescriptor")
parser.add_argument('-i', dest='id',
                    help="The ID of the entities descriptor")
parser.add_argument('-k', dest='keyfile',
                    help="A file with a key to sign the metadata with")
parser.add_argument('-n', dest='name', default="")
parser.add_argument('-p', dest='path',
                    help="path to the configuration file")
parser.add_argument('-s', dest='sign', action='store_true',
                    help="sign the metadata")
parser.add_argument('-x', dest='xmlsec',
                    help="xmlsec binaries to be used for the signing")
parser.add_argument('-o', dest='output', default="local")
parser.add_argument('-a', dest='attrsmap')
parser.add_argument(dest="config", nargs="+")
args = parser.parse_args()

valid_for = 0
nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
paths = [".", "/opt/local/bin"]

if args.valid:
    # translate into hours
    valid_for = int(args.valid) * 24

ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    mdrpi.NAMESPACE: mdrpi,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc,
    shibmd.NAMESPACE: shibmd
}

metad = None

ATTRCONV = ac_factory(args.attrsmap)

mds = MetadataStore(ONTS.values(), None, None)


def create_combined_metadata(metadata_files):
    key = 1
    for data in metadata_files:
        # if args.ignore_valid:
        #     kwargs = {"check_validity": False}
        # else:
        kwargs = {}

        metad = MetaDataFile(ONTS.values(), None, filename="no_file", **kwargs)
        metad.parse_and_check_signature(data)
        mds.metadata["data_{}".format(key)] = metad
        key += 1

    print(mds.dumps(args.output))


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
    if fil.endswith(".py"):
        fil = fil[:-3]

    conf_mod = import_module(fil)

    plugin_base = PluginBase(package='endpoint_plugins')
    plugin_source = plugin_base.make_plugin_source(searchpath=conf_mod.PLUGIN_PATH)

    metadata = {"backends": {}, "frontends": {}}

    providers = []
    for backend_file in conf_mod.BACKEND_MODULES:
        backend_plugin = plugin_source.load_plugin(backend_file).setup(conf_mod.BASE)
        providers.append(backend_plugin.provider)
        metadata["backends"][backend_plugin.provider] = _make_metadata(backend_plugin.config)

    receivers = []
    for frontend_file in conf_mod.FRONTEND_MODULES:
        frontend_plugin = plugin_source.load_plugin(frontend_file).setup(conf_mod.BASE)
        receivers.append(frontend_plugin.receiver)

        proxy_idp_endpoints = frontend_plugin.config["endpoints"]
        for endpoint_category in proxy_idp_endpoints.keys():
            category_endpoints = []
            for provider in providers:
                for function, endpoint in proxy_idp_endpoints[endpoint_category].items():
                    endpoint = "%s/%s/%s" % (conf_mod.BASE, provider, endpoint)
                    category_endpoints.append((endpoint, function))
            frontend_plugin.config["idp_config"]["service"]["idp"]["endpoints"][
                endpoint_category] = category_endpoints

        metadata["frontends"][frontend_plugin.receiver] = _make_metadata(
            frontend_plugin.config["idp_config"])

    make_combined_metadata = False
    if make_combined_metadata:
        create_combined_metadata(metadata)
    else:
        for backend, data in metadata["backends"].items():
            file = open("%s_backend_metadata.xml" % backend, "w")
            file.write(data)
            file.close()

        for frontend, data in metadata["frontends"].items():
            file = open("%s_frontend_metadata.xml" % frontend, "w")
            file.write(data)
            file.close()
