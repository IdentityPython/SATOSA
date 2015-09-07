#!/usr/bin/env python
import argparse
import copy
import os
import sys
from future.backports.test.support import import_module
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
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
parser.add_argument('-w', dest='wellknown',
                    help="Use wellknown namespace prefixes")
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
    tmp_file_name = "tmp_cmb_workfile.xml"
    for data in metadata_files:
        # if args.ignore_valid:
        #     kwargs = {"check_validity": False}
        # else:
        kwargs = {}

        f = open(tmp_file_name, "w")
        f.write(data)
        f.close()

        metad = MetaDataFile(ONTS.values(), None, filename=tmp_file_name, **kwargs)
        metad.load()
        mds.metadata["data_{}".format(key)] = metad
        key += 1

    os.remove(tmp_file_name)
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


def create_config_file(config, metadata_desc, mod_conf):
    cnf = copy.deepcopy(config.CONFIG)
    entity_id = metadata_desc["entity_id"]
    cnf["service"]["idp"]["endpoints"]["single_sign_on_service"] = []
    cnf["service"]["idp"]["endpoints"]["single_sign_on_service"].append(
        ("%s/%s/%s/sso/redirect" % (config.BASE, mod_conf.PROVIDER, entity_id),
         BINDING_HTTP_REDIRECT))
    cnf["service"]["idp"]["endpoints"]["single_sign_on_service"].append(
        ("%s/%s/%s/sso/post" % (config.BASE, mod_conf.PROVIDER, entity_id), BINDING_HTTP_POST))
    cnf["entityid"] = "{}/{}".format(cnf["entityid"], entity_id)
    return cnf


for filespec in args.config:
    bas, fil = os.path.split(filespec)
    if bas != "":
        sys.path.insert(0, bas)
    if fil.endswith(".py"):
        fil = fil[:-3]

    conf_mod = import_module(fil)

    metadata = []
    for module_config_file in conf_mod.BACKEND_MODULES:
        # Load backend module and get metadata description
        module_conf = import_module(module_config_file)
        provider = list(module_conf.CONFIG.keys())[0]
        module = module_conf.CONFIG[provider]["module"](None,
                                                        module_conf.CONFIG[provider]["config"])
        meta_desc = module.get_metadata_desc()
        for desc in meta_desc:
            metadata.append(_make_metadata(create_config_file(conf_mod, desc, module_conf)))

    create_combined_metadata(metadata)
