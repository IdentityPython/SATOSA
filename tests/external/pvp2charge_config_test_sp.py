import os
import uuid
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.cert import OpenSSLWrapper
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT
from saml2.entity_category.at_egov_pvp2 import PVP2, PVP2CHARGE

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/usr/bin", "/opt/local/bin", "/usr/local/bin"])
else:
    #Test to run xmlsec1!
    xmlsec_path = '/usr/bin/xmlsec1'

BASEDIR = os.path.abspath(os.path.dirname(__file__))

#Where the SP is deployed (external interface, i.e. the front-facig proxy).
BASE= "http://test.sp.se:8900"

# Method that generates the cert to be added to SPCertEncType in the authn request.
# You can change this after your needs.
def generate_cert():
    pass

CONFIG = {
    "entityid": "http://test.sp.se/pvp2charge_sp.xml",
    "description": "PEFIM test SP",
    "entity_category": [PVP2CHARGE],
    #Here you configure the method to be used for generating certificates.
    "generate_cert_func": generate_cert,
    "service": {
        "sp": {
            #Will sign the request!
            "authn_requests_signed": "true",
            #Demands that the assertion is signed.
            #We have not yet solved the issue to both sign and encrypt the assertion.
            #Sign the complete response instead.
            "want_assertions_signed": "false",
            #Demands that the response is signed!
            "want_response_signed": "true",
            #Allows the assertion/response is not ment for this sp.
            #The assertion is created for the proxy, so you must allow that the assertion is not designated for this SP.
            "allow_unsolicited": "true",
            "name": "LocalTestSP",
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/acs/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/acs/post" % BASE, BINDING_HTTP_POST)
                ],
                "single_logout_service": [(BASE + "/slo", BINDING_HTTP_REDIRECT)],
                "discovery_response": [("%s/disco" % BASE, BINDING_DISCO)]
            },
            "required_attributes": ["pvp-version", "pvp-principal-name", ],
            "optional_attributes": ["pvp-givenname", "pvp-birthdate", "pvp-userid", ],
            "name_id_format": [NAMEID_FORMAT_PERSISTENT],
        }
    },
    "debug": 1,
    #You must change this to your files!
    "key_file": BASEDIR + "/../keys/mykey.pem",
    "cert_file": BASEDIR + "/../keys/mycert.pem",
    #"attribute_map_dir": "./attributemaps",
    "metadata": {
        "local": [BASEDIR + "/../proxy_conf_local.xml"],
    },
    # -- below used by make_metadata --
    "organization": {
        "name": "KuK Servus",
        "display_name": [("KuK Servus", "de"), ("KuK Servus", "en")],
        "url": "http://test.sp.se",
    },
    "contact_person": [{"contact_type": "technical", 
                        "given_name": "Rainer", "sur_name": "Hoerbe",
                        "telephone_number": "+43 1 100 0000",
                        "email_address": ["rh_testfed_pv_at@mail.hoerbe.at",],}, 
                       {"contact_type": "support",
                        "given_name": "Support",
                        "email_address": "support@example.com"},
                       ],
    "xmlsec_binary": xmlsec_path,
    "name_form": NAME_FORMAT_URI,
    "logger": {
        "rotating": {
            "filename": "sp.log",
            "maxBytes": 1000000,
            "backupCount": 1,
        },
        "loglevel": "debug",
    }
}
