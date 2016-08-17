import os

import click
from saml2.config import Config
from saml2.sigver import security_context

from ..metadata_creation.saml_metadata import create_entity_descriptors
from ..metadata_creation.saml_metadata import create_signed_entities_descriptor
from ..satosa_config import SATOSAConfig


def _get_security_context(key, cert):
    conf = Config()
    conf.key_file = key
    conf.cert_file = cert
    return security_context(conf)


def create_and_write_saml_metadata(proxy_conf, key, cert, dir, valid):
    """
    Generates SAML metadata for the given PROXY_CONF, signed with the given KEY and associated CERT.
    """
    satosa_config = SATOSAConfig(proxy_conf)
    secc = _get_security_context(key, cert)
    frontend_entities, backend_entities = create_entity_descriptors(satosa_config)

    backend_entity_descriptors = [e for sublist in backend_entities.values() for e in sublist]
    frontend_entity_descriptors = [e for sublist in frontend_entities.values() for e in sublist]
    for metadata, filename in zip([create_signed_entities_descriptor(backend_entity_descriptors, secc, valid),
                                   create_signed_entities_descriptor(frontend_entity_descriptors, secc, valid)],
                                  ["backend.xml", "frontend.xml"]):
        path = os.path.join(dir, filename)
        print("Writing metadata to '{}'".format(path))
        with open(path, "w") as f:
            f.write(metadata)


@click.command()
@click.argument("proxy_conf")
@click.argument("key")
@click.argument("cert")
@click.option("--dir",
              type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, readable=False,
                              resolve_path=False),
              default=".", help="Where the output files should be written.")
@click.option("--valid", type=click.INT, default=None, help="Number of hours the metadata should be valid.")
def construct_saml_metadata(proxy_conf, key, cert, dir, valid):
    create_and_write_saml_metadata(proxy_conf, key, cert, dir, valid)
