import os

import click
from saml2.config import Config
from saml2.sigver import security_context

from satosa.metadata_creation.saml_metadata import create_signed_entities_descriptor
from ..metadata_creation.saml_metadata import create_entity_descriptors
from ..satosa_config import SATOSAConfig


def _get_security_context(key, cert):
    conf = Config()
    conf.key_file = key
    conf.cert_file = cert
    return security_context(conf)


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
    """
    Generates SAML metadata for the given PROXY_CONF, signed with the given KEY and associated CERT.
    """
    satosa_config = SATOSAConfig(proxy_conf)
    secc = _get_security_context(key, cert)
    frontend_entities, backend_entities = create_entity_descriptors(satosa_config)

    for metadata in [create_signed_entities_descriptor(backend_entities, secc, valid),
                     create_signed_entities_descriptor(frontend_entities, secc, valid)]:
        for plugin_name, data in metadata.items():
            path = os.path.join(dir, plugin_name)
            print("Writing plugin '%s' metadata to '%s'" % (plugin_name, path))
            with open(path, "w") as f:
                f.write(data)
