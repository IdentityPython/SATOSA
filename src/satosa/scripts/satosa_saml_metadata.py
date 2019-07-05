import os
from functools import partial, reduce
from itertools import starmap
from operator import add

import click
from saml2.config import Config
from saml2.sigver import security_context

from ..metadata_creation.saml_metadata import create_entity_descriptors
from ..metadata_creation.saml_metadata import create_signed_entity_descriptor
from ..satosa_config import SATOSAConfig


def _get_security_context(key, cert):
    conf = Config()
    conf.key_file = key
    conf.cert_file = cert
    return security_context(conf)


def _create_split_entity_descriptors(entities, secc, valid):
    output = []
    for module_name, eds in entities.items():
        for i, ed in enumerate(eds):
            output.append(
                (
                    create_signed_entity_descriptor(ed, secc, valid),
                    "{}_{}.xml".format(module_name, i),
                )
            )

    return output


def _create_merged_entities_descriptors(entities, secc, valid, name):
    output = []
    entity_descriptors = [e for sublist in entities.values() for e in sublist]
    for entity_descr in entity_descriptors:
        output.append(
            (create_signed_entity_descriptor(entity_descr, secc, valid), name)
        )

    return output


def create_saml_metadata(entities, split_option, filename, secc, valid):
    if split_option:
        return _create_split_entity_descriptors(entities, secc, valid)
    else:
        return _create_merged_entities_descriptors(
            entities, secc, valid, filename
        )


def write_saml_metadata(directory, output):
    for metadata, filename in output:
        path = os.path.join(directory, filename)
        print("Writing metadata to '{}'".format(path))
        with open(path, "w") as f:
            f.write(metadata)


def create_and_write_saml_metadata(proxy_conf, key, cert, dir, valid,
                                   split_frontend_metadata=False,
                                   split_backend_metadata=False):
    """
    Generates SAML metadata for the given PROXY_CONF, signed with the given KEY and associated CERT.
    """
    satosa_config = SATOSAConfig(proxy_conf)
    secc = _get_security_context(key, cert)
    frontend_entities, backend_entities = create_entity_descriptors(
        satosa_config
    )

    entities_metadata = reduce(
        add,
        starmap(
            partial(create_saml_metadata, secc=secc, valid=valid),
            (
                (frontend_entities, split_frontend_metadata, "frontend.xml"),
                (backend_entities, split_backend_metadata, "backend.xml"),
            ),
        ),
    )

    write_saml_metadata(dir, entities_metadata)


@click.command()
@click.argument("proxy_conf")
@click.argument("key")
@click.argument("cert")
@click.option("--dir",
              type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, readable=False,
                              resolve_path=False),
              default=".", help="Where the output files should be written.")
@click.option("--valid", type=click.INT, default=None, help="Number of hours the metadata should be valid.")
@click.option("--split-frontend", is_flag=True, type=click.BOOL, default=False,
              help="Create one entity descriptor per file for the frontend metadata")
@click.option("--split-backend", is_flag=True, type=click.BOOL, default=False,
              help="Create one entity descriptor per file for the backend metadata")
def construct_saml_metadata(proxy_conf, key, cert, dir, valid, split_frontend, split_backend):
    create_and_write_saml_metadata(proxy_conf, key, cert, dir, valid, split_frontend, split_backend)
