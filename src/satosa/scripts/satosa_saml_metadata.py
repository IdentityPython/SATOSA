import os

import click
from saml2.config import Config
from saml2.sigver import security_context

from ..metadata_creation.saml_metadata import create_entity_descriptors
from ..metadata_creation.saml_metadata import create_entity_descriptor_metadata
from ..metadata_creation.saml_metadata import create_signed_entity_descriptor
from ..satosa_config import SATOSAConfig


def _get_security_context(key, cert):
    conf = Config()
    conf.key_file = key
    conf.cert_file = cert
    return security_context(conf)


def _create_split_entity_descriptors(entities, secc, valid, sign=True):
    output = []
    for module_name, eds in entities.items():
        for i, ed in enumerate(eds):
            ed_str = (
                create_signed_entity_descriptor(ed, secc, valid)
                if sign
                else create_entity_descriptor_metadata(ed, valid)
            )
            output.append((ed_str, "{}_{}.xml".format(module_name, i)))

    return output


def _create_merged_entities_descriptors(entities, secc, valid, name, sign=True):
    output = []
    frontend_entity_descriptors = [e for sublist in entities.values() for e in sublist]
    for frontend in frontend_entity_descriptors:
        ed_str = (
            create_signed_entity_descriptor(frontend, secc, valid)
            if sign
            else create_entity_descriptor_metadata(frontend, valid)
        )
        output.append((ed_str, name))

    return output


def create_and_write_saml_metadata(proxy_conf, key, cert, dir, valid, split_frontend_metadata=False,
                                   split_backend_metadata=False, sign=True):
    """
    Generates SAML metadata for the given PROXY_CONF, signed with the given KEY and associated CERT.
    """
    satosa_config = SATOSAConfig(proxy_conf)

    if sign and (not key or not cert):
        raise ValueError("Key and cert are required when signing")
    secc = _get_security_context(key, cert) if sign else None

    frontend_entities, backend_entities = create_entity_descriptors(satosa_config)

    output = []
    if frontend_entities:
        if split_frontend_metadata:
            output.extend(_create_split_entity_descriptors(frontend_entities, secc, valid, sign))
        else:
            output.extend(_create_merged_entities_descriptors(frontend_entities, secc, valid, "frontend.xml", sign))
    if backend_entities:
        if split_backend_metadata:
            output.extend(_create_split_entity_descriptors(backend_entities, secc, valid, sign))
        else:
            output.extend(_create_merged_entities_descriptors(backend_entities, secc, valid, "backend.xml", sign))

    for metadata, filename in output:
        path = os.path.join(dir, filename)
        print("Writing metadata to '{}'".format(path))
        with open(path, "w") as f:
            f.write(metadata)


@click.command()
@click.argument("proxy_conf")
@click.argument("key", required=False)
@click.argument("cert", required=False)
@click.option("--dir",
              type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, readable=False,
                              resolve_path=False),
              default=".", help="Where the output files should be written.")
@click.option("--valid", type=click.INT, default=None, help="Number of hours the metadata should be valid.")
@click.option("--split-frontend", is_flag=True, type=click.BOOL, default=False,
              help="Create one entity descriptor per file for the frontend metadata")
@click.option("--split-backend", is_flag=True, type=click.BOOL, default=False,
              help="Create one entity descriptor per file for the backend metadata")
@click.option("--sign/--no-sign", is_flag=True, type=click.BOOL, default=True,
              help="Sign the generated metadata")
def construct_saml_metadata(proxy_conf, key, cert, dir, valid, split_frontend, split_backend, sign):
    create_and_write_saml_metadata(proxy_conf, key, cert, dir, valid, split_frontend, split_backend, sign)
