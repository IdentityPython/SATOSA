import os
import re

from yaml import SafeLoader as _safe_loader
from yaml import YAMLError
from yaml import safe_load as load


def _constructor_env_variables(loader, node):
    """
    Extracts the environment variable from the node's value.
    :param yaml.Loader loader: the yaml loader
    :param node: the current node in the yaml
    :return: value of the environment variable
    """
    raw_value = loader.construct_scalar(node)
    new_value = os.environ.get(raw_value)
    if new_value is None:
        msg = "Cannot construct value from {node}: {value}".format(
            node=node, value=new_value
        )
        raise YAMLError(msg)
    return new_value


def _constructor_envfile_variables(loader, node):
    """
    Extracts the environment variable from the node's value.
    :param yaml.Loader loader: the yaml loader
    :param node: the current node in the yaml
    :return: value read from file pointed to by environment variable
    """
    raw_value = loader.construct_scalar(node)
    filepath = os.environ.get(raw_value)
    try:
        with open(filepath, "r") as fd:
            new_value = fd.read()
    except (TypeError, IOError) as e:
        msg = "Cannot construct value from {node}: {path}".format(
            node=node, path=filepath
        )
        raise YAMLError(msg) from e
    else:
        return new_value


TAG_ENV = "!ENV"
TAG_ENVFILE = "!ENVFILE"


_safe_loader.add_constructor(TAG_ENV, _constructor_env_variables)
_safe_loader.add_constructor(TAG_ENVFILE, _constructor_envfile_variables)
