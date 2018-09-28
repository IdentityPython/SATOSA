import warnings as _warnings
from enum import Enum

from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED


_warnings.simplefilter("default")


class UserIdHashType(Enum):
    """
    All different user id hash types
    """

    transient = 1
    persistent = 2
    pairwise = 3
    public = 4
    emailaddress = 5
    unspecified = 6

    def __getattr__(self, name):
        msg = "UserIdHashType is deprecated and will be removed."
        _warnings.warn(msg, DeprecationWarning)
        return self.__getattribute__(name)

    @classmethod
    def from_string(cls, str):
        msg = "UserIdHashType is deprecated and will be removed."
        _warnings.warn(msg, DeprecationWarning)
        try:
            return getattr(cls, str)
        except AttributeError:
            raise ValueError("Unknown hash type '{}'".format(str))


def saml_name_id_format_to_hash_type(name_format):
    """
    Translate pySAML2 name format to satosa format

    :type name_format: str
    :rtype: satosa.internal_data.UserIdHashType
    :param name_format: SAML2 name format
    :return: satosa format
    """
    msg = "saml_name_id_format_to_hash_type is deprecated and will be removed."
    _warnings.warn(msg, DeprecationWarning)

    name_id_format_to_hash_type = {
        NAMEID_FORMAT_TRANSIENT: UserIdHashType.transient,
        NAMEID_FORMAT_PERSISTENT: UserIdHashType.persistent,
        NAMEID_FORMAT_EMAILADDRESS: UserIdHashType.emailaddress,
        NAMEID_FORMAT_UNSPECIFIED: UserIdHashType.unspecified,
    }

    return name_id_format_to_hash_type.get(
        name_format, UserIdHashType.transient
    )


def hash_type_to_saml_name_id_format(hash_type):
    """
    Translate satosa format to pySAML2 name format

    :type hash_type: satosa.internal_data.UserIdHashType
    :rtype: str
    :param hash_type: satosa format
    :return: pySAML2 name format
    """
    msg = "hash_type_to_saml_name_id_format is deprecated and will be removed."
    _warnings.warn(msg, DeprecationWarning)

    hash_type_to_name_id_format = {
        UserIdHashType.transient: NAMEID_FORMAT_TRANSIENT,
        UserIdHashType.persistent: NAMEID_FORMAT_PERSISTENT,
        UserIdHashType.emailaddress: NAMEID_FORMAT_EMAILADDRESS,
        UserIdHashType.unspecified: NAMEID_FORMAT_UNSPECIFIED,
    }

    return hash_type_to_name_id_format.get(hash_type, NAMEID_FORMAT_PERSISTENT)


def oidc_subject_type_to_hash_type(subject_type):
    msg = "oidc_subject_type_to_hash_type is deprecated and will be removed."
    _warnings.warn(msg, DeprecationWarning)

    if subject_type == "public":
        return UserIdHashType.public

    return UserIdHashType.pairwise
