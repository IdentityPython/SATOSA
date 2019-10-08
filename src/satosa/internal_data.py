import warnings as _warnings

from satosa.internal import InternalData
from satosa.internal import AuthenticationInformation
from satosa.deprecated import UserIdHashType
from satosa.deprecated import UserIdHasher
from satosa.deprecated import InternalRequest
from satosa.deprecated import InternalResponse


_warnings.warn(
    "internal_data is deprecated; use satosa.internal instead.",
    DeprecationWarning,
)
