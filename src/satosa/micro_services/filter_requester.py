import logging
from typing import Tuple

from satosa.context import Context
from satosa.exception import SATOSAConfigurationError, SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import RequestMicroService

logger = logging.getLogger(__name__)


class FilterRequester(RequestMicroService):
    """
    Decide whether a requester is allowed to send an authentication request to the target entity based on a whitelist
    """
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        errmsg = "FilterRequester: config must contain a key 'allow' with a non-empty list of entityIDs."
        try:
            self.rules = config["allow"]
        except KeyError:
            logging.error(errmsg)
            raise SATOSAConfigurationError(errmsg)
        if self.rules is None:
            logging.error(errmsg)
            raise SATOSAConfigurationError(errmsg)

    def process(self, context: Context, internal_request: InternalData) -> Tuple[Context, InternalData]:
        if internal_request.requester not in self.rules and '*' not in self.rules:
            errmsg = "Requester '%s' is not allowed in filter_requester configuration" % internal_request.requester
            raise SATOSAError(errmsg)
        return super().process(context, internal_request)
