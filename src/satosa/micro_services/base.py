"""
Micro service for SATOSA
"""
import logging

from ..exception import SATOSAAuthenticationError
from ..logging_util import satosa_logging

logger = logging.getLogger(__name__)


class MicroService(object):
    """
    Abstract class for micro services
    """

    def process(self, context, data):
        """
        This is where the micro service should modify the request / response

        :type context: satosa.context.Context
        :type data: satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest
        :rtype: satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest

        :param context: The current context
        :param data: Data to be modified
        :return: Modified data
        """
        raise NotImplementedError


class ResponseMicroService(MicroService):
    """
    Base class for response micro services
    """

    def __init__(self, **kwargs):
        """
        Constructor.

        Subclasses MUST also accept keyword arguments.
        :param kwargs:
            internal_attributes: attribute mapping between internal and external attribute names
            config: the microservice plugin configuration, defined under the 'config' key in the config file
        """
        super().__init__()

    def process(self, context, data):
        """
        @see MicroService#process
        :type context: satosa.context.Context
        :type data: satosa.internal_data.InternalResponse
        :rtype: satosa.internal_data.InternalResponse
        """
        raise NotImplementedError


class RequestMicroService(MicroService):
    """
    Base class for request micro services
    """

    def __init__(self, **kwargs):
        """
        Constructor.

        Subclasses MUST also accept keyword arguments.
        :param kwargs:
            internal_attributes: attribute mapping between internal and external attribute names
            config: the microservice plugin configuration, defined under the 'config' key in the config file
        """
        super().__init__()

    def process(self, context, data):
        """
        @see MicroService#process
        :type context: satosa.context.Context
        :type data: satosa.internal_data.InternalRequest
        :rtype: satosa.internal_data.InternalRequest
        """
        raise NotImplementedError


def process_microservice_queue(service_queue, context, data):
    for service in service_queue:
        try:
            data = service.process(context, data)
        except Exception as e:
            satosa_logging(logger, logging.DEBUG, "Micro service error in {}: {}".format(type(service).__name__,
                                                                                         str(e)),
                           context.state)
            raise SATOSAAuthenticationError(context.state, "Micro service error") from e

    return data
