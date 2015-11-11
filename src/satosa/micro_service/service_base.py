"""
Micro service for SATOSA
"""
import logging
from satosa.exception import AuthenticationError

__author__ = 'mathiashedstrom'

LOGGER = logging.getLogger(__name__)

class MicroService(object):
    """
    Abstract class for micro services
    """

    def __init__(self):
        self._child_service = None

    def process_service_queue(self, context, data, state):
        """
        Processes the whole queue of micro services

        :type context: satosa.context.Context
        :type data: satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest
        :type state: satosa.state.State
        :rtype: satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest

        :param context: The current context
        :param data: Data to be modified
        :param state: The current state. Only used if there is a error
        :return: Modified data
        """
        if self._child_service:
            data = self._child_service.process_service_queue(context, data, state)
        try:
            return self.process(context, data)
        except Exception as error:
            LOGGER.exception("Micro service error: %s" % error)
            raise AuthenticationError(state, "Micro service error")

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
    pass


class RequestMicroService(MicroService):
    """
    Base class for request micro services
    """
    pass


def build_micro_service_queue(services):
    """
    Builds a micro service queue from a list of micro services

    :type services: list[satosa.micro_service.service_base.ResponseMicroService| satosa.micro_service.service_base.RequestMicroService]
    :rtype: satosa.micro_service.service_base.ResponseMicroService| satosa.micro_service.service_base.RequestMicroService

    :param services: A list of micro services
    :return: A micro service queue
    """
    prev_service = None
    for service in services:
        service._child_service = prev_service
        prev_service = service
    return prev_service
