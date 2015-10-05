"""
Micro service for SATOSA
"""
__author__ = 'mathiashedstrom'


class MicroService(object):
    """
    Abstract class for micro services
    """

    def __init__(self):
        self._child_service = None

    def process_service_queue(self, context, data):
        """
        Processes the whole queue of micro services

        :type context: satosa.context.Context
        :type data: satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest
        :rtype: satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest

        :param context: The current context
        :param data: Data to be modified
        :return: Modified data
        """
        if self._child_service:
            data = self._child_service.process_service_queue(context, data)
        return self.process(context, data)

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


def buld_micro_service_queue(services):
    """
    Builds a micro service queue from a list of micro services

    :type services: list[satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest]
    :rtype: satosa.internal_data.InternalResponse | satosa.internal_data.InternalRequest

    :param services: A list of micro services
    :return: A micro service queue
    """
    prev_service = None
    for service in services:
        service._child_service = prev_service
        prev_service = service
    return prev_service
