"""
Micro service for SATOSA
"""
import logging
from typing import Any, Callable, Optional, Union
import satosa.context
import satosa.internal
import satosa.response

logger = logging.getLogger(__name__)


ProcessReturnType = Union[satosa.internal.InternalData, satosa.response.Response]
MicroServiceCallSignature = Callable[[satosa.context.Context, satosa.internal.InternalData], ProcessReturnType]
CallbackReturnType = satosa.response.Response
CallbackCallSignature = Callable[[satosa.context.Context, Any], CallbackReturnType]


class MicroService(object):
    """
    Abstract class for micro services
    """

    def __init__(self, name: str, base_url: str, **kwargs: Any):
        self.name = name
        self.base_url = base_url
        self.next: Optional[MicroServiceCallSignature] = None

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData) -> ProcessReturnType:
        """
        This is where the micro service should modify the request / response.
        Subclasses must call this method (or in another way make sure the `next`
        callable is called).

        :param context: The current context
        :param data: Data to be modified
        :return: Modified data
        """
        return self.next(context, data)

    def register_endpoints(self) -> list[tuple[str, CallbackCallSignature]]:
        """
        URL mapping of additional endpoints this micro service needs to register for callbacks.

        Example of a mapping from the url path '/callback' to the callback() method of a micro service:
            reg_endp = [
                ("^/callback1$", self.callback),
            ]

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, CallbackCallSignature), ...]
        """
        return []


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
