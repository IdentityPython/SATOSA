from satosa.context import Context
from satosa.internal import InternalData

from .base import RequestMicroService
from ..exception import SATOSAError


class DiscoToTargetIssuerError(SATOSAError):
    """SATOSA exception raised by CustomRouting rules"""


class DiscoToTargetIssuer(RequestMicroService):
    def __init__(self, config:dict, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.disco_endpoints = config['disco_endpoints']
        if not isinstance(self.disco_endpoints, list) or not self.disco_endpoints:
            raise DiscoToTargetIssuerError('disco_endpoints must be a list of str')

    def process(self, context:Context, data:InternalData):
        context.state[self.name] = {
            'target_frontend': context.target_frontend,
            'internal_data': data.to_dict(),
        }
        return super().process(context, data)

    def register_endpoints(self):
        """
        URL mapping of additional endpoints this micro service needs to register for callbacks.

        Example of a mapping from the url path '/callback' to the callback() method of a micro service:
            reg_endp = [
                ('^/callback1$', self.callback),
            ]

        :rtype List[Tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, Callable[[satosa.context.Context], satosa.response.Response]), ...]
        """

        return [
            (path , self._handle_disco_response)
            for path in self.disco_endpoints
        ]

    def _handle_disco_response(self, context:Context):
        target_issuer = context.request.get('entityID')
        if not target_issuer:
            raise DiscoToTargetIssuerError('no valid entity_id in the disco response')

        target_frontend = context.state.get(self.name, {}).get('target_frontend')
        data_serialized = context.state.get(self.name, {}).get('internal_data', {})
        data = InternalData.from_dict(data_serialized)

        context.target_frontend = target_frontend
        context.decorate(Context.KEY_TARGET_ENTITYID, target_issuer)
        return super().process(context, data)
