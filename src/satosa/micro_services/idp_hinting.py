import logging
from urllib.parse import parse_qs

from .base import RequestMicroService
from ..exception import SATOSAConfigurationError
from ..exception import SATOSAError


logger = logging.getLogger(__name__)


class IdpHintingError(SATOSAError):
    """
    SATOSA exception raised by IdpHinting microservice
    """
    pass


class IdpHinting(RequestMicroService):
    """
    Detect if an idp hinting feature have been requested
    """

    def __init__(self, config, *args, **kwargs):
        """
        Constructor.
        :param config: microservice configuration
        :type config: Dict[str, Dict[str, str]]
        """
        super().__init__(*args, **kwargs)
        try:
            self.idp_hint_param_names = config['allowed_params']
        except KeyError:
            raise SATOSAConfigurationError(
                f"{self.__class__.__name__} can't find allowed_params"
            )

    def process(self, context, data):
        """
        This intercepts if idp_hint paramenter is in use
        :param context: request context
        :param data: the internal request
        """
        target_entity_id = context.get_decoration(context.KEY_TARGET_ENTITYID)
        qs_raw = context._http_headers['QUERY_STRING']
        if target_entity_id or not qs_raw:
            return super().process(context, data)

        qs = parse_qs(qs_raw)
        hints = (
            entity_id
            for param in self.idp_hint_param_names
            for entity_id in qs.get(param, [None])
            if entity_id
        )
        hint = next(hints, None)

        context.decorate(context.KEY_TARGET_ENTITYID, hint)
        return super().process(context, data)
