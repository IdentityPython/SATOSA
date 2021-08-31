import logging

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
        qs_params = context.qs_params

        issuer_is_already_selected = bool(target_entity_id)
        query_string_is_missing = not qs_params
        if issuer_is_already_selected or query_string_is_missing:
            return super().process(context, data)

        hints = (
            entity_id
            for param_name in self.idp_hint_param_names
            for qs_param_name, entity_id in qs_params.items()
            if param_name == qs_param_name
        )
        hint = next(hints, None)

        context.decorate(context.KEY_TARGET_ENTITYID, hint)
        return super().process(context, data)
