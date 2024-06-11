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
        self.override_selected_entry = config.get("override_selected_entry") or False
        try:
            self.idp_hint_param_names = config["allowed_params"]
        except KeyError:
            raise SATOSAConfigurationError(
                f"{self.__class__.__name__} No value set for allowed_params configuration option"
            )

    def process(self, context, data):
        """
        This intercepts if idp_hint paramenter is in use
        :param context: request context
        :param data: the internal request
        """
        qs_params = context.qs_params
        query_string_is_missing = not qs_params
        if query_string_is_missing:
            return super().process(context, data)

        target_entity_id = context.get_decoration(context.KEY_TARGET_ENTITYID)
        issuer_is_already_selected = bool(target_entity_id)
        if issuer_is_already_selected and not self.override_selected_entry:
            return super().process(context, data)

        hints = (
            entity_id
            for param_name in self.idp_hint_param_names
            for qs_param_name, entity_id in qs_params.items()
            if param_name == qs_param_name
        )
        hint = next(hints, None)
        if hint:
            context.decorate(context.KEY_TARGET_ENTITYID, hint)

        return super().process(context, data)
