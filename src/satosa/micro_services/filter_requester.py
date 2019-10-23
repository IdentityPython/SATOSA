import logging
from base64 import urlsafe_b64encode

from satosa.context import Context

from .base import RequestMicroService
from ..exception import SATOSAConfigurationError
from ..exception import SATOSAError

logger = logging.getLogger(__name__)


class FilterRequester(RequestMicroService):
    """
    Decide whether a requester is allowed to send an authentication request to the target entity based on a whitelist
    """
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for target_entity, rules in config["rules"].items():
            conflicting_rules = set(rules.get("deny", [])).intersection(rules.get("allow", []))
            if conflicting_rules:
                raise SATOSAConfigurationError("Conflicting requester rules for FilterRequester,"
                                               "{} is both denied and allowed".format(conflicting_rules))

        self.rules = {self._b64_url(k): v for k, v in config["rules"].items()}
        self.conf_target_entity_id = config.get('target_entity_id', None)

    def process(self, context, data):
        target_entity_id = context.get_decoration(Context.KEY_TARGET_ENTITYID) or self.conf_target_entity_id
        if None is target_entity_id:
            msg_tpl = "{name} can only be used when a target entityid is set"
            msg = msg_tpl.format(name=self.__class__.__name__)
            logger.error(msg)
            raise SATOSAError(msg)

        target_specific_rules = self.rules.get(target_entity_id)
        # default to allowing everything if there are no specific rules
        if not target_specific_rules:
            logging.debug("Requester '%s' allowed by default to target entity '%s' due to no entity specific rules",
                          data.requester, target_entity_id)
            return super().process(context, data)

        # deny rules takes precedence
        deny_rules = target_specific_rules.get("deny", [])
        if data.requester in deny_rules:
            logging.debug("Requester '%s' is not allowed by target entity '%s' due to deny rules '%s'", data.requester,
                          target_entity_id, deny_rules)
            raise SATOSAError("Requester is not allowed by target provider")

        allow_rules = target_specific_rules.get("allow", [])
        allow_all = "*" in allow_rules
        if data.requester in allow_rules or allow_all:
            logging.debug("Requester '%s' allowed by target entity '%s' due to allow rules '%s",
                          data.requester, target_entity_id, allow_rules)
            return super().process(context, data)

        logger.debug("Requester '%s' is not allowed by target entity '%s' due to final deny all rule in '%s'",
                      data.requester, target_entity_id, deny_rules)
        raise SATOSAError("Requester is not allowed by target provider")
