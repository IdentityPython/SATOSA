import logging
from base64 import urlsafe_b64encode

from .base import RequestMicroService
from ..exception import SATOSAConfigurationError
from ..exception import SATOSAError

logger = logging.getLogger(__name__)


class DecideBackendByRequester(RequestMicroService):
    """
    Select which backend should be used based on who the requester is.
    """

    def __init__(self, config, *args, **kwargs):
        """
        Constructor.
        :param config: mapping from requester identifier to
        backend module name under the key 'requester_mapping'
        :type config: Dict[str, Dict[str, str]]
        """
        super().__init__(*args, **kwargs)
        self.requester_mapping = config['requester_mapping']

    def process(self, context, data):
        """
        Will modify the context.target_backend attribute based on the requester identifier.
        :param context: request context
        :param data: the internal request
        """
        context.target_backend = self.requester_mapping[data.requester]
        return super().process(context, data)


class DecideIfRequesterIsAllowed(RequestMicroService):
    """
    Decide whether a requester is allowed to send an authentication request to the target entity.

    This micro service currently only works with `SAMLMirrorFrontend`.
    """
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for target_entity, rules in config["rules"].items():
            conflicting_rules = set(rules.get("deny", [])).intersection(rules.get("allow", []))
            if conflicting_rules:
                raise SATOSAConfigurationError("Conflicting requester rules for DecideIfRequesterIsAllowed,"
                                               "{} is both denied and allowed".format(conflicting_rules))

        # target entity id is base64 url encoded to make it usable in URLs,
        # so we convert the rules the use those encoded entity id's instead
        self.rules = {self._b64_url(k): v for k, v in config["rules"].items()}

    def _b64_url(self, data):
        return urlsafe_b64encode(data.encode("utf-8")).decode("utf-8")

    def process(self, context, data):
        try:
            target_entity_id = context.internal_data["mirror.target_entity_id"]
        except KeyError:
            logger.error("DecideIfRequesterIsAllowed can only be used with SAMLMirrorFrontend")
            raise SATOSAError("DecideIfRequesterIsAllowed can only be used with SAMLMirrorFrontend")

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

        logging.debug("Requester '%s' is not allowed by target entity '%s' due to no deny all rule in '%s'",
                      data.requester, target_entity_id, deny_rules)
        raise SATOSAError("Requester is not allowed by target provider")
