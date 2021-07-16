import logging
from base64 import urlsafe_b64encode

from satosa.context import Context
from satosa.internal import InternalData

from .base import RequestMicroService
from ..exception import SATOSAConfigurationError
from ..exception import SATOSAError


logger = logging.getLogger(__name__)


class CustomRoutingError(SATOSAError):
    """SATOSA exception raised by CustomRouting rules"""
    pass


class DecideBackendByTargetIssuer(RequestMicroService):
    """
    Select target backend based on the target issuer.
    """

    def __init__(self, config:dict, *args, **kwargs):
        """
        Constructor.

        :param config: microservice configuration loaded from yaml file
        :type config: Dict[str, Dict[str, str]]
        """
        super().__init__(*args, **kwargs)

        self.target_mapping = config['target_mapping']
        self.default_backend = config['default_backend']

    def process(self, context:Context, data:InternalData):
        """Set context.target_backend based on the target issuer"""

        target_issuer = context.get_decoration(Context.KEY_TARGET_ENTITYID)
        if not target_issuer:
            logger.info('skipping backend decision because no target_issuer was found')
            return super().process(context, data)

        target_backend = (
            self.target_mapping.get(target_issuer)
            or self.default_backend
        )

        report = {
            'msg': 'decided target backend by target issuer',
            'target_issuer': target_issuer,
            'target_backend': target_backend,
        }
        logger.info(report)

        context.target_backend = target_backend
        return super().process(context, data)


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

    This micro service currently only works when a target entityid is set.
    Currently, a target entityid is set only when the `SAMLMirrorFrontend` is
    used.
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
        target_entity_id = context.get_decoration(Context.KEY_TARGET_ENTITYID)
        if None is target_entity_id:
            msg = "{name} can only be used when a target entityid is set".format(
                name=self.__class__.__name__
            )
            logger.error(msg)
            raise SATOSAError(msg)

        target_specific_rules = self.rules.get(target_entity_id)
        # default to allowing everything if there are no specific rules
        if not target_specific_rules:
            logger.debug("Requester '{}' allowed by default to target entity '{}' due to no entity specific rules".format(
                data.requester, target_entity_id
            ))
            return super().process(context, data)

        # deny rules takes precedence
        deny_rules = target_specific_rules.get("deny", [])
        if data.requester in deny_rules:
            logger.debug("Requester '{}' is not allowed by target entity '{}' due to deny rules '{}'".format(
                data.requester, target_entity_id, deny_rules
            ))
            raise SATOSAError("Requester is not allowed by target provider")

        allow_rules = target_specific_rules.get("allow", [])
        allow_all = "*" in allow_rules
        if data.requester in allow_rules or allow_all:
            logger.debug("Requester '{}' allowed by target entity '{}' due to allow rules '{}".format(
                data.requester, target_entity_id, allow_rules
            ))
            return super().process(context, data)

        logger.debug("Requester '{}' is not allowed by target entity '{}' due to final deny all rule in '{}'".format(
            data.requester, target_entity_id, deny_rules
        ))
        raise SATOSAError("Requester is not allowed by target provider")
