import logging

import satosa.logging_util as lu

from .base import ResponseMicroService

logger = logging.getLogger(__name__)


class AttributePolicy(ResponseMicroService):
    """
    Module to filter Attributes by a given Policy.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_policy = config["attribute_policy"]

    def process(self, context, data):
        state = context.state
        session_id = lu.get_session_id(state)

        msg = "Incoming data.attributes {}".format(data.attributes)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        policy = self.attribute_policy.get(data.requester, {})
        if "allowed" in policy:
            for key in (data.attributes.keys() - set(policy["allowed"])):
                del data.attributes[key]

        msg = "Returning data.attributes {}".format(data.attributes)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)
        return super().process(context, data)
