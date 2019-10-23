"""
SATOSA microservice that outputs log in custom format.
"""

import copy
import json
import logging

import satosa.logging_util as lu
from .base import ResponseMicroService


logger = logging.getLogger(__name__)


class CustomLoggingService(ResponseMicroService):
    """
    Use context and data object to create custom log output
    """
    logprefix = "CUSTOM_LOGGING_SERVICE:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def process(self, context, data):
        logprefix = CustomLoggingService.logprefix

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config
        configClean = copy.deepcopy(config)

        msg = "{} Using default configuration {}".format(logprefix, configClean)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        # Find the entityID for the SP that initiated the flow and target IdP
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
            idpEntityID = data.auth_info.issuer
        except KeyError as err:
            msg = "{} Unable to determine the entityID's for the IdP or SP".format(logprefix)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            return super().process(context, data)

        msg = "{} entityID for the SP requester is {}".format(logprefix, spEntityID)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        msg = "{} entityID for the target IdP is {}".format(logprefix, idpEntityID)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.error(logline)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'log_target' in config:
                log_target = config['log_target']
            else:
                log_target = self.config['log_target']

            if 'attrs' in config:
                attrs = config['attrs']
            else:
                attrs = self.config['attrs']


        except KeyError as err:
            msg = "{} Configuration '{}' is missing".format(logprefix, err)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            return super().process(context, data)

        record = None

        try:
            msg = "{} Using context {}".format(logprefix, context)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            msg = "{} Using data {}".format(logprefix, data.to_dict())
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

            # Open log_target file
            msg = "{} Opening log_target file {}".format(logprefix, log_target)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            loghandle = open(log_target,"a")

            # This is where the logging magic happens
            log = {}
            log['router'] = context.state.state_dict['ROUTER']
            log['timestamp'] = data.auth_info.timestamp
            log['sessionid'] = context.state.state_dict['SESSION_ID']
            log['idp'] = idpEntityID
            log['sp'] = spEntityID
            log['attr'] = { key: data.to_dict()['attr'].get(key) for key in attrs }

            print(json.dumps(log), file=loghandle, end="\n")

        except Exception as err:
            msg = "{} Caught exception: {}".format(logprefix, err)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(None), message=msg)
            logger.error(logline)
            return super().process(context, data)

        else:
            msg = "{} Closing log_target file".format(logprefix)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

            # Close log_target file
            loghandle.close()

        return super().process(context, data)
