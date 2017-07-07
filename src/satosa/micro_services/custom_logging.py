"""
SATOSA microservice that outputs log in custom format.
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from base64 import urlsafe_b64encode, urlsafe_b64decode

import json
import copy
import logging

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

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, configClean), context.state)

        # Find the entityID for the SP that initiated the flow and target IdP
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
            idpEntityID = data.auth_info.issuer
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID's for the IdP or SP".format(logprefix), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} entityID for the SP requester is {}".format(logprefix, spEntityID), context.state)
        satosa_logging(logger, logging.ERROR, "{} entityID for the target IdP is {}".format(logprefix, idpEntityID), context.state)

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
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        record = None

        try:
            satosa_logging(logger, logging.DEBUG, "{} Using context {}".format(logprefix, context), context.state)
            satosa_logging(logger, logging.DEBUG, "{} Using data {}".format(logprefix, data.to_dict()), context.state)

            # Open log_target file
            satosa_logging(logger, logging.DEBUG, "{} Opening log_target file {}".format(logprefix, log_target), context.state)
            loghandle = open(log_target,"a")

            # This is where the logging magic happens
            log = {}
            log['router'] = context.state.state_dict['ROUTER']
            log['timestamp'] = data.auth_info.timestamp
            log['sessionid'] = context.state.state_dict['SESSION_ID']
            log['idp'] = idpEntityID
            log['sp'] = spEntityID
            log['attr'] = { key: data.to_dict()['attr'][key] for key in attrs }
            
            print(json.dumps(log), file=loghandle, end="\n")

        except Exception as err:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {0}".format(logprefix, err), None)
            return super().process(context, data)

        else:
            satosa_logging(logger, logging.DEBUG, "{} Closing log_target file".format(logprefix), context.state)

            # Close log_target file
            loghandle.close()

        return super().process(context, data)
