"""
SATOSA microservice that uses a configured ordered list of
attributes that may be asserted by a SAML IdP to construct
a primary identifier or key for the user and assert it as
the value for a configured attribute, for example uid.
"""

import copy
import logging
import urllib.parse

import satosa.logging_util as lu
import satosa.micro_services.base
from satosa.response import Redirect


logger = logging.getLogger(__name__)


class PrimaryIdentifier(satosa.micro_services.base.ResponseMicroService):
    """
    Use a configured ordered list of attributes to construct a primary
    identifier for the user and assert it as a particular configured
    attribute. If a primary identifier cannot be found or constructed
    handle the error in a configured way that may be to ignore
    the error or redirect to an external error handling service.
    """
    logprefix = "PRIMARY_IDENTIFIER:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def constructPrimaryIdentifier(self, data, ordered_identifier_candidates):
        """
        Construct and return a primary identifier value from the
        data asserted by the IdP using the ordered list of candidates
        from the configuration.
        """
        logprefix = PrimaryIdentifier.logprefix
        context = self.context

        attributes = data.attributes
        msg = "{} Input attributes {}".format(logprefix, attributes)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        value = None

        for candidate in ordered_identifier_candidates:
            msg = "{} Considering candidate {}".format(logprefix, candidate)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

            # Get the values asserted by the IdP for the configured list of attribute names for this candidate
            # and substitute None if the IdP did not assert any value for a configured attribute.
            values = [ attributes.get(attribute_name, [None])[0] for attribute_name in candidate['attribute_names'] if attribute_name != 'name_id' ]
            msg = "{} Found candidate values {}".format(logprefix, values)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

            # If one of the configured attribute names is name_id then if there is also a configured
            # name_id_format add the value for the NameID of that format if it was asserted by the IdP
            # or else add the value None.
            if 'name_id' in candidate['attribute_names']:
                candidate_nameid_value = None
                candidate_nameid_value = None
                candidate_name_id_format = candidate.get('name_id_format')
                name_id_value = data.subject_id
                name_id_format = data.subject_type
                if (
                    name_id_value
                    and candidate_name_id_format
                    and candidate_name_id_format == name_id_format
                ):
                    msg = "{} IdP asserted NameID {}".format(logprefix, name_id_value)
                    logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                    logger.debug(logline)
                    candidate_nameid_value = name_id_value

                # Only add the NameID value asserted by the IdP if it is not already
                # in the list of values. This is necessary because some non-compliant IdPs
                # have been known, for example, to assert the value of eduPersonPrincipalName
                # in the value for SAML2 persistent NameID as well as asserting
                # eduPersonPrincipalName.
                if candidate_nameid_value not in values:
                    msg = "{} Added NameID {} to candidate values".format(
                        logprefix, candidate_nameid_value
                    )
                    logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                    logger.debug(logline)
                    values.append(candidate_nameid_value)
                else:
                    msg = "{} NameID {} value also asserted as attribute value".format(
                        logprefix, candidate_nameid_value
                    )
                    logline = logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                    logger.warn(logline)

            # If no value was asserted by the IdP for one of the configured list of attribute names
            # for this candidate then go onto the next candidate.
            if None in values:
                msg = "{} Candidate is missing value so skipping".format(logprefix)
                logline = logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                logger.debug(logline)
                continue

            # All values for the configured list of attribute names are present
            # so we can create a primary identifer. Add a scope if configured
            # to do so.
            if 'add_scope' in candidate:
                if candidate['add_scope'] == 'issuer_entityid':
                    scope = data.auth_info.issuer
                else:
                    scope = candidate['add_scope']
                msg = "{} Added scope {} to values".format(logprefix, scope)
                logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                logger.debug(logline)
                values.append(scope)

            # Concatenate all values to create the primary identifier.
            value = ''.join(values)
            break

        return value

    def process(self, context, data):
        logprefix = PrimaryIdentifier.logprefix
        self.context = context

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config

        msg = "{} Using default configuration {}".format(logprefix, config)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        # Find the entityID for the SP that initiated the flow
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError as err:
            msg = "{} Unable to determine the entityID for the SP requester".format(logprefix)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            return super().process(context, data)

        msg = "{} entityID for the SP requester is {}".format(logprefix, spEntityID)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        # Find the entityID for the IdP that issued the assertion
        try:
            idpEntityID = data.auth_info.issuer
        except KeyError as err:
            msg = "{} Unable to determine the entityID for the IdP issuer".format(logprefix)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            return super().process(context, data)

        # Examine our configuration to determine if there is a per-IdP configuration
        if idpEntityID in self.config:
            config = self.config[idpEntityID]
            msg  = "{} For IdP {} using configuration {}".format(logprefix, idpEntityID, config)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

        # Examine our configuration to determine if there is a per-SP configuration.
        # An SP configuration overrides an IdP configuration when there is a conflict.
        if spEntityID in self.config:
            config = self.config[spEntityID]
            msg = "{} For SP {} using configuration {}".format(logprefix, spEntityID, config)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'ordered_identifier_candidates' in config:
                ordered_identifier_candidates = config['ordered_identifier_candidates']
            else:
                ordered_identifier_candidates = self.config['ordered_identifier_candidates']
            if 'primary_identifier' in config:
                primary_identifier = config['primary_identifier']
            elif 'primary_identifier' in self.config:
                primary_identifier = self.config['primary_identifier']
            else:
                primary_identifier = 'uid'
            if 'clear_input_attributes' in config:
                clear_input_attributes = config['clear_input_attributes']
            elif 'clear_input_attributes' in self.config:
                clear_input_attributes = self.config['clear_input_attributes']
            else:
                clear_input_attributes = False
            if 'replace_subject_id' in config:
                replace_subject_id = config['replace_subject_id']
            elif 'replace_subject_id' in self.config:
                replace_subject_id = self.config['replace_subject_id']
            else:
                replace_subject_id = False
            if 'ignore' in config:
                ignore = True
            else:
                ignore = False
            if 'on_error' in config:
                on_error = config['on_error']
            elif 'on_error' in self.config:
                on_error = self.config['on_error']
            else:
                on_error = None

        except KeyError as err:
            msg = "{} Configuration '{}' is missing".format(logprefix, err)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            return super().process(context, data)

        # Ignore this SP entirely if so configured.
        if ignore:
            msg = "{} Ignoring SP {}".format(logprefix, spEntityID)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            return super().process(context, data)

        # Construct the primary identifier.
        msg = "{} Constructing primary identifier".format(logprefix)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        primary_identifier_val = self.constructPrimaryIdentifier(data, ordered_identifier_candidates)

        if not primary_identifier_val:
            msg = "{} No primary identifier found".format(logprefix)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.warn(logline)
            if on_error:
                # Redirect to the configured error handling service with
                # the entityIDs for the target SP and IdP used by the user
                # as query string parameters (URL encoded).
                encodedSpEntityID = urllib.parse.quote_plus(spEntityID)
                encodedIdpEntityID = urllib.parse.quote_plus(data.auth_info.issuer)
                url = "{}?sp={}&idp={}".format(on_error, encodedSpEntityID, encodedIdpEntityID)
                msg = "{} Redirecting to {}".format(logprefix, url)
                logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                logger.info(logline)
                return Redirect(url)

        msg = "{} Found primary identifier: {}".format(logprefix, primary_identifier_val)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.info(logline)

        # Clear input attributes if so configured.
        if clear_input_attributes:
            msg = "{} Clearing values for these input attributes: {}".format(
                logprefix, data.attributes.keys()
            )
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            data.attributes = {}

        if primary_identifier:
            # Set the primary identifier attribute to the value found.
            data.attributes[primary_identifier] = primary_identifier_val
            msg = "{} Setting attribute {} to value {}".format(
                logprefix, primary_identifier, primary_identifier_val
            )
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

        # Replace subject_id with the constructed primary identifier if so configured.
        if replace_subject_id:
            msg = "{} Setting subject_id to value {}".format(
                logprefix, primary_identifier_val
            )
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            data.subject_id = primary_identifier_val

        msg = "{} returning data.attributes {}".format(logprefix, str(data.attributes))
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        return super().process(context, data)
