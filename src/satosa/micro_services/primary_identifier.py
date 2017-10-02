"""
SATOSA microservice that uses a configured ordered list of
attributes that may be asserted by a SAML IdP to construct
a primary identifier or key for the user and assert it as
the value for a configured attribute, for example uid. 
"""

import satosa.micro_services.base
from satosa.logging_util import satosa_logging
from satosa.response import Redirect

import copy
import logging
import urllib.parse

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
        satosa_logging(logger, logging.DEBUG, "{} Input attributes {}".format(logprefix, attributes), context.state)

        value = None

        for candidate in ordered_identifier_candidates:
            satosa_logging(logger, logging.DEBUG, "{} Considering candidate {}".format(logprefix, candidate), context.state)

            # Get the values asserted by the IdP for the configured list of attribute names for this candidate
            # and substitute None if the IdP did not assert any value for a configured attribute.
            values = [ attributes.get(attribute_name, [None])[0] for attribute_name in candidate['attribute_names'] ]
            satosa_logging(logger, logging.DEBUG, "{} Found candidate values {}".format(logprefix, values), context.state)

            # If one of the configured attribute names is name_id then if there is also a configured
            # name_id_format add the value for the NameID of that format if it was asserted by the IdP
            # or else add the value None.
            if 'name_id' in candidate['attribute_names']:
                nameid_value = None
                if 'name_id' in data.to_dict():
                    name_id = data.to_dict()['name_id']
                    satosa_logging(logger, logging.DEBUG, "{} IdP asserted NameID {}".format(logprefix, name_id), context.state)
                    if 'name_id_format' in candidate:
                        if candidate['name_id_format'] in name_id:
                            nameid_value = name_id[candidate['name_id_format']]

                # Only add the NameID value asserted by the IdP if it is not already 
                # in the list of values. This is necessary because some non-compliant IdPs
                # have been known, for example, to assert the value of eduPersonPrincipalName 
                # in the value for SAML2 persistent NameID as well as asserting
                # eduPersonPrincipalName.
                if nameid_value not in values:
                    satosa_logging(logger, logging.DEBUG, "{} Added NameID {} to candidate values".format(logprefix, nameid_value), context.state)
                    values.append(nameid_value)
                else:
                    satosa_logging(logger, logging.WARN, "{} NameID {} value also asserted as attribute value".format(logprefix, nameid_value), context.state)

            # If no value was asserted by the IdP for one of the configured list of attribute names
            # for this candidate then go onto the next candidate.
            if None in values:
                satosa_logging(logger, logging.DEBUG, "{} Candidate is missing value so skipping".format(logprefix), context.state)
                continue

            # All values for the configured list of attribute names are present
            # so we can create a primary identifer. Add a scope if configured
            # to do so.
            if 'add_scope' in candidate:
                if candidate['add_scope'] == 'issuer_entityid':
                    scope = data.to_dict()['auth_info']['issuer']
                else:
                    scope = candidate['add_scope']
                satosa_logging(logger, logging.DEBUG, "{} Added scope {} to values".format(logprefix, scope), context.state)
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

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, config), context.state)

        # Find the entityID for the SP that initiated the flow
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID for the SP requester".format(logprefix), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} entityID for the SP requester is {}".format(logprefix, spEntityID), context.state)

        # Find the entityID for the IdP that issued the assertion
        try:
            idpEntityID = data.to_dict()['auth_info']['issuer']
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID for the IdP issuer".format(logprefix), context.state)
            return super().process(context, data)

        # Examine our configuration to determine if there is a per-IdP configuration
        if idpEntityID in self.config:
            config = self.config[idpEntityID]
            satosa_logging(logger, logging.DEBUG, "{} For IdP {} using configuration {}".format(logprefix, idpEntityID, config), context.state)

        # Examine our configuration to determine if there is a per-SP configuration.
        # An SP configuration overrides an IdP configuration when there is a conflict.
        if spEntityID in self.config:
            config = self.config[spEntityID]
            satosa_logging(logger, logging.DEBUG, "{} For SP {} using configuration {}".format(logprefix, spEntityID, config), context.state)
        
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
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        # Ignore this SP entirely if so configured.
        if ignore:
            satosa_logging(logger, logging.INFO, "{} Ignoring SP {}".format(logprefix, spEntityID), context.state)
            return super().process(context, data)

        # Construct the primary identifier.
        satosa_logging(logger, logging.DEBUG, "{} Constructing primary identifier".format(logprefix), context.state)
        primary_identifier_val = self.constructPrimaryIdentifier(data, ordered_identifier_candidates)

        if not primary_identifier_val:
            satosa_logging(logger, logging.WARN, "{} No primary identifier found".format(logprefix), context.state)
            if on_error:
                # Redirect to the configured error handling service with 
                # the entityIDs for the target SP and IdP used by the user
                # as query string parameters (URL encoded).
                encodedSpEntityID = urllib.parse.quote_plus(spEntityID)
                encodedIdpEntityID = urllib.parse.quote_plus(data.to_dict()['auth_info']['issuer'])
                url = "{}?sp={}&idp={}".format(on_error, encodedSpEntityID, encodedIdpEntityID)
                satosa_logging(logger, logging.INFO, "{} Redirecting to {}".format(logprefix, url), context.state)
                return Redirect(url)

        satosa_logging(logger, logging.INFO, "{} Found primary identifier: {}".format(logprefix, primary_identifier_val), context.state)

        # Clear input attributes if so configured.
        if clear_input_attributes:
            satosa_logging(logger, logging.DEBUG, "{} Clearing values for these input attributes: {}".format(logprefix, data.attributes), context.state)
            data.attributes = {}

        # Set the primary identifier attribute to the value found.
        data.attributes[primary_identifier] = primary_identifier_val
        satosa_logging(logger, logging.DEBUG, "{} Setting attribute {} to value {}".format(logprefix, primary_identifier, primary_identifier_val), context.state)

        satosa_logging(logger, logging.DEBUG, "{} returning data.attributes {}".format(logprefix, str(data.attributes)), context.state)
        return super().process(context, data)
