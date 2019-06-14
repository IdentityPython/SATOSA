"""
SATOSA microservice that uses an identifier asserted by
the home organization SAML IdP as a key to search an LDAP
directory for a record and then consume attributes from
the record and assert them to the receiving SP.
"""

from satosa.micro_services.base import ResponseMicroService
from satosa.logging_util import satosa_logging
from satosa.response import Redirect

import logging
import ldap3
import urllib

from ldap3.core.exceptions import LDAPException

from . ldap_attribute_store import (LdapAttributeStore,
                                    LdapAttributeStoreError)

logger = logging.getLogger(__name__)

class LdapAttributeStoreNoPool(LdapAttributeStore):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in LDAP and obtain attributes
    to assert about the user to the frontend receiving service.
    """

    def _ldap_connection_factory(self, config):
        """
        Use the input configuration to instantiate and return
        a ldap3 Connection object.
        """
        ldap_url = config['ldap_url']
        bind_dn = config['bind_dn']
        bind_password = config['bind_password']

        if not ldap_url:
            raise LdapAttributeStoreError("ldap_url is not configured")
        if not bind_dn:
            raise LdapAttributeStoreError("bind_dn is not configured")
        if not bind_password:
            raise LdapAttributeStoreError("bind_password is not configured")

        server = ldap3.Server(config['ldap_url'])

        satosa_logging(logger, logging.DEBUG, "Creating a new LDAP connection", None)
        satosa_logging(logger, logging.DEBUG, "Using LDAP URL {}".format(ldap_url), None)
        satosa_logging(logger, logging.DEBUG, "Using bind DN {}".format(bind_dn), None)

        try:
            connection = ldap3.Connection(
                            server,
                            bind_dn,
                            bind_password,
                            auto_bind=False, # creates anonymous session open and bound to the server with a synchronous communication strategy
                            client_strategy=ldap3.RESTARTABLE,
                            read_only=True,
                            version=3)
            satosa_logging(logger, logging.DEBUG, "Successfully connected to LDAP server", None)

        except LDAPException as e:
            msg = "Caught exception when connecting to LDAP server: {}".format(e)
            satosa_logging(logger, logging.ERROR, msg, None)
            raise LdapAttributeStoreError(msg)

        return connection

    def process(self, context, data):
        """
        Default interface for microservices. Process the input data for
        the input context.
        """
        self.context = context

        # Find the entityID for the SP that initiated the flow.
        try:
            sp_entity_id = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "Unable to determine the entityID for the SP requester", context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "entityID for the SP requester is {}".format(sp_entity_id), context.state)

        # Get the configuration for the SP.
        if sp_entity_id in self.config.keys():
            config = self.config[sp_entity_id]
        else:
            config = self.config['default']

        satosa_logging(logger, logging.DEBUG, "Using config {}".format(self._filter_config(config)), context.state)

        # Ignore this SP entirely if so configured.
        if config['ignore']:
            satosa_logging(logger, logging.INFO, "Ignoring SP {}".format(sp_entity_id), None)
            return super().process(context, data)

        # The list of values for the LDAP search filters that will be tried in order to find the
        # LDAP directory record for the user.
        filter_values = []

        # Loop over the configured list of identifiers from the IdP to consider and find
        # asserted values to construct the ordered list of values for the LDAP search filters.
        for candidate in config['ordered_identifier_candidates']:
            value = self._construct_filter_value(candidate, data)
            # If we have constructed a non empty value then add it as the next filter value
            # to use when searching for the user record.
            if value:
                filter_values.append(value)
                satosa_logging(logger, logging.DEBUG, "Added search filter value {} to list of search filters".format(value), context.state)

        # Initialize an empty LDAP record. The first LDAP record found using the ordered
        # list of search filter values will be the record used.
        record = None
        results = None
        exp_msg = ''

        for filter_val in filter_values:
            connection = config['connection']
            search_filter = '({0}={1})'.format(config['ldap_identifier_attribute'], filter_val)
            # show ldap filter
            satosa_logging(logger, logging.INFO, "LDAP query for {}".format(search_filter), context.state)
            satosa_logging(logger, logging.DEBUG, "Constructed search filter {}".format(search_filter), context.state)

            try:
                # message_id only works in REUSABLE async connection strategy
                results = connection.search(config['search_base'], search_filter, attributes=config['search_return_attributes'].keys())
            except LDAPException as err:
                exp_msg = "Caught LDAP exception: {}".format(err)
            except LdapAttributeStoreError as err:
                exp_msg = "Caught LDAP Attribute Store exception: {}".format(err)
            except Exception as err:
                exp_msg = "Caught unhandled exception: {}".format(err)

            if exp_msg:
                satosa_logging(logger, logging.ERROR, exp_msg, context.state)
                return super().process(context, data)

            if not results:
                satosa_logging(logger, logging.DEBUG, "Querying LDAP server: Nop results for {}.".format(filter_val), context.state)
                continue
            responses = connection.entries

            satosa_logging(logger, logging.DEBUG, "Done querying LDAP server", context.state)
            satosa_logging(logger, logging.DEBUG, "LDAP server returned {} records".format(len(responses)), context.state)

            # for now consider only the first record found (if any)
            if len(responses) > 0:
                if len(responses) > 1:
                    satosa_logging(logger, logging.WARN, "LDAP server returned {} records using search filter value {}".format(len(responses), filter_val), context.state)
                record = responses[0]
                break

        # Before using a found record, if any, to populate attributes
        # clear any attributes incoming to this microservice if so configured.
        if config['clear_input_attributes']:
            satosa_logging(logger, logging.DEBUG, "Clearing values for these input attributes: {}".format(data.attributes), context.state)
            data.attributes = {}

        # this adapts records with different search and conenction strategy (sync without pool)
        r = dict()
        r['dn'] = record.entry_dn
        r['attributes'] = record.entry_attributes_as_dict
        record = r
        # ends adaptation

        # Use a found record, if any, to populate attributes and input for NameID
        if record:
            satosa_logging(logger, logging.DEBUG, "Using record with DN {}".format(record["dn"]), context.state)
            satosa_logging(logger, logging.DEBUG, "Record with DN {} has attributes {}".format(record["dn"], record["attributes"]), context.state)

            # Populate attributes as configured.
            self._populate_attributes(config, record, context, data)

            # Populate input for NameID if configured. SATOSA core does the hashing of input
            # to create a persistent NameID.
            self._populate_input_for_name_id(config, record, context, data)

        else:
            satosa_logging(logger, logging.WARN, "No record found in LDAP so no attributes will be added", context.state)
            on_ldap_search_result_empty = config['on_ldap_search_result_empty']
            if on_ldap_search_result_empty:
                # Redirect to the configured URL with
                # the entityIDs for the target SP and IdP used by the user
                # as query string parameters (URL encoded).
                encoded_sp_entity_id = urllib.parse.quote_plus(sp_entity_id)
                encoded_idp_entity_id = urllib.parse.quote_plus(data.auth_info.issuer)
                url = "{}?sp={}&idp={}".format(on_ldap_search_result_empty, encoded_sp_entity_id, encoded_idp_entity_id)
                satosa_logging(logger, logging.INFO, "Redirecting to {}".format(url), context.state)
                return Redirect(url)

        satosa_logging(logger, logging.DEBUG, "Returning data.attributes {}".format(str(data.attributes)), context.state)
        return ResponseMicroService.process(self, context, data)
