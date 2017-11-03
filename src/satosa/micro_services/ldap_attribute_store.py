"""
SATOSA microservice that uses an identifier asserted by 
the home organization SAML IdP as a key to search an LDAP
directory for a record and then consume attributes from
the record and assert them to the receiving SP.
"""

import satosa.micro_services.base
from satosa.logging_util import satosa_logging
from satosa.response import Redirect
from satosa.exception import SATOSAError

import copy
import logging
import ldap3
import urllib

from ldap3.core.exceptions import LDAPException

logger = logging.getLogger(__name__)

class LdapAttributeStoreError(SATOSAError):
    """
    LDAP attribute store error
    """
    pass

class LdapAttributeStore(satosa.micro_services.base.ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in LDAP and obtain attributes
    to assert about the user to the frontend receiving service.
    """

    config_defaults = {
        'bind_dn'                       : None,
        'bind_password'                 : None,
        'clear_input_attributes'        : False,
        'ignore'                        : False,
        'ldap_identifier_attribute'     : None,
        'ldap_url'                      : None,
        'on_ldap_search_result_empty'   : None,
        'ordered_identifier_candidates' : None,
        'pool_size'                     : 10,
        'pool_keepalive'                : 10,
        'search_base'                   : None,
        'search_return_attributes'      : None,
        'user_id_from_attrs'            : []
        }

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if 'default' in config and "" in config:
            msg = """Use either 'default' or "" in config but not both"""
            satosa_logging(logger, logging.ERROR, msg, None)
            raise LdapAttributeStoreError(msg)

        if "" in config:
            config['default'] = config.pop("")

        if 'default' not in config:
            msg = "No default configuration is present"
            satosa_logging(logger, logging.ERROR, msg, None)
            raise LdapAttributeStoreError(msg)

        self.config = {}

        # Process the default configuration first then any per-SP overrides.
        sp_list = ['default']
        sp_list.extend([ key for key in config.keys() if key != 'default' ])

        connections = {}

        for sp in sp_list:
            if not isinstance(config[sp], dict):
                msg = "Configuration value for {} must be a dictionary"
                satosa_logging(logger, logging.ERROR, msg, None)
                raise LdapAttributeStoreError(msg)

            # Initialize configuration using module defaults then update
            # with configuration defaults and then per-SP overrides.
            sp_config = copy.deepcopy(LdapAttributeStore.config_defaults)
            if 'default' in self.config:
                sp_config.update(self.config['default'])
            sp_config.update(config[sp])

            # Tuple to index existing LDAP connections so they can be
            # re-used if there are no changes in parameters.
            connection_params = (
                sp_config['bind_dn'],
                sp_config['bind_password'],
                sp_config['ldap_url'],
                sp_config['search_base']
                )

            if connection_params in connections:
                sp_config['connection'] = connections[connection_params]
                satosa_logging(logger, logging.DEBUG, "Reusing LDAP connection for SP {}".format(sp), None)
            else:
                try:
                    connection = self._ldap_connection_factory(sp_config)
                    connections[connection_params] = connection
                    sp_config['connection'] = connection
                    satosa_logging(logger, logging.DEBUG, "Created new LDAP connection for SP {}".format(sp), None)
                except LdapAttributeStoreError as e:
                    # It is acceptable to not have a default LDAP connection
                    # but all SP overrides must have a connection, either
                    # inherited from the default or directly configured.
                    if sp != 'default':
                        msg = "No LDAP connection can be initialized for SP {}".format(sp)
                        satosa_logging(logger, logging.ERROR, msg, None)
                        raise LdapAttributeStoreError(msg)

            self.config[sp] = sp_config

        satosa_logging(logger, logging.INFO, "LDAP Attribute Store microservice initialized", None)

    def _construct_filter_value(self, candidate, data):
        """
        Construct and return a LDAP directory search filter value from the
        candidate identifier.

        Argument 'canidate' is a dictionary with one required key and 
        two optional keys:
            
        key              required   value
        ---------------  --------   ---------------------------------
        attribute_names  Y          list of identifier names

        name_id_format   N          NameID format (string)

        add_scope        N          "issuer_entityid" or other string

        Argument 'data' is that object passed into the microservice
        method process().

        If the attribute_names list consists of more than one identifier
        name then the values of the identifiers will be concatenated together
        to create the filter value.
        
        If one of the identifier names in the attribute_names is the string
        'name_id' then the NameID value with format name_id_format
        will be concatenated to the filter value.

        If the add_scope key is present with value 'issuer_entityid' then the
        entityID for the IdP will be concatenated to "scope" the value. If the
        string is any other value it will be directly concatenated.
        """
        context = self.context

        attributes = data.attributes
        satosa_logging(logger, logging.DEBUG, "Input attributes {}".format(attributes), context.state)

        # Get the values configured list of identifier names for this candidate
        # and substitute None if there are no values for a configured identifier.
        values = []
        for identifier_name in candidate['attribute_names']:
            v = attributes.get(identifier_name, None)
            if isinstance(v, list):
                v = v[0]
            values.append(v)
        satosa_logging(logger, logging.DEBUG, "Found candidate values {}".format(values), context.state)

        # If one of the configured identifier names is name_id then if there is also a configured
        # name_id_format add the value for the NameID of that format if it was asserted by the IdP
        # or else add the value None.
        if 'name_id' in candidate['attribute_names']:
            nameid_value = None
            if 'name_id' in data.to_dict():
                name_id = data.to_dict()['name_id']
                satosa_logging(logger, logging.DEBUG, "IdP asserted NameID {}".format(name_id), context.state)
                if 'name_id_format' in candidate:
                    if candidate['name_id_format'] in name_id:
                        nameid_value = name_id[candidate['name_id_format']]

            # Only add the NameID value asserted by the IdP if it is not already 
            # in the list of values. This is necessary because some non-compliant IdPs
            # have been known, for example, to assert the value of eduPersonPrincipalName 
            # in the value for SAML2 persistent NameID as well as asserting
            # eduPersonPrincipalName.
            if nameid_value not in values:
                satosa_logging(logger, logging.DEBUG, "Added NameID {} to candidate values".format(nameid_value), context.state)
                values.append(nameid_value)
            else:
                satosa_logging(logger, logging.WARN, "NameID {} value also asserted as attribute value".format(nameid_value), context.state)

        # If no value was asserted by the IdP for one of the configured list of identifier names
        # for this candidate then go onto the next candidate.
        if None in values:
            satosa_logging(logger, logging.DEBUG, "Candidate is missing value so skipping", context.state)
            return None

        # All values for the configured list of attribute names are present
        # so we can create a value. Add a scope if configured
        # to do so.
        if 'add_scope' in candidate:
            if candidate['add_scope'] == 'issuer_entityid':
                scope = data.to_dict()['auth_info']['issuer']
            else:
                scope = candidate['add_scope']
            satosa_logging(logger, logging.DEBUG, "Added scope {} to values".format(scope), context.state)
            values.append(scope)

        # Concatenate all values to create the filter value.
        value = ''.join(values)

        satosa_logging(logger, logging.DEBUG, "Constructed filter value {}".format(value), context.state)

        return value

    def _filter_config(self, config, fields=None):
        """
        Filter sensitive details like passwords from a configuration
        dictionary.
        """
        filter_fields_default = [
            'bind_password',
            'connection'
            ]

        filter_fields = fields or filter_fields_default
        return dict(
            map(
                lambda key: (key, '<hidden>' if key in filter_fields else config[key]),
                config.keys()
                )
            )

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

        pool_size = config['pool_size']
        pool_keepalive = config['pool_keepalive']

        server = ldap3.Server(config['ldap_url'])

        satosa_logging(logger, logging.DEBUG, "Creating a new LDAP connection", None)
        satosa_logging(logger, logging.DEBUG, "Using LDAP URL {}".format(ldap_url), None)
        satosa_logging(logger, logging.DEBUG, "Using bind DN {}".format(bind_dn), None)
        satosa_logging(logger, logging.DEBUG, "Using pool size {}".format(pool_size), None)
        satosa_logging(logger, logging.DEBUG, "Using pool keep alive {}".format(pool_keepalive), None)

        try:
            connection = ldap3.Connection(
                            server, 
                            bind_dn, 
                            bind_password, 
                            auto_bind=True,
                            client_strategy=ldap3.REUSABLE,
                            pool_size=pool_size,
                            pool_keepalive=pool_keepalive
                            )

        except LDAPException as e:
            msg = "Caught exception when connecting to LDAP server: {}".format(e)
            satosa_logging(logger, logging.ERROR, msg, None)
            raise AttributeStoreError(msg)

        satosa_logging(logger, logging.DEBUG, "Successfully connected to LDAP server", None)

        return connection

    def _populate_attributes(self, config, record, context, data):
        """
        Use a record found in LDAP to populate attributes.
        """
        search_return_attributes = config['search_return_attributes']
        for attr in search_return_attributes.keys():
            if attr in record["attributes"]:
                if record["attributes"][attr]:
                    data.attributes[search_return_attributes[attr]] = record["attributes"][attr]
                    satosa_logging(
                        logger, 
                        logging.DEBUG, 
                        "Setting internal attribute {} with values {}".format(
                            search_return_attributes[attr], 
                            record["attributes"][attr]
                            ), 
                        context.state
                        )
                else:
                    satosa_logging(
                        logger, 
                        logging.DEBUG, 
                        "Not setting internal attribute {} because value {} is null or empty".format(
                            search_return_attributes[attr], 
                            record["attributes"][attr]
                            ), 
                        context.state
                        )

    def _populate_input_for_name_id(self, config, record, context, data):
        """
        Use a record found in LDAP to populate input for 
        NameID generation.
        """
        user_id = ""
        user_id_from_attrs = config['user_id_from_attrs']
        for attr in user_id_from_attrs:
            if attr in record["attributes"]:
                value = record["attributes"][attr]
                if isinstance(value, list):
                    # Use a default sort to ensure some predictability since the
                    # LDAP directory server may return multi-valued attributes
                    # in any order.
                    value.sort()
                    user_id += "".join(value)
                    satosa_logging(
                        logger, 
                        logging.DEBUG, 
                        "Added attribute {} with values {} to input for NameID".format(attr, v), 
                        context.state
                        )
                else:
                    user_id += value
                    satosa_logging(
                        logger, 
                        logging.DEBUG, 
                        "Added attribute {} with value {} to input for NameID".format(attr, value), 
                        context.state
                        )
        if not user_id:
            satosa_logging(
                logger, 
                logging.WARNING, 
                "Input for NameID is empty so not overriding default", 
                context.state
                )
        else:
            data.user_id = user_id
            satosa_logging(
                logger, 
                logging.DEBUG, 
                "Input for NameID is {}".format(data.user_id), 
                context.state
                )

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

        try:
            connection = config['connection']

            for filter_val in filter_values:
                if record:
                    break

                search_filter = '({0}={1})'.format(config['ldap_identifier_attribute'], filter_val)
                satosa_logging(logger, logging.DEBUG, "Constructed search filter {}".format(search_filter), context.state)

                satosa_logging(logger, logging.DEBUG, "Querying LDAP server...", context.state)
                message_id = connection.search(config['search_base'], search_filter, attributes=config['search_return_attributes'].keys())
                responses = connection.get_response(message_id)[0]
                satosa_logging(logger, logging.DEBUG, "Done querying LDAP server", context.state)
                satosa_logging(logger, logging.DEBUG, "LDAP server returned {} records".format(len(responses)), context.state)

                # for now consider only the first record found (if any)
                if len(responses) > 0:
                    if len(responses) > 1:
                        satosa_logging(logger, logging.WARN, "LDAP server returned {} records using search filter value {}".format(len(responses), filter_val), context.state)
                    record = responses[0]
                    break
        except LDAPException as err:
            satosa_logging(logger, logging.ERROR, "Caught LDAP exception: {}".format(err), context.state)
        except LdapAttributeStoreError as err:
            satosa_logging(logger, logging.ERROR, "Caught LDAP Attribute Store exception: {}".format(err), context.state)
        except Exception as err:
            satosa_logging(logger, logging.ERROR, "Caught unhandled exception: {}".format(err), context.state)
        else:
            err = None
        finally:
            if err:
                return super().process(context, data)

        # Before using a found record, if any, to populate attributes
        # clear any attributes incoming to this microservice if so configured.
        if config['clear_input_attributes']:
            satosa_logging(logger, logging.DEBUG, "Clearing values for these input attributes: {}".format(data.attributes), context.state)
            data.attributes = {}

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
                encoded_idp_entity_id = urllib.parse.quote_plus(data.to_dict()['auth_info']['issuer'])
                url = "{}?sp={}&idp={}".format(on_ldap_search_result_empty, encoded_sp_entity_id, encoded_idp_entity_id)
                satosa_logging(logger, logging.INFO, "Redirecting to {}".format(url), context.state)
                return Redirect(url)

        satosa_logging(logger, logging.DEBUG, "Returning data.attributes {}".format(str(data.attributes)), context.state)
        return super().process(context, data)
