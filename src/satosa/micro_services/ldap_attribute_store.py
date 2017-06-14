"""
SATOSA microservice that uses an identifier asserted by 
the home organization SAML IdP as a key to search an LDAP
directory for a record and then consume attributes from
the record and assert them to the receiving SP.
"""

import satosa.micro_services.base
from satosa.logging_util import satosa_logging

import copy
import logging
import ldap3

logger = logging.getLogger(__name__)

class LdapAttributeStore(satosa.micro_services.base.ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in LDAP and obtain attributes
    to assert about the user to the frontend receiving service.
    """
    logprefix = "LDAP_ATTRIBUTE_STORE:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def constructFilterValue(self, identifier, data):
        """
        Construct and return a LDAP directory search filter value from the
        data asserted by the IdP based on the input identifier.

        If the input identifier is a list of identifiers then this
        method is called recursively and the values concatenated together.

        If the input identifier is a dictionary with 'name_id' as the key
        and a NameID format as value than the NameID value (if any) asserted
        by the IdP for that format is used as the value.
        """
        value = ""

        # If the identifier is a list of identifiers then loop over them
        # calling ourself recursively and concatenate the values from 
        # the identifiers together.
        if isinstance(identifier, list):
            for i in identifier:
                value += self.constructFilterValue(i, data)

        # If the identifier is a dictionary with key 'name_id' then the value
        # is a NameID format. Look for a NameID asserted by the IdP with that
        # format and if found use its value.
        elif isinstance(identifier, dict):
            if 'name_id' in identifier:
                nameIdFormat = identifier['name_id']
                if 'name_id' in data.to_dict():
                    if nameIdFormat in data.to_dict()['name_id']:
                        value += data.to_dict()['name_id'][nameIdFormat]

        # The identifier is not a list or dictionary so just consume the asserted values
        # for this single identifier to create the value.
        else:
            if identifier in data.attributes:
                for v in data.attributes[identifier]:
                    value += v

        return value

    def process(self, context, data):
        logprefix = LdapAttributeStore.logprefix

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config
        configClean = copy.deepcopy(config)
        if 'bind_password' in configClean:
            configClean['bind_password'] = 'XXXXXXXX'    

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, configClean), context.state)

        # Find the entityID for the SP that initiated the flow
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID for the SP requester".format(logprefix), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} entityID for the SP requester is {}".format(logprefix, spEntityID), context.state)

        # Examine our configuration to determine if there is a per-SP configuration
        if spEntityID in self.config:
            config = self.config[spEntityID]
            configClean = copy.deepcopy(config)
            if 'bind_password' in configClean:
                configClean['bind_password'] = 'XXXXXXXX'    
            satosa_logging(logger, logging.DEBUG, "{} For SP {} using configuration {}".format(logprefix, spEntityID, configClean), context.state)
        
        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'ldap_url' in config:
                ldap_url = config['ldap_url']
            else:
                ldap_url = self.config['ldap_url']
            if 'bind_dn' in config:
                bind_dn = config['bind_dn']
            else:
                bind_dn = self.config['bind_dn']
            if 'bind_dn' in config:
                bind_password = config['bind_password']
            else:
                bind_password = self.config['bind_password']
            if 'search_base' in config:
                search_base = config['search_base']
            else:
                search_base = self.config['search_base']
            if 'search_return_attributes' in config:
                search_return_attributes = config['search_return_attributes']
            else:
                search_return_attributes = self.config['search_return_attributes']
            if 'idp_identifiers' in config:
                idp_identifiers = config['idp_identifiers']
            else:
                idp_identifiers = self.config['idp_identifiers']
            if 'ldap_identifier_attribute' in config:
                ldap_identifier_attribute = config['ldap_identifier_attribute']
            else:
                ldap_identifier_attribute = self.config['ldap_identifier_attribute']
            if 'clear_input_attributes' in config:
                clear_input_attributes = config['clear_input_attributes']
            elif 'clear_input_attributes' in self.config:
                clear_input_attributes = self.config['clear_input_attributes']
            else:
                clear_input_attributes = False
            if 'user_id_from_attrs' in config:
                user_id_from_attrs = config['user_id_from_attrs']
            elif 'user_id_from_attrs' in self.config:
                user_id_from_attrs = self.config['user_id_from_attrs']
            else:
                user_id_from_attrs = []

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        # The list of values for the LDAP search filters that will be tried in order to find the
        # LDAP directory record for the user.
        filterValues = []

        # Loop over the configured list of identifiers from the IdP to consider and find
        # asserted values to construct the ordered list of values for the LDAP search filters.
        for identifier in idp_identifiers:
            value = self.constructFilterValue(identifier, data)

            # If we have constructed a non empty value then add it as the next filter value
            # to use when searching for the user record.
            if value:
                filterValues.append(value)
                satosa_logging(logger, logging.DEBUG, "{} Added identifier {} with value {} to list of search filters".format(logprefix, identifier, value), context.state)

        # Initialize an empty LDAP record. The first LDAP record found using the ordered
        # list of search filter values will be the record used.
        record = None

        try:
            satosa_logging(logger, logging.DEBUG, "{} Using LDAP URL {}".format(logprefix, ldap_url), context.state)
            server = ldap3.Server(ldap_url)

            satosa_logging(logger, logging.DEBUG, "{} Using bind DN {}".format(logprefix, bind_dn), context.state)
            connection = ldap3.Connection(server, bind_dn, bind_password, auto_bind=True)
            satosa_logging(logger, logging.DEBUG, "{} Connected to LDAP server".format(logprefix), context.state)

            for filterVal in filterValues:
                if record:
                    break

                search_filter = '({0}={1})'.format(ldap_identifier_attribute, filterVal)
                satosa_logging(logger, logging.DEBUG, "{} Constructed search filter {}".format(logprefix, search_filter), context.state)

                satosa_logging(logger, logging.DEBUG, "{} Querying LDAP server...".format(logprefix), context.state)
                connection.search(search_base, search_filter, attributes=search_return_attributes.keys())
                satosa_logging(logger, logging.DEBUG, "{} Done querying LDAP server".format(logprefix), context.state)

                responses = connection.response
                satosa_logging(logger, logging.DEBUG, "{} LDAP server returned {} records".format(logprefix, len(responses)), context.state)

                # for now consider only the first record found (if any)
                if len(responses) > 0:
                    if len(responses) > 1:
                        satosa_logging(logger, logging.WARN, "{} LDAP server returned {} records using IdP asserted attribute {}".format(logprefix, len(responses), identifier), context.state)
                    record = responses[0]
                    break
                        
        except Exception as err:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {0}".format(logprefix, err), None)
            return super().process(context, data)

        else:
            satosa_logging(logger, logging.DEBUG, "{} Unbinding and closing connection to LDAP server".format(logprefix), context.state)
            connection.unbind()

        # Before using a found record, if any, to populate attributes
        # clear any attributes incoming to this microservice if so configured.
        if clear_input_attributes:
            satosa_logging(logger, logging.DEBUG, "{} Clearing values for these input attributes: {}".format(logprefix, data.attributes), context.state)
            data.attributes = {}

        # Use a found record, if any, to populate attributes and input for NameID
        if record:
            satosa_logging(logger, logging.DEBUG, "{} Using record with DN {}".format(logprefix, record["dn"]), context.state)
            satosa_logging(logger, logging.DEBUG, "{} Record with DN {} has attributes {}".format(logprefix, record["dn"], record["attributes"]), context.state)

            # Populate attributes as configured.
            for attr in search_return_attributes.keys():
                if attr in record["attributes"]:
                    data.attributes[search_return_attributes[attr]] = record["attributes"][attr]
                    satosa_logging(logger, logging.DEBUG, "{} Setting internal attribute {} with values {}".format(logprefix, search_return_attributes[attr], record["attributes"][attr]), context.state)

            # Populate input for NameID if configured. SATOSA core does the hashing of input
            # to create a persistent NameID.
            if user_id_from_attrs:
                userId = ""
                for attr in user_id_from_attrs:
                    if attr in record["attributes"]:
                        value = record["attributes"][attr]
                        if isinstance(value, list):
                            # Use a default sort to ensure some predictability since the
                            # LDAP directory server may return multi-valued attributes
                            # in any order.
                            value.sort()
                            for v in value:
                                userId += v
                                satosa_logging(logger, logging.DEBUG, "{} Added attribute {} with value {} to input for NameID".format(logprefix, attr, v), context.state)
                        else:
                            userId += value
                            satosa_logging(logger, logging.DEBUG, "{} Added attribute {} with value {} to input for NameID".format(logprefix, attr, value), context.state)
                if not userId:
                    satosa_logging(logger, logging.WARNING, "{} Input for NameID is empty so not overriding default".format(logprefix), context.state)
                else:
                    data.user_id = userId
                    satosa_logging(logger, logging.DEBUG, "{} Input for NameID is {}".format(logprefix, data.user_id), context.state)

        else:
            satosa_logging(logger, logging.WARN, "{} No record found in LDAP so no attributes will be added".format(logprefix), context.state)

        satosa_logging(logger, logging.DEBUG, "{} returning data.attributes {}".format(logprefix, str(data.attributes)), context.state)
        return super().process(context, data)
