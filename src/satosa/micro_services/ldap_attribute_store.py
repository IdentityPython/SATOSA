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

    def constructFilterValue(self, candidate, data):
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
        logprefix = self.logprefix
        context = self.context

        attributes = data.attributes
        satosa_logging(logger, logging.DEBUG, "{} Input attributes {}".format(logprefix, attributes), context.state)

        # Get the values configured list of identifier names for this candidate
        # and substitute None if there are no values for a configured identifier.
        values = []
        for identifier_name in candidate['attribute_names']:
            v = attributes.get(identifier_name, None)
            if isinstance(v, list):
                v = v[0]
            values.append(v)
        satosa_logging(logger, logging.DEBUG, "{} Found candidate values {}".format(logprefix, values), context.state)

        # If one of the configured identifier names is name_id then if there is also a configured
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

        # If no value was asserted by the IdP for one of the configured list of identifier names
        # for this candidate then go onto the next candidate.
        if None in values:
            satosa_logging(logger, logging.DEBUG, "{} Candidate is missing value so skipping".format(logprefix), context.state)
            return None

        # All values for the configured list of attribute names are present
        # so we can create a value. Add a scope if configured
        # to do so.
        if 'add_scope' in candidate:
            if candidate['add_scope'] == 'issuer_entityid':
                scope = data.to_dict()['auth_info']['issuer']
            else:
                scope = candidate['add_scope']
            satosa_logging(logger, logging.DEBUG, "{} Added scope {} to values".format(logprefix, scope), context.state)
            values.append(scope)

        # Concatenate all values to create the filter value.
        value = ''.join(values)

        satosa_logging(logger, logging.DEBUG, "{} Constructed filter value {}".format(logprefix, value), context.state)

        return value

    def process(self, context, data):
        logprefix = LdapAttributeStore.logprefix
        self.logprefix = logprefix
        self.context = context

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
            if 'ordered_identifier_candidates' in config:
                ordered_identifier_candidates = config['ordered_identifier_candidates']
            else:
                ordered_identifier_candidates = self.config['ordered_identifier_candidates']
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
            if 'ignore' in config:
                ignore = True
            else:
                ignore = False

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        # Ignore this SP entirely if so configured.
        if ignore:
            satosa_logging(logger, logging.INFO, "{} Ignoring SP {}".format(logprefix, spEntityID), None)
            return super().process(context, data)

        # The list of values for the LDAP search filters that will be tried in order to find the
        # LDAP directory record for the user.
        filterValues = []

        # Loop over the configured list of identifiers from the IdP to consider and find
        # asserted values to construct the ordered list of values for the LDAP search filters.
        for candidate in ordered_identifier_candidates:
            value = self.constructFilterValue(candidate, data)

            # If we have constructed a non empty value then add it as the next filter value
            # to use when searching for the user record.
            if value:
                filterValues.append(value)
                satosa_logging(logger, logging.DEBUG, "{} Added search filter value {} to list of search filters".format(logprefix, value), context.state)

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
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {}".format(logprefix, err), context.state)
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
                    if record["attributes"][attr]:
                        data.attributes[search_return_attributes[attr]] = record["attributes"][attr]
                        satosa_logging(logger, logging.DEBUG, "{} Setting internal attribute {} with values {}".format(logprefix, search_return_attributes[attr], record["attributes"][attr]), context.state)
                    else:
                        satosa_logging(logger, logging.DEBUG, "{} Not setting internal attribute {} because value {} is null or empty".format(logprefix, search_return_attributes[attr], record["attributes"][attr]), context.state)

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
