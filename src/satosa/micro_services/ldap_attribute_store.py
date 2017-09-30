"""
SATOSA microservice that uses an identifier asserted by 
the home organization SAML IdP as a key to search an LDAP
directory for a record and then consume attributes from
the record and assert them to the receiving SP.
"""

import satosa.micro_services.base
from satosa.logging_util import satosa_logging
from satosa.response import Redirect

import copy
import logging
import ldap3
import urllib

logger = logging.getLogger(__name__)

class LdapAttributeStoreException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "LdapAttributeStoreException: {}".format(self.value)

class LdapAttributeStore(satosa.micro_services.base.ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in LDAP and obtain attributes
    to assert about the user to the frontend receiving service.
    """
    logprefix = "LDAP_ATTRIBUTE_STORE:"

    # Allowed configuration options for the microservice. Any key
    # in the config dictionary passed into the __init__() method
    # that is not a key in this dictionary is treated as the
    # entityID for a per-SP configuration.
    #
    # The keys are the allowed configuration options. The values
    # are a list of [default value, if required or not]. Note that
    # required here means required as part of an effective
    # configuration during a particular flow, so it applies
    # to the default configuration overridden with any per-SP
    # configuration details.
    config_options = {
        'bind_dn'                       : {'default' : None,  'required' : True},
        'bind_password'                 : {'default' : None,  'required' : True},
        'clear_input_attributes'        : {'default' : False, 'required' : False},
        'ignore'                        : {'default' : False, 'required' : False},
        'ldap_identifier_attribute'     : {'default' : None,  'required' : True},
        'ldap_url'                      : {'default' : None,  'required' : True},
        'on_ldap_search_result_empty'   : {'default' : None,  'required' : False},
        'ordered_identifier_candidates' : {'default' : None,  'required' : True},
        'search_base'                   : {'default' : None,  'required' : True},
        'search_return_attributes'      : {'default' : None,  'required' : True},
        'user_id_from_attrs'            : {'default' : [],    'required' : False} 
        }

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.logprefix = LdapAttributeStore.logprefix

    def _constructFilterValue(self, candidate, data):
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

    def _copyConfigOptions(self, source, target):
        """
        Copy allowed configuration options from the source
        dictionary to the target dictionary.
        """
        for option in LdapAttributeStore.config_options:
            if option in source:
                target[option] = source[option]

    def _getEffectiveConfig(self, entityID = None, state = None):
        """
        Get the effective configuration for the SP with entityID
        or the default configuration if no entityID.
        """
        logprefix = self.logprefix

        # Set microservice defaults for available configuration options.
        base_config = { key: value['default'] for key, value in LdapAttributeStore.config_options.items()}
        effective_config = copy.deepcopy(base_config)

        # Process default input configuration to the microservice.
        self._copyConfigOptions(self.config, effective_config)
        clean_for_logging = self._hideConfigSecrets(effective_config)
        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, clean_for_logging), state)

        # Process per-SP input configuration to the microservice.
        if entityID:
            if entityID in self.config:
                self._copyConfigOptions(self.config[entityID], effective_config)
                clean_for_logging = self._hideConfigSecrets(effective_config)
                satosa_logging(logger, logging.DEBUG, "{} For SP {} using configuration {}".format(logprefix, entityID, clean_for_logging), state)

        # Check effective configuration against required configuration details.
        for config_opt, required in {key: value['required'] for key, value in LdapAttributeStore.config_options.items()}.items():
            if required:
                if not effective_config[config_opt]:
                    raise LdapAttributeStoreException("Configuration option {} is required but missing".format(config_opt))

        return effective_config

    def _hideConfigSecrets(self, config):
        """
        Make a deep copy of the input config dictionary and
        replace the bind password with a dummy string and
        return the copy. 
        """
        clean_config = copy.deepcopy(config)
        if 'bind_password' in clean_config:
            clean_config['bind_password'] = 'XXXXXXXX'

        return clean_config

    def process(self, context, data):
        """
        Default interface for microservices. Process the input data for
        the input context.
        """
        self.context = context
        logprefix = self.logprefix

        # Find the entityID for the SP that initiated the flow.
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID for the SP requester".format(logprefix), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} entityID for the SP requester is {}".format(logprefix, spEntityID), context.state)

        # Get the effective configuration for the SP.
        try:
            config = self._getEffectiveConfig(spEntityID, context.state)
        except LdapAttributeStoreException as e:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {}".format(logprefix, e), context.state)
            return super().process(context, data)

        # Ignore this SP entirely if so configured.
        if config['ignore']:
            satosa_logging(logger, logging.INFO, "{} Ignoring SP {}".format(logprefix, spEntityID), None)
            return super().process(context, data)

        # The list of values for the LDAP search filters that will be tried in order to find the
        # LDAP directory record for the user.
        filterValues = []

        # Loop over the configured list of identifiers from the IdP to consider and find
        # asserted values to construct the ordered list of values for the LDAP search filters.
        for candidate in config['ordered_identifier_candidates']:
            value = self._constructFilterValue(candidate, data)

            # If we have constructed a non empty value then add it as the next filter value
            # to use when searching for the user record.
            if value:
                filterValues.append(value)
                satosa_logging(logger, logging.DEBUG, "{} Added search filter value {} to list of search filters".format(logprefix, value), context.state)

        # Initialize an empty LDAP record. The first LDAP record found using the ordered
        # list of search filter values will be the record used.
        record = None

        try:
            ldap_url = config['ldap_url']
            satosa_logging(logger, logging.DEBUG, "{} Using LDAP URL {}".format(logprefix, ldap_url), context.state)
            server = ldap3.Server(ldap_url)

            bind_dn = config['bind_dn']
            satosa_logging(logger, logging.DEBUG, "{} Using bind DN {}".format(logprefix, bind_dn), context.state)
            connection = ldap3.Connection(server, bind_dn, config['bind_password'], auto_bind=True)
            satosa_logging(logger, logging.DEBUG, "{} Connected to LDAP server".format(logprefix), context.state)

            for filterVal in filterValues:
                if record:
                    break

                search_filter = '({0}={1})'.format(config['ldap_identifier_attribute'], filterVal)
                satosa_logging(logger, logging.DEBUG, "{} Constructed search filter {}".format(logprefix, search_filter), context.state)

                satosa_logging(logger, logging.DEBUG, "{} Querying LDAP server...".format(logprefix), context.state)
                connection.search(config['search_base'], search_filter, attributes=config['search_return_attributes'].keys())
                satosa_logging(logger, logging.DEBUG, "{} Done querying LDAP server".format(logprefix), context.state)

                responses = connection.response
                satosa_logging(logger, logging.DEBUG, "{} LDAP server returned {} records".format(logprefix, len(responses)), context.state)

                # for now consider only the first record found (if any)
                if len(responses) > 0:
                    if len(responses) > 1:
                        satosa_logging(logger, logging.WARN, "{} LDAP server returned {} records using search filter value {}".format(logprefix, len(responses), filterVar), context.state)
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
        if config['clear_input_attributes']:
            satosa_logging(logger, logging.DEBUG, "{} Clearing values for these input attributes: {}".format(logprefix, data.attributes), context.state)
            data.attributes = {}

        # Use a found record, if any, to populate attributes and input for NameID
        if record:
            satosa_logging(logger, logging.DEBUG, "{} Using record with DN {}".format(logprefix, record["dn"]), context.state)
            satosa_logging(logger, logging.DEBUG, "{} Record with DN {} has attributes {}".format(logprefix, record["dn"], record["attributes"]), context.state)

            # Populate attributes as configured.
            search_return_attributes = config['search_return_attributes']
            for attr in search_return_attributes.keys():
                if attr in record["attributes"]:
                    if record["attributes"][attr]:
                        data.attributes[search_return_attributes[attr]] = record["attributes"][attr]
                        satosa_logging(logger, logging.DEBUG, "{} Setting internal attribute {} with values {}".format(logprefix, search_return_attributes[attr], record["attributes"][attr]), context.state)
                    else:
                        satosa_logging(logger, logging.DEBUG, "{} Not setting internal attribute {} because value {} is null or empty".format(logprefix, search_return_attributes[attr], record["attributes"][attr]), context.state)

            # Populate input for NameID if configured. SATOSA core does the hashing of input
            # to create a persistent NameID.
            user_id_from_attrs = config['user_id_from_attrs']
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
            on_ldap_search_result_empty = config['on_ldap_search_result_empty']
            if on_ldap_search_result_empty:
                # Redirect to the configured URL with
                # the entityIDs for the target SP and IdP used by the user
                # as query string parameters (URL encoded).
                encodedSpEntityID = urllib.parse.quote_plus(spEntityID)
                encodedIdpEntityID = urllib.parse.quote_plus(data.to_dict()['auth_info']['issuer'])
                url = "{}?sp={}&idp={}".format(on_ldap_search_result_empty, encodedSpEntityID, encodedIdpEntityID)
                satosa_logging(logger, logging.INFO, "{} Redirecting to {}".format(logprefix, url), context.state)
                return Redirect(url)

        satosa_logging(logger, logging.DEBUG, "{} returning data.attributes {}".format(logprefix, str(data.attributes)), context.state)
        return super().process(context, data)
