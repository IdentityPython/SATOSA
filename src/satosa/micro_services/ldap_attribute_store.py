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

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        record = None

        try:
            satosa_logging(logger, logging.DEBUG, "{} Using LDAP URL {}".format(logprefix, ldap_url), context.state)
            server = ldap3.Server(ldap_url)

            satosa_logging(logger, logging.DEBUG, "{} Using bind DN {}".format(logprefix, bind_dn), context.state)
            connection = ldap3.Connection(server, bind_dn, bind_password, auto_bind=True)
            satosa_logging(logger, logging.DEBUG, "{} Connected to LDAP server".format(logprefix), context.state)


            for identifier in idp_identifiers:
                if record:
                    break

                satosa_logging(logger, logging.DEBUG, "{} Using IdP asserted attribute {}".format(logprefix, identifier), context.state)

                if identifier in data.attributes:
                    satosa_logging(logger, logging.DEBUG, "{} IdP asserted {} values for attribute {}".format(logprefix, len(data.attributes[identifier]),identifier), context.state)

                    for identifier_value in data.attributes[identifier]:
                        satosa_logging(logger, logging.DEBUG, "{} Considering IdP asserted value {} for attribute {}".format(logprefix, identifier_value, identifier), context.state)

                        search_filter = '({0}={1})'.format(ldap_identifier_attribute, identifier_value)
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
                        
                else:
                    satosa_logging(logger, logging.DEBUG, "{} IdP did not assert attribute {}".format(logprefix, identifier), context.state)

        except Exception as err:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {0}".format(logprefix, err), None)
            return super().process(context, data)

        else:
            satosa_logging(logger, logging.DEBUG, "{} Unbinding and closing connection to LDAP server".format(logprefix), context.state)
            connection.unbind()

        # use a found record, if any, to populate attributes
        if record:
            satosa_logging(logger, logging.DEBUG, "{} Using record with DN {}".format(logprefix, record["dn"]), context.state)
            satosa_logging(logger, logging.DEBUG, "{} Record with DN {} has attributes {}".format(logprefix, record["dn"], record["attributes"]), context.state)
            data.attributes = {}
            for attr in search_return_attributes.keys():
                if attr in record["attributes"]:
                    data.attributes[search_return_attributes[attr]] = record["attributes"][attr]
                    satosa_logging(logger, logging.DEBUG, "{} Setting internal attribute {} with values {}".format(logprefix, search_return_attributes[attr], record["attributes"][attr]), context.state)

        else:
            # We should probably have an option here to clear attributes from IdP
            pass

        satosa_logging(logger, logging.DEBUG, "{} returning data.attributes {}".format(logprefix, str(data.attributes)), context.state)
        return super().process(context, data)
