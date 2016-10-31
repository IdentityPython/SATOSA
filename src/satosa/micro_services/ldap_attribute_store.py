"""
SATOSA microservice that uses an identifier asserted by 
the home organization SAML IdP as a key to search an LDAP
directory for a record and then consume attributes from
the record and assert them to the receiving SP.
"""

import satosa.micro_services.base
from satosa.logging_util import satosa_logging

import logging
import ldap3

logger = logging.getLogger(__name__)

class LdapAttributeStore(satosa.micro_services.base.ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in LDAP and obtain attributes
    to assert about the user to the frontend receiving service.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def process(self, context, data):
        try:
            ldap_url = self.config['ldap_url']
            bind_dn = self.config['bind_dn']
            bind_password = self.config['bind_password']
            search_base = self.config['search_base']
            search_return_attributes = self.config['search_return_attributes']
            idp_identifiers = self.config['idp_identifiers']
            ldap_identifier_attribute = self.config['ldap_identifier_attribute']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "Configuration '{key}' is missing".format(key=err), context.state)
            return super().process(context, data)

        entry = None

        try:
            satosa_logging(logger, logging.DEBUG, "Using LDAP URL {}".format(ldap_url), context.state)
            server = ldap3.Server(ldap_url)

            satosa_logging(logger, logging.DEBUG, "Using bind DN {}".format(bind_dn), context.state)
            connection = ldap3.Connection(server, bind_dn, bind_password, auto_bind=True)
            satosa_logging(logger, logging.DEBUG, "Connected to LDAP server", context.state)


            for identifier in idp_identifiers:
                if entry:
                    break

                satosa_logging(logger, logging.DEBUG, "Using IdP asserted attribute {}".format(identifier), context.state)

                if identifier in data.attributes:
                    satosa_logging(logger, logging.DEBUG, "IdP asserted {} values for attribute {}".format(len(data.attributes[identifier]),identifier), context.state)

                    for identifier_value in data.attributes[identifier]:
                        satosa_logging(logger, logging.DEBUG, "Considering IdP asserted value {} for attribute {}".format(identifier_value, identifier), context.state)

                        search_filter = '({0}={1})'.format(ldap_identifier_attribute, identifier_value)
                        satosa_logging(logger, logging.DEBUG, "Constructed search filter {}".format(search_filter), context.state)

                        satosa_logging(logger, logging.DEBUG, "Querying LDAP server...", context.state)
                        connection.search(search_base, search_filter, attributes=search_return_attributes.keys())
                        satosa_logging(logger, logging.DEBUG, "Done querying LDAP server", context.state)

                        entries = connection.entries
                        satosa_logging(logger, logging.DEBUG, "LDAP server returned {} entries".format(len(entries)), context.state)

                        # for now consider only the first entry found (if any)
                        if len(entries) > 0:
                            if len(entries) > 1:
                                satosa_logging(logger, logging.WARN, "LDAP server returned {} entries using IdP asserted attribute {}".format(len(entries), identifier), context.state)
                            entry = entries[0]
                            break
                        
                else:
                    satosa_logging(logger, logging.DEBUG, "IdP did not assert attribute {}".format(identifier), context.state)

        except Exception as err:
            satosa_logging(logger, logging.ERROR, "Caught exception: {0}".format(err), None)
            return super().process(context, data)

        else:
            satosa_logging(logger, logging.DEBUG, "Unbinding and closing connection to LDAP server", context.state)
            connection.unbind()

        # use a found entry, if any, to populate attributes
        if entry:
            satosa_logging(logger, logging.DEBUG, "Using entry with DN {}".format(entry.entry_get_dn()), context.state)
            data.attributes = {}
            for attr in search_return_attributes.keys():
                if attr in entry:
                    data.attributes[search_return_attributes[attr]] = entry[attr].values
                    satosa_logging(logger, logging.DEBUG, "Setting internal attribute {} with values {}".format(search_return_attributes[attr], entry[attr].values), context.state)

        else:
            # We should probably have an option here to clear attributes from IdP
            pass

        satosa_logging(logger, logging.DEBUG, "returning data.attributes %s" % str(data.attributes), context.state)
        return super().process(context, data)
