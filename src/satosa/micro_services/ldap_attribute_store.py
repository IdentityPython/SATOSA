"""
SATOSA microservice that uses an identifier asserted by
the home organization SAML IdP as a key to search an LDAP
directory for a record and then consume attributes from
the record and assert them to the receiving SP.
"""

import copy
import logging
import urllib

import ldap3
from ldap3.core.exceptions import LDAPException

from collections import defaultdict

from satosa.exception import SATOSAError
from satosa.logging_util import satosa_logging
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect


logger = logging.getLogger(__name__)

KEY_FOUND_LDAP_RECORD = "ldap_attribute_store_found_record"


class LdapAttributeStoreError(SATOSAError):
    """
    LDAP attribute store error
    """


class LdapAttributeStore(ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in LDAP and obtain attributes
    to assert about the user to the frontend receiving service.
    """

    config_defaults = {
        "bind_dn": None,
        "bind_password": None,
        "clear_input_attributes": False,
        "ignore": False,
        "ldap_identifier_attribute": None,
        "ldap_url": None,
        "ldap_to_internal_map": None,
        "on_ldap_search_result_empty": None,
        "ordered_identifier_candidates": None,
        "overwrite_existing_attributes": True,
        "search_base": None,
        "query_return_attributes": None,
        "search_return_attributes": None,
        "user_id_from_attrs": [],
        "read_only": True,
        "version": 3,
        "auto_bind": "AUTO_BIND_TLS_BEFORE_BIND",
        "client_strategy": "REUSABLE",
        "pool_size": 10,
        "pool_keepalive": 10,
    }

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if "default" in config and "" in config:
            msg = """Use either 'default' or "" in config but not both"""
            satosa_logging(logger, logging.ERROR, msg, None)
            raise LdapAttributeStoreError(msg)

        if "" in config:
            config["default"] = config.pop("")

        if "default" not in config:
            msg = "No default configuration is present"
            satosa_logging(logger, logging.ERROR, msg, None)
            raise LdapAttributeStoreError(msg)

        self.config = {}

        # Process the default configuration first then any per-SP overrides.
        sp_list = ["default"]
        sp_list.extend([key for key in config.keys() if key != "default"])

        connections = {}

        for sp in sp_list:
            if not isinstance(config[sp], dict):
                msg = "Configuration value for {} must be a dictionary"
                satosa_logging(logger, logging.ERROR, msg, None)
                raise LdapAttributeStoreError(msg)

            # Initialize configuration using module defaults then update
            # with configuration defaults and then per-SP overrides.
            # sp_config = copy.deepcopy(LdapAttributeStore.config_defaults)
            sp_config = copy.deepcopy(self.config_defaults)
            if "default" in self.config:
                sp_config.update(self.config["default"])
            sp_config.update(config[sp])

            # Tuple to index existing LDAP connections so they can be
            # re-used if there are no changes in parameters.
            connection_params = (
                sp_config["bind_dn"],
                sp_config["bind_password"],
                sp_config["ldap_url"],
                sp_config["search_base"],
            )

            if connection_params in connections:
                sp_config["connection"] = connections[connection_params]
                msg = "Reusing LDAP connection for SP {}".format(sp)
                satosa_logging(logger, logging.DEBUG, msg, None)
            else:
                try:
                    connection = self._ldap_connection_factory(sp_config)
                    connections[connection_params] = connection
                    sp_config["connection"] = connection
                    msg = "Created new LDAP connection for SP {}".format(sp)
                    satosa_logging(logger, logging.DEBUG, msg, None)
                except LdapAttributeStoreError:
                    # It is acceptable to not have a default LDAP connection
                    # but all SP overrides must have a connection, either
                    # inherited from the default or directly configured.
                    if sp != "default":
                        msg = "No LDAP connection can be initialized for SP {}"
                        msg = msg.format(sp)
                        satosa_logging(logger, logging.ERROR, msg, None)
                        raise LdapAttributeStoreError(msg)

            self.config[sp] = sp_config

        msg = "LDAP Attribute Store microservice initialized"
        satosa_logging(logger, logging.INFO, msg, None)

    def _construct_filter_value(
        self, candidate, name_id_value, name_id_format, issuer, attributes
    ):
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
        # Get the values configured list of identifier names for this candidate
        # and substitute None if there are no values for a configured
        # identifier.
        values = [
            attr_value[0] if isinstance(attr_value, list) else attr_value
            for identifier_name in candidate["attribute_names"]
            for attr_value in [attributes.get(identifier_name)]
        ]
        msg = "Found candidate values {}".format(values)
        satosa_logging(logger, logging.DEBUG, msg, None)

        # If one of the configured identifier names is name_id then if there is
        # also a configured name_id_format add the value for the NameID of that
        # format if it was asserted by the IdP or else add the value None.
        if "name_id" in candidate["attribute_names"]:
            candidate_nameid_value = None
            candidate_name_id_format = candidate.get("name_id_format")
            if (
                name_id_value
                and candidate_name_id_format
                and candidate_name_id_format == name_id_format
            ):
                msg = "IdP asserted NameID {}".format(name_id_value)
                satosa_logging(logger, logging.DEBUG, msg, None)
                candidate_nameid_value = name_id_value

            # Only add the NameID value asserted by the IdP if it is not
            # already in the list of values. This is necessary because some
            # non-compliant IdPs have been known, for example, to assert the
            # value of eduPersonPrincipalName in the value for SAML2 persistent
            # NameID as well as asserting eduPersonPrincipalName.
            if candidate_nameid_value not in values:
                msg = "Added NameID {} to candidate values"
                msg = msg.format(candidate_nameid_value)
                satosa_logging(logger, logging.DEBUG, msg, None)
                values.append(candidate_nameid_value)
            else:
                msg = "NameID {} value also asserted as attribute value"
                msg = msg.format(candidate_nameid_value)
                satosa_logging(logger, logging.WARN, msg, None)

        # If no value was asserted by the IdP for one of the configured list of
        # identifier names for this candidate then go onto the next candidate.
        if None in values:
            msg = "Candidate is missing value so skipping"
            satosa_logging(logger, logging.DEBUG, msg, None)
            return None

        # All values for the configured list of attribute names are present
        # so we can create a value. Add a scope if configured
        # to do so.
        if "add_scope" in candidate:
            scope = (
                issuer
                if candidate["add_scope"] == "issuer_entityid"
                else candidate["add_scope"]
            )
            msg = "Added scope {} to values".format(scope)
            satosa_logging(logger, logging.DEBUG, msg, None)
            values.append(scope)

        # Concatenate all values to create the filter value.
        value = "".join(values)

        msg = "Constructed filter value {}".format(value)
        satosa_logging(logger, logging.DEBUG, msg, None)

        return value

    def _filter_config(self, config, fields=None):
        """
        Filter sensitive details like passwords from a configuration
        dictionary.
        """
        filter_fields_default = ["bind_password", "connection"]
        filter_fields = fields or filter_fields_default
        result = {
            field: "<hidden>" if field in filter_fields else value
            for field, value in config.items()
        }
        return result

    def _ldap_connection_factory(self, config):
        """
        Use the input configuration to instantiate and return
        a ldap3 Connection object.
        """
        ldap_url = config["ldap_url"]
        bind_dn = config["bind_dn"]
        bind_password = config["bind_password"]

        if not ldap_url:
            raise LdapAttributeStoreError("ldap_url is not configured")
        if not bind_dn:
            raise LdapAttributeStoreError("bind_dn is not configured")
        if not bind_password:
            raise LdapAttributeStoreError("bind_password is not configured")

        server = ldap3.Server(config["ldap_url"])

        msg = "Creating a new LDAP connection"
        satosa_logging(logger, logging.DEBUG, msg, None)

        msg = "Using LDAP URL {}".format(ldap_url)
        satosa_logging(logger, logging.DEBUG, msg, None)

        msg = "Using bind DN {}".format(bind_dn)
        satosa_logging(logger, logging.DEBUG, msg, None)

        auto_bind_string = config["auto_bind"]
        auto_bind_map = {
            "AUTO_BIND_NONE": ldap3.AUTO_BIND_NONE,
            "AUTO_BIND_NO_TLS": ldap3.AUTO_BIND_NO_TLS,
            "AUTO_BIND_TLS_AFTER_BIND": ldap3.AUTO_BIND_TLS_AFTER_BIND,
            "AUTO_BIND_TLS_BEFORE_BIND": ldap3.AUTO_BIND_TLS_BEFORE_BIND,
        }
        auto_bind = auto_bind_map[auto_bind_string]

        read_only = config["read_only"]
        version = config["version"]

        client_strategy_string = config["client_strategy"]
        client_strategy_map = {
            "SYNC": ldap3.SYNC,
            "ASYNC": ldap3.ASYNC,
            "LDIF": ldap3.LDIF,
            "RESTARTABLE": ldap3.RESTARTABLE,
            "REUSABLE": ldap3.REUSABLE,
        }
        client_strategy = client_strategy_map[client_strategy_string]

        pool_size = config["pool_size"]
        pool_keepalive = config["pool_keepalive"]
        if client_strategy == ldap3.REUSABLE:
            msg = "Using pool size {}".format(pool_size)
            satosa_logging(logger, logging.DEBUG, msg, None)
            msg = "Using pool keep alive {}".format(pool_keepalive)
            satosa_logging(logger, logging.DEBUG, msg, None)

        try:
            connection = ldap3.Connection(
                server,
                bind_dn,
                bind_password,
                auto_bind=auto_bind,
                client_strategy=client_strategy,
                read_only=read_only,
                version=version,
                pool_size=pool_size,
                pool_keepalive=pool_keepalive,
            )
            msg = "Successfully connected to LDAP server"
            satosa_logging(logger, logging.DEBUG, msg, None)

        except LDAPException as e:
            msg = "Caught exception when connecting to LDAP server: {}"
            msg = msg.format(e)
            satosa_logging(logger, logging.ERROR, msg, None)
            raise LdapAttributeStoreError(msg)

        msg = "Successfully connected to LDAP server"
        satosa_logging(logger, logging.DEBUG, msg, None)

        return connection

    def _populate_attributes(self, config, record):
        """
        Use a record found in LDAP to populate attributes.
        """

        ldap_attributes = record.get("attributes", None)
        if not ldap_attributes:
            msg = "No attributes returned with LDAP record"
            satosa_logging(logger, logging.DEBUG, msg, None)
            return

        ldap_to_internal_map = (
            config["ldap_to_internal_map"]
            if config["ldap_to_internal_map"]
            # Deprecated configuration. Will be removed in future.
            else config["search_return_attributes"]
        )

        attributes = defaultdict(list)

        for attr, values in ldap_attributes.items():
            internal_attr = ldap_to_internal_map.get(attr, None)
            if not internal_attr and ";" in attr:
                internal_attr = ldap_to_internal_map.get(attr.split(";")[0], None)

            if internal_attr and values:
                attributes[internal_attr].extend(values)
                msg = "Recording internal attribute {} with values {}"
                msg = msg.format(internal_attr, attributes[internal_attr])
                satosa_logging(logger, logging.DEBUG, msg, None)

        return attributes

    def _populate_input_for_name_id(self, config, record, data):
        """
        Use a record found in LDAP to populate input for
        NameID generation.
        """
        user_id_from_attrs = config["user_id_from_attrs"]
        user_ids = [
            sorted_list_value
            for attr in user_id_from_attrs
            for value in [record["attributes"].get(attr)]
            if value
            for list_value in [value if type(value) is list else [value]]
            for sorted_list_value in sorted(list_value)
        ]
        return user_ids

    def process(self, context, data):
        """
        Default interface for microservices. Process the input data for
        the input context.
        """
        issuer = data.auth_info.issuer
        requester = data.requester
        config = self.config.get(requester) or self.config["default"]
        msg = {
            "message": "entityID for the involved entities",
            "requester": requester,
            "issuer": issuer,
            "config": self._filter_config(config),
        }
        satosa_logging(logger, logging.DEBUG, msg, context.state)

        # Ignore this SP entirely if so configured.
        if config["ignore"]:
            msg = "Ignoring SP {}".format(requester)
            satosa_logging(logger, logging.INFO, msg, context.state)
            return super().process(context, data)

        # The list of values for the LDAP search filters that will be tried in
        # order to find the LDAP directory record for the user.
        filter_values = [
            filter_value
            for candidate in config["ordered_identifier_candidates"]
            # Consider and find asserted values to construct the ordered list
            # of values for the LDAP search filters.
            for filter_value in [
                self._construct_filter_value(
                    candidate,
                    data.subject_id,
                    data.subject_type,
                    issuer,
                    data.attributes,
                )
            ]
            # If we have constructed a non empty value then add it as the next
            # filter value to use when searching for the user record.
            if filter_value
        ]
        msg = {"message": "Search filters", "filter_values": filter_values}
        satosa_logging(logger, logging.DEBUG, msg, context.state)

        # Initialize an empty LDAP record. The first LDAP record found using
        # the ordered # list of search filter values will be the record used.
        record = None
        results = None
        exp_msg = None

        for filter_val in filter_values:
            connection = config["connection"]
            ldap_ident_attr = config["ldap_identifier_attribute"]
            search_filter = "({0}={1})".format(ldap_ident_attr, filter_val)
            msg = {
                "message": "LDAP query with constructed search filter",
                "search filter": search_filter,
            }
            satosa_logging(logger, logging.DEBUG, msg, context.state)

            attributes = (
                config["query_return_attributes"]
                if config["query_return_attributes"]
                # Deprecated configuration. Will be removed in future.
                else config["search_return_attributes"].keys()
            )
            try:
                results = connection.search(
                    config["search_base"], search_filter, attributes=attributes
                )
            except LDAPException as err:
                exp_msg = "Caught LDAP exception: {}".format(err)
            except LdapAttributeStoreError as err:
                exp_msg = "Caught LDAP Attribute Store exception: {}"
                exp_msg = exp_msg.format(err)
            except Exception as err:
                exp_msg = "Caught unhandled exception: {}".format(err)

            if exp_msg:
                satosa_logging(logger, logging.ERROR, exp_msg, context.state)
                return super().process(context, data)

            if not results:
                msg = "Querying LDAP server: No results for {}."
                msg = msg.format(filter_val)
                satosa_logging(logger, logging.DEBUG, msg, context.state)
                continue

            if isinstance(results, bool):
                responses = connection.entries
            else:
                responses = connection.get_response(results)[0]

            msg = "Done querying LDAP server"
            satosa_logging(logger, logging.DEBUG, msg, context.state)
            msg = "LDAP server returned {} records".format(len(responses))
            satosa_logging(logger, logging.INFO, msg, context.state)

            # For now consider only the first record found (if any).
            if len(responses) > 0:
                if len(responses) > 1:
                    msg = "LDAP server returned {} records using search filter"
                    msg = msg + " value {}"
                    msg = msg.format(len(responses), filter_val)
                    satosa_logging(logger, logging.WARN, msg, context.state)
                record = responses[0]
                break

        # Before using a found record, if any, to populate attributes
        # clear any attributes incoming to this microservice if so configured.
        if config["clear_input_attributes"]:
            msg = "Clearing values for these input attributes: {}"
            msg = msg.format(data.attributes)
            satosa_logging(logger, logging.DEBUG, msg, context.state)
            data.attributes = {}

        # This adapts records with different search and connection strategy
        # (sync without pool), it should be tested with anonimous bind with
        # message_id.
        if isinstance(results, bool):
            record = {
                "dn": record.entry_dn if hasattr(record, "entry_dn") else "",
                "attributes": (
                    record.entry_attributes_as_dict
                    if hasattr(record, "entry_attributes_as_dict")
                    else {}
                ),
            }

        # Use a found record, if any, to populate attributes and input for
        # NameID
        if record:
            msg = {
                "message": "Using record with DN and attributes",
                "DN": record["dn"],
                "attributes": record["attributes"],
            }
            satosa_logging(logger, logging.DEBUG, msg, context.state)

            # Populate attributes as configured.
            new_attrs = self._populate_attributes(config, record)

            overwrite = config["overwrite_existing_attributes"]
            for attr, values in new_attrs.items():
                if not overwrite:
                    values = list(set(data.attributes.get(attr, []) + values))
                data.attributes[attr] = values

            # Populate input for NameID if configured. SATOSA core does the
            # hashing of input to create a persistent NameID.
            user_ids = self._populate_input_for_name_id(config, record, data)
            if user_ids:
                data.subject_id = "".join(user_ids)
            msg = "NameID value is {}".format(data.subject_id)
            satosa_logging(logger, logging.DEBUG, msg, None)

            # Add the record to the context so that later microservices
            # may use it if required.
            context.decorate(KEY_FOUND_LDAP_RECORD, record)
            msg = "Added record {} to context".format(record)
            satosa_logging(logger, logging.DEBUG, msg, context.state)
        else:
            msg = "No record found in LDAP so no attributes will be added"
            satosa_logging(logger, logging.WARN, msg, context.state)
            on_ldap_search_result_empty = config["on_ldap_search_result_empty"]
            if on_ldap_search_result_empty:
                # Redirect to the configured URL with
                # the entityIDs for the target SP and IdP used by the user
                # as query string parameters (URL encoded).
                encoded_sp_entity_id = urllib.parse.quote_plus(requester)
                encoded_idp_entity_id = urllib.parse.quote_plus(issuer)
                url = "{}?sp={}&idp={}".format(
                    on_ldap_search_result_empty,
                    encoded_sp_entity_id,
                    encoded_idp_entity_id,
                )
                msg = "Redirecting to {}".format(url)
                satosa_logging(logger, logging.INFO, msg, context.state)
                return Redirect(url)

        msg = "Returning data.attributes {}".format(data.attributes)
        satosa_logging(logger, logging.DEBUG, msg, context.state)
        return super().process(context, data)
