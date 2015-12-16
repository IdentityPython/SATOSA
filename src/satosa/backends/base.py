"""
Holds a base class for backend modules used in the SATOSA proxy.
"""
from base64 import urlsafe_b64encode

from satosa.metadata_creation.description import MetadataDescription, ContactPersonDesc, \
    OrganizationDesc, UIInfoDesc

__author__ = 'mathiashedstrom'


class BackendModule(object):
    """
    Base class for a backend module.
    """

    def __init__(self, auth_callback_func, internal_attributes):
        """
        :type auth_callback_func:
        (satosa.context.Context, satosa.internal_data.InternalResponse) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]

        :param auth_callback_func: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        """
        self.auth_callback_func = auth_callback_func
        self.internal_attributes = internal_attributes

    def start_auth(self, context, internal_request):
        """
        This is the start up function of the backend authorization.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :rtype satosa.response.Response

        :param context: the request context
        :param internal_request: Information about the authorization request
        :return: response
        """
        raise NotImplementedError()

    def register_endpoints(self):
        """
        Register backend functions to endpoint urls.

        Example of registering an endpoint:
            reg_endp = [
                ("^Saml2IDP/acs/redirect", (endpoint_function, arguments)),
            ]


        :rtype list[(str, ((satosa.context.Context, Any) -> Any, Any))]

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, (function, arguments)), ...]
        """
        raise NotImplementedError()

    def get_metadata_desc(self):
        """
        Returns a description of the backend module.
        This is used when creating the VOPaaS frontend metadata
        :rtype: satosa.metadata_creation.description.MetadataDescription
        :return: A description of the backend
        """
        raise NotImplementedError()


def get_metadata_desc_for_oidc_backend(config, entity_id=None):
    """
    Returns a description of an VOPaaSOpenIdBackend
    :type config: dict[str, Any]
    :type entity_id: str
    :rtype: satosa.metadata_creation.description.MetadataDescription
    :param config: The openid_connect module config
    :param entity_id: If entity_id is None, the id will be retrieved from the config
    :return: A description
    """
    metadata_description = []
    if entity_id is None:
        entity_id = config["op_url"]
    entity_id = urlsafe_b64encode(entity_id.encode("utf-8")).decode("utf-8")
    description = MetadataDescription(entity_id)

    if "op_info" in config:
        op_info = config["op_info"]

        # Add contact person information
        for contact_person in op_info.get("contact_person", []):
            person = ContactPersonDesc()
            if 'contact_type' in contact_person:
                person.contact_type = contact_person['contact_type']
            for address in contact_person.get('email_address', []):
                person.add_email_address(address)
            if 'given_name' in contact_person:
                person.given_name = contact_person['given_name']
            if 'sur_name' in contact_person:
                person.sur_name = contact_person['sur_name']

            description.add_contact_person(person)

        # Add organization information
        if "organization" in op_info:
            organization_info = op_info["organization"]
            organization = OrganizationDesc()

            for name_info in organization_info.get("organization_name", []):
                organization.add_name(name_info[0], name_info[1])
            for display_name_info in organization_info.get("organization_display_name", []):
                organization.add_display_name(display_name_info[0], display_name_info[1])
            for url_info in organization_info.get("organization_url", []):
                organization.add_url(url_info[0], url_info[1])

            description.set_organization(organization)

        # Add ui information
        if "ui_info" in op_info:
            ui_info = op_info["ui_info"]
            ui_description = UIInfoDesc()
            for desc in ui_info.get("description", []):
                ui_description.add_description(desc[0], desc[1])
            for name in ui_info.get("display_name", []):
                ui_description.add_display_name(name[0], name[1])
            for logo in ui_info.get("logo", []):
                ui_description.add_logo(logo["image"], logo["width"], logo["height"], logo["lang"])

            description.set_ui_info(ui_description)

    metadata_description.append(description)
    return metadata_description
