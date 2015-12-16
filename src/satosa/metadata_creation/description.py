"""
Help classes for creating the VOPaaS frontend metadata
"""
from satosa.image_converter import convert_to_base64

__author__ = 'mathiashedstrom'


class ContactPersonDesc(object):
    """
    Description class for a contact preson
    """

    def __init__(self):
        self.contact_type = None
        self._email_address = []
        self.given_name = None
        self.sur_name = None

    def add_email_address(self, address):
        """
        Adds an email address to the person description

        :type address: str

        :param address: Address to be added
        """
        self._email_address.append(address)

    def to_dict(self):
        """
        Returns a dictionary representation of the ContactPersonDesc.
        The format is the same as a pysaml2 configuration for a contact person.
        :rtype: dict[str, str]
        :return: A dictionary representation
        """
        person = {}
        if self.contact_type:
            person["contact_type"] = self.contact_type
        if self._email_address:
            person["email_address"] = self._email_address
        if self.given_name:
            person["given_name"] = self.given_name
        if self.sur_name:
            person["sur_name"] = self.sur_name
        return person


class UIInfoDesc(object):
    """
    Description class for UI info
    """

    def __init__(self):
        self._description = []
        self._display_name = []
        self._logos = []

    def add_description(self, text, lang):
        """
        Binds a description to the given language

        :type text: str
        :type lang: str

        :param text: Description
        :param lang: description language
        """
        self._description.append({"text": text, "lang": lang})

    def add_display_name(self, text, lang):
        """
        Binds a display name to the given language

        :type text: str
        :type lang: str

        :param text: Display name
        :param lang: Language
        """
        self._display_name.append({"text": text, "lang": lang})

    def add_logo(self, text, width, height, lang):
        """
        Binds a logo to the given language
        :type text: str
        :type width: str
        :type height: str
        :type lang: str

        :param text: Path to logo
        :param width: width of logo
        :param height: height of logo
        :param lang: language
        """
        text = convert_to_base64(text)
        self._logos.append({"text": text, "width": width, "height": height, "lang": lang})

    def to_dict(self):
        """
        Returns a dictionary representation of the UIInfoDesc object.
        The format is the same as a pysaml2 configuration for ui info.
        :rtype: dict[str, str]
        :return: A dictionary representation
        """
        ui_info = {}
        if self._description:
            ui_info["description"] = self._description
        if self._display_name:
            ui_info["display_name"] = self._display_name
        if self._logos:
            ui_info["logo"] = self._logos
        return {"service": {"idp": {"ui_info": ui_info}}} if ui_info else {}


class OrganizationDesc(object):
    """
    Description class for an organization
    """

    def __init__(self):
        self._display_name = []
        self._name = []
        self._url = []

    def add_display_name(self, name, lang):
        """
        Binds a display name to the given language
        :type name: str
        :type lang: str
        :param name: display name
        :param lang: language
        """
        self._display_name.append((name, lang))

    def add_name(self, name, lang):
        """
        Binds a name to the given language
        :type name: str
        :type lang: str
        :param name: Name of the organization
        :param lang: language
        """
        self._name.append((name, lang))

    def add_url(self, url, lang):
        """
        Binds an url to the given language
        :type url: str
        :type lang: str
        :param url: url to bind
        :param lang: language
        """
        self._url.append((url, lang))

    def to_dict(self):
        """
        Returns a dictionary representation of the OrganizationDesc object.
        The format is the same as a pysaml2 configuration for organization.
        :rtype: dict[str, str]
        :return: A dictionary representation
        """
        org = {}
        if self._display_name:
            org["display_name"] = self._display_name
        if self._name:
            org["name"] = self._name
        if self._url:
            org["url"] = self._url
        return {"organization": org} if org else {}


class MetadataDescription(object):
    """
    Description class for a backend module
    """

    def __init__(self, entity_id):
        self.entity_id = entity_id
        self._organization = None
        self._contact_person = []
        self._ui_info = None

    def set_organization(self, organization):
        """
        Set an organization to the description
        :type organization: vopaas.metadata_creation.description.OrganizationDesc
        :param organization: Organization description
        """
        assert isinstance(organization, OrganizationDesc)
        self._organization = organization

    def add_contact_person(self, person):
        """
        Adds a contact person to the description
        :type person: vopaas.metadata_creation.description.ContactPersonDesc
        :param person: The contact person to be added
        """
        assert isinstance(person, ContactPersonDesc)
        self._contact_person.append(person)

    def set_ui_info(self, ui_info):
        """
        Set an ui info to the description
        :type ui_info: vopaas.metadata_creation.description.UIInfoDesc
        :param ui_info: The ui info to be set
        """
        assert isinstance(ui_info, UIInfoDesc)
        self._ui_info = ui_info

    def to_dict(self):
        """
        Returns a dictionary representation of the MetadataDescription object.
        The format is the same as a pysaml2 configuration
        :rtype: dict[str, Any]
        :return: A dictionary representation
        """
        description = {}
        description["entityid"] = self.entity_id
        if self._organization:
            description.update(self._organization.to_dict())
        if self._contact_person:
            description['contact_person'] = []
            for person in self._contact_person:
                description['contact_person'].append(person.to_dict())
        if self._ui_info:
            description.update(self._ui_info.to_dict())
        return description
