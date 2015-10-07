"""
The module contains internal data representation in SATOSA and general converteras that can be used
for converting from SAML/OAuth/OpenID connect to the internal representation.
"""
from base64 import urlsafe_b64encode, urlsafe_b64decode
import datetime
from enum import Enum
import hashlib
import json

__author__ = 'haho0032'

SATOSA_ATTRIBUTES = {
    'aRecord': True,
    'aliasedEntryName': True,
    'aliasedObjectName': True,
    'associatedDomain': True,
    'associatedName': True,
    'audio': True,
    'authorityRevocationList': True,
    'buildingName': True,
    'businessCategory': True,
    'c': True,
    'cACertificate': True,
    'cNAMERecord': True,
    'carLicense': True,
    'certificateRevocationList': True,
    'cn': True,
    'co': True,
    'commonName': True,
    'countryName': True,
    'crossCertificatePair': True,
    'dITRedirect': True,
    'dSAQuality': True,
    'dc': True,
    'deltaRevocationList': True,
    'departmentNumber': True,
    'description': True,
    'destinationIndicator': True,
    'displayName': True,
    'distinguishedName': True,
    'dmdName': True,
    'dnQualifier': True,
    'documentAuthor': True,
    'documentIdentifier': True,
    'documentLocation': True,
    'documentPublisher': True,
    'documentTitle': True,
    'documentVersion': True,
    'domainComponent': True,
    'drink': True,
    'eduOrgHomePageURI': True,
    'eduOrgIdentityAuthNPolicyURI': True,
    'eduOrgLegalName': True,
    'eduOrgSuperiorURI': True,
    'eduOrgWhitePagesURI': True,
    'eduPersonAffiliation': True,
    'eduPersonEntitlement': True,
    'eduPersonNickname': True,
    'eduPersonOrgDN': True,
    'eduPersonOrgUnitDN': True,
    'eduPersonPrimaryAffiliation': True,
    'eduPersonPrimaryOrgUnitDN': True,
    'eduPersonPrincipalName': True,
    'eduPersonScopedAffiliation': True,
    'eduPersonTargetedID': True,
    'email': True,
    'emailAddress': True,
    'employeeNumber': True,
    'employeeType': True,
    'enhancedSearchGuide': True,
    'facsimileTelephoneNumber': True,
    'favouriteDrink': True,
    'fax': True,
    'federationFeideSchemaVersion': True,
    'friendlyCountryName': True,
    'generationQualifier': True,
    'givenName': True,
    'gn': True,
    'homePhone': True,
    'homePostalAddress': True,
    'homeTelephoneNumber': True,
    'host': True,
    'houseIdentifier': True,
    'info': True,
    'initials': True,
    'internationaliSDNNumber': True,
    'janetMailbox': True,
    'jpegPhoto': True,
    'knowledgeInformation': True,
    'l': True,
    'labeledURI': True,
    'localityName': True,
    'mDRecord': True,
    'mXRecord': True,
    'mail': True,
    'mailPreferenceOption': True,
    'manager': True,
    'member': True,
    'mobile': True,
    'mobileTelephoneNumber': True,
    'nSRecord': True,
    'name': True,
    'norEduOrgAcronym': True,
    'norEduOrgNIN': True,
    'norEduOrgSchemaVersion': True,
    'norEduOrgUniqueIdentifier': True,
    'norEduOrgUniqueNumber': True,
    'norEduOrgUnitUniqueIdentifier': True,
    'norEduOrgUnitUniqueNumber': True,
    'norEduPersonBirthDate': True,
    'norEduPersonLIN': True,
    'norEduPersonNIN': True,
    'o': True,
    'objectClass': True,
    'organizationName': True,
    'organizationalStatus': True,
    'organizationalUnitName': True,
    'otherMailbox': True,
    'ou': True,
    'owner': True,
    'pager': True,
    'pagerTelephoneNumber': True,
    'personalSignature': True,
    'personalTitle': True,
    'photo': True,
    'physicalDeliveryOfficeName': True,
    'pkcs9email': True,
    'postOfficeBox': True,
    'postalAddress': True,
    'postalCode': True,
    'preferredDeliveryMethod': True,
    'preferredLanguage': True,
    'presentationAddress': True,
    'protocolInformation': True,
    'pseudonym': True,
    'registeredAddress': True,
    'rfc822Mailbox': True,
    'roleOccupant': True,
    'roomNumber': True,
    'sOARecord': True,
    'searchGuide': True,
    'secretary': True,
    'seeAlso': True,
    'serialNumber': True,
    'singleLevelQuality': True,
    'sn': True,
    'st': True,
    'stateOrProvinceName': True,
    'street': True,
    'streetAddress': True,
    'subtreeMaximumQuality': True,
    'subtreeMinimumQuality': True,
    'supportedAlgorithms': True,
    'supportedApplicationContext': True,
    'surname': True,
    'telephoneNumber': True,
    'teletexTerminalIdentifier': True,
    'telexNumber': True,
    'textEncodedORAddress': True,
    'title': True,
    'uid': True,
    'uniqueIdentifier': True,
    'uniqueMember': True,
    'userCertificate': True,
    'userClass': True,
    'userPKCS12': True,
    'userPassword': True,
    'userSMIMECertificate': True,
    'userid': True,
    'x121Address': True,
    'x500UniqueIdentifier': True
}

OIDC_TO_SATOSA = {
    'sub': 'eduPersonTargetedID',
    'name': 'name',
    'given_name': 'givenName',
    'family_name': 'surname',
    'middle_name': None,
    'nickname': 'eduPersonNickname',
    'preferred_username': 'userid',
    'profile_string': '',  # URL of the End-User's profile page.
    'picture': None,  # URL of the End-User's profile picture.
    'website': None,  # URL of the End-User's Web page or blog.
    'email': 'email',
    'email_verified': None,  # boolean - True if the End-User's e-mail address is verified;
    'gender': None,  # End-User's gender.
    'birthdate': None,  # End-User's birthday
    'zoneinfo': None,  # time zone database representing the End-User's time zone.
    'locale': None,  # End-User's locale
    'phone_number': None,
    'phone_number_verified': None,
    'address': None,
    'updated_at': None  # Time the End-User's information was last updated.
}

SATOSA_TO_OIDC = dict((value, key) for key, value in OIDC_TO_SATOSA.items())

PYSAML_TO_SATOSA = {
    'aRecord': 'aRecord',
    'aliasedEntryName': 'aliasedEntryName',
    'aliasedObjectName': 'aliasedObjectName',
    'associatedDomain': 'associatedDomain',
    'associatedName': 'associatedName',
    'audio': 'audio',
    'authorityRevocationList': 'authorityRevocationList',
    'buildingName': 'buildingName',
    'businessCategory': 'businessCategory',
    'c': 'c',
    'cACertificate': 'cACertificate',
    'cNAMERecord': 'cNAMERecord',
    'carLicense': 'carLicense',
    'certificateRevocationList': 'certificateRevocationList',
    'cn': 'cn',
    'co': 'co',
    'commonName': 'commonName',
    'countryName': 'countryName',
    'crossCertificatePair': 'crossCertificatePair',
    'dITRedirect': 'dITRedirect',
    'dSAQuality': 'dSAQuality',
    'dc': 'dc',
    'deltaRevocationList': 'deltaRevocationList',
    'departmentNumber': 'departmentNumber',
    'description': 'description',
    'destinationIndicator': 'destinationIndicator',
    'displayName': 'displayName',
    'distinguishedName': 'distinguishedName',
    'dmdName': 'dmdName',
    'dnQualifier': 'dnQualifier',
    'documentAuthor': 'documentAuthor',
    'documentIdentifier': 'documentIdentifier',
    'documentLocation': 'documentLocation',
    'documentPublisher': 'documentPublisher',
    'documentTitle': 'documentTitle',
    'documentVersion': 'documentVersion',
    'domainComponent': 'domainComponent',
    'drink': 'drink',
    'eduOrgHomePageURI': 'eduOrgHomePageURI',
    'eduOrgIdentityAuthNPolicyURI': 'eduOrgIdentityAuthNPolicyURI',
    'eduOrgLegalName': 'eduOrgLegalName',
    'eduOrgSuperiorURI': 'eduOrgSuperiorURI',
    'eduOrgWhitePagesURI': 'eduOrgWhitePagesURI',
    'eduPersonAffiliation': 'eduPersonAffiliation',
    'eduPersonEntitlement': 'eduPersonEntitlement',
    'eduPersonNickname': 'eduPersonNickname',
    'eduPersonOrgDN': 'eduPersonOrgDN',
    'eduPersonOrgUnitDN': 'eduPersonOrgUnitDN',
    'eduPersonPrimaryAffiliation': 'eduPersonPrimaryAffiliation',
    'eduPersonPrimaryOrgUnitDN': 'eduPersonPrimaryOrgUnitDN',
    'eduPersonPrincipalName': 'eduPersonPrincipalName',
    'eduPersonScopedAffiliation': 'eduPersonScopedAffiliation',
    'eduPersonTargetedID': 'eduPersonTargetedID',
    'email': 'email',
    'emailAddress': 'emailAddress',
    'employeeNumber': 'employeeNumber',
    'employeeType': 'employeeType',
    'enhancedSearchGuide': 'enhancedSearchGuide',
    'facsimileTelephoneNumber': 'facsimileTelephoneNumber',
    'favouriteDrink': 'favouriteDrink',
    'fax': 'fax',
    'federationFeideSchemaVersion': 'federationFeideSchemaVersion',
    'friendlyCountryName': 'friendlyCountryName',
    'generationQualifier': 'generationQualifier',
    'givenName': 'givenName',
    'gn': 'gn',
    'homePhone': 'homePhone',
    'homePostalAddress': 'homePostalAddress',
    'homeTelephoneNumber': 'homeTelephoneNumber',
    'host': 'host',
    'houseIdentifier': 'houseIdentifier',
    'info': 'info',
    'initials': 'initials',
    'internationaliSDNNumber': 'internationaliSDNNumber',
    'janetMailbox': 'janetMailbox',
    'jpegPhoto': 'jpegPhoto',
    'knowledgeInformation': 'knowledgeInformation',
    'l': 'l',
    'labeledURI': 'labeledURI',
    'localityName': 'localityName',
    'mDRecord': 'mDRecord',
    'mXRecord': 'mXRecord',
    'mail': 'mail',
    'mailPreferenceOption': 'mailPreferenceOption',
    'manager': 'manager',
    'member': 'member',
    'mobile': 'mobile',
    'mobileTelephoneNumber': 'mobileTelephoneNumber',
    'nSRecord': 'nSRecord',
    'name': 'name',
    'norEduOrgAcronym': 'norEduOrgAcronym',
    'norEduOrgNIN': 'norEduOrgNIN',
    'norEduOrgSchemaVersion': 'norEduOrgSchemaVersion',
    'norEduOrgUniqueIdentifier': 'norEduOrgUniqueIdentifier',
    'norEduOrgUniqueNumber': 'norEduOrgUniqueNumber',
    'norEduOrgUnitUniqueIdentifier': 'norEduOrgUnitUniqueIdentifier',
    'norEduOrgUnitUniqueNumber': 'norEduOrgUnitUniqueNumber',
    'norEduPersonBirthDate': 'norEduPersonBirthDate',
    'norEduPersonLIN': 'norEduPersonLIN',
    'norEduPersonNIN': 'norEduPersonNIN',
    'o': 'o',
    'objectClass': 'objectClass',
    'organizationName': 'organizationName',
    'organizationalStatus': 'organizationalStatus',
    'organizationalUnitName': 'organizationalUnitName',
    'otherMailbox': 'otherMailbox',
    'ou': 'ou',
    'owner': 'owner',
    'pager': 'pager',
    'pagerTelephoneNumber': 'pagerTelephoneNumber',
    'personalSignature': 'personalSignature',
    'personalTitle': 'personalTitle',
    'photo': 'photo',
    'physicalDeliveryOfficeName': 'physicalDeliveryOfficeName',
    'pkcs9email': 'pkcs9email',
    'postOfficeBox': 'postOfficeBox',
    'postalAddress': 'postalAddress',
    'postalCode': 'postalCode',
    'preferredDeliveryMethod': 'preferredDeliveryMethod',
    'preferredLanguage': 'preferredLanguage',
    'presentationAddress': 'presentationAddress',
    'protocolInformation': 'protocolInformation',
    'pseudonym': 'pseudonym',
    'registeredAddress': 'registeredAddress',
    'rfc822Mailbox': 'rfc822Mailbox',
    'roleOccupant': 'roleOccupant',
    'roomNumber': 'roomNumber',
    'sOARecord': 'sOARecord',
    'searchGuide': 'searchGuide',
    'secretary': 'secretary',
    'seeAlso': 'seeAlso',
    'serialNumber': 'serialNumber',
    'singleLevelQuality': 'singleLevelQuality',
    'sn': 'sn',
    'st': 'st',
    'stateOrProvinceName': 'stateOrProvinceName',
    'street': 'street',
    'streetAddress': 'streetAddress',
    'subtreeMaximumQuality': 'subtreeMaximumQuality',
    'subtreeMinimumQuality': 'subtreeMinimumQuality',
    'supportedAlgorithms': 'supportedAlgorithms',
    'supportedApplicationContext': 'supportedApplicationContext',
    'surname': 'surname',
    'telephoneNumber': 'telephoneNumber',
    'teletexTerminalIdentifier': 'teletexTerminalIdentifier',
    'telexNumber': 'telexNumber',
    'textEncodedORAddress': 'textEncodedORAddress',
    'title': 'title',
    'uid': 'uid',
    'uniqueIdentifier': 'uniqueIdentifier',
    'uniqueMember': 'uniqueMember',
    'userCertificate': 'userCertificate',
    'userClass': 'userClass',
    'userPKCS12': 'userPKCS12',
    'userPassword': 'userPassword',
    'userSMIMECertificate': 'userSMIMECertificate',
    'userid': 'userid',
    'x121Address': 'x121Address',
    'x500UniqueIdentifier': 'x500UniqueIdentifier',
}

SATOSA_TO_PYSAML = dict((value, key) for key, value in PYSAML_TO_SATOSA.items())


class UserIdHashType(Enum):
    transient = 1
    persistent = 2
    pairwise = 2
    public = 3


class UserIdHasher():
    @staticmethod
    def save_state(internal_request, state):
        new_state = {"state": state,
                     "requestor": internal_request.requestor}
        return urlsafe_b64encode(json.dumps(new_state).encode("UTF-8")).decode("UTF-8")

    @staticmethod
    def set_id(salt, internal_response, state):
        state = json.loads(urlsafe_b64decode(state.encode("UTF-8")).decode("UTF-8"))
        requestor = state["requestor"]
        user_id = internal_response.user_id
        user_id_hash_type = internal_response.user_id_hash_type

        if user_id_hash_type == UserIdHashType.transient:
            timestamp = datetime.datetime.now().time()
            user_id = "{req}{time}{id}".format(req=requestor, time=timestamp, id=user_id)
        elif user_id_hash_type == UserIdHashType.persistent:
            user_id = "{req}{id}".format(req=requestor, id=user_id)
        elif user_id_hash_type == UserIdHashType.pairwise:
            user_id = "{req}{id}".format(req=requestor, id=user_id)
        elif user_id_hash_type == UserIdHashType.public:
            user_id = "{id}".format(id=user_id)
        else:
            raise ValueError("Unknown id hash type: '{}'".format(user_id_hash_type))

        user_id += salt
        internal_response.user_id = hashlib.sha256(user_id.encode("utf-8")).hexdigest()

        return (internal_response, state["state"])


class AuthenticationInformation(object):
    def __init__(self, auth_class_ref, timestamp, issuer):
        self.auth_class_ref = auth_class_ref
        self.timestamp = timestamp
        self.issuer = issuer


class InternalData(object):
    def __init__(self, user_id_hash_type):
        self.user_id_hash_type = user_id_hash_type


class InternalRequest(InternalData):
    def __init__(self, user_id_hash_type, requestor):
        """

        :param user_id_hash_type:
        :param requestor: identifier of the requestor

        :type user_id_hash_type: UserIdHashType
        :type requestor: str
        """
        super(InternalRequest, self).__init__(user_id_hash_type)
        self.requestor = requestor


class InternalResponse(InternalData):
    """
    Holds internal representation of service related data.

    :param _attributes: This dict is a data carrier between frontend and backend modules.

    :type _user_id: str
    :type _attributes: dict[str, str]
    :type user_id_hash_type: UserIdHashType
    :type internal_attributes: dict[str, str]
    :type auth_info: AuthenticationInformation
    """

    def __init__(self, user_id_hash_type, internal_attributes=SATOSA_ATTRIBUTES, auth_info=None):
        super(InternalResponse, self).__init__(user_id_hash_type)
        self._user_id = None
        self._attributes = {}
        self.internal_attributes = internal_attributes
        self.auth_info = auth_info

    def add_pysaml_attributes(self, dict):
        """
        :type dict: dict[str, str]
        :param dict:
        :return:
        """
        self.add_attributes(PYSAML_TO_SATOSA, dict)

    def get_pysaml_attributes(self):
        return self.get_attributes(SATOSA_TO_PYSAML)

    def get_attributes(self, map):
        attributes = {}
        for s_key in self._attributes:
            if (s_key in map and s_key in self.internal_attributes and
                    self.internal_attributes[s_key]):
                attributes[SATOSA_TO_PYSAML[s_key]] = self._attributes[s_key]
        return attributes

    def add_attributes(self, map, dict):
        """
        :type dict: dict[str, str]
        :param dict:
        :return:
        """
        attributes = {}
        for key in dict:
            if key in map:
                s_key = map[key]
                if s_key in self.internal_attributes and self.internal_attributes[s_key]:
                    self._attributes[s_key] = dict[key]

    @property
    def user_id(self):
        """
        Get the user identification.

        :rtype: str

        :return: User identification.
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        if not user_id:
            raise ValueError("user_id can't be set to None")
        elif user_id.startswith('/'):
            raise ValueError("user_id can't start with '/'")
        self._user_id = user_id
