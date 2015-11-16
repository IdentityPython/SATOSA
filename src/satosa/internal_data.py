"""
The module contains internal data representation in SATOSA and general converteras that can be used
for converting from SAML/OAuth/OpenID connect to the internal representation.
"""
import datetime
from enum import Enum
import hashlib
import json

__author__ = 'haho0032'
#
# SATOSA_ATTRIBUTES = {
#     'arecord': True,
#     'aliasedentryname': True,
#     'aliasedobjectname': True,
#     'associateddomain': True,
#     'associatedname': True,
#     'audio': True,
#     'authorityrevocationlist': True,
#     'buildingname': True,
#     'businesscategory': True,
#     'c': True,
#     'cacertificate': True,
#     'cnamerecord': True,
#     'carlicense': True,
#     'certificaterevocationlist': True,
#     'cn': True,
#     'co': True,
#     'commonname': True,
#     'countryname': True,
#     'crosscertificatepair': True,
#     'ditredirect': True,
#     'dsaquality': True,
#     'dc': True,
#     'deltarevocationlist': True,
#     'departmentnumber': True,
#     'description': True,
#     'destinationindicator': True,
#     'displayname': True,
#     'distinguishedname': True,
#     'dmdname': True,
#     'dnqualifier': True,
#     'documentauthor': True,
#     'documentidentifier': True,
#     'documentlocation': True,
#     'documentpublisher': True,
#     'documenttitle': True,
#     'documentversion': True,
#     'domaincomponent': True,
#     'drink': True,
#     'eduorghomepageuri': True,
#     'eduorgidentityauthnpolicyuri': True,
#     'eduorglegalname': True,
#     'eduorgsuperioruri': True,
#     'eduorgwhitepagesuri': True,
#     'edupersonaffiliation': True,
#     'edupersonentitlement': True,
#     'edupersonnickname': True,
#     'edupersonorgdn': True,
#     'edupersonorgunitdn': True,
#     'edupersonprimaryaffiliation': True,
#     'edupersonprimaryorgunitdn': True,
#     'edupersonprincipalname': True,
#     'edupersonscopedaffiliation': True,
#     'edupersontargetedid': True,
#     'email': True,
#     'emailaddress': True,
#     'employeenumber': True,
#     'employeetype': True,
#     'enhancedsearchguide': True,
#     'facsimiletelephonenumber': True,
#     'favouritedrink': True,
#     'fax': True,
#     'federationfeideschemaversion': True,
#     'friendlycountryname': True,
#     'generationqualifier': True,
#     'givenname': True,
#     'gn': True,
#     'homephone': True,
#     'homepostaladdress': True,
#     'hometelephonenumber': True,
#     'host': True,
#     'houseidentifier': True,
#     'info': True,
#     'initials': True,
#     'internationalisdnnumber': True,
#     'janetmailbox': True,
#     'jpegphoto': True,
#     'knowledgeinformation': True,
#     'l': True,
#     'labeleduri': True,
#     'localityname': True,
#     'mdrecord': True,
#     'mxrecord': True,
#     'mail': True,
#     'mailpreferenceoption': True,
#     'manager': True,
#     'member': True,
#     'mobile': True,
#     'mobiletelephonenumber': True,
#     'nsrecord': True,
#     'name': True,
#     'noreduorgacronym': True,
#     'noreduorgnin': True,
#     'noreduorgschemaversion': True,
#     'noreduorguniqueidentifier': True,
#     'noreduorguniquenumber': True,
#     'noreduorgunituniqueidentifier': True,
#     'noreduorgunituniquenumber': True,
#     'noredupersonbirthdate': True,
#     'noredupersonlin': True,
#     'noredupersonnin': True,
#     'o': True,
#     'objectclass': True,
#     'osihomeurl': True,
#     'osimiddlename': True,
#     'osiotheremail': True,
#     'osiotherhomephone': True,
#     'osiworkurl': True,
#     'osiicardtimelastupdated': True,
#     'osipreferredtimezone': True,
#     'organizationname': True,
#     'organizationalstatus': True,
#     'organizationalunitname': True,
#     'othermailbox': True,
#     'ou': True,
#     'owner': True,
#     'pager': True,
#     'pagertelephonenumber': True,
#     'personalsignature': True,
#     'personaltitle': True,
#     'photo': True,
#     'physicaldeliveryofficename': True,
#     'pkcs9email': True,
#     'postofficebox': True,
#     'postaladdress': True,
#     'postalcode': True,
#     'preferreddeliverymethod': True,
#     'preferredlanguage': True,
#     'presentationaddress': True,
#     'protocolinformation': True,
#     'pseudonym': True,
#     'registeredaddress': True,
#     'rfc822mailbox': True,
#     'roleoccupant': True,
#     'roomnumber': True,
#     'schacgender': True,
#     'schacdateofbirth': True,
#     'soarecord': True,
#     'searchguide': True,
#     'secretary': True,
#     'seealso': True,
#     'serialnumber': True,
#     'singlelevelquality': True,
#     'sn': True,
#     'st': True,
#     'stateorprovincename': True,
#     'street': True,
#     'streetaddress': True,
#     'subtreemaximumquality': True,
#     'subtreeminimumquality': True,
#     'supportedalgorithms': True,
#     'supportedapplicationcontext': True,
#     'surname': True,
#     'telephonenumber': True,
#     'teletexterminalidentifier': True,
#     'telexnumber': True,
#     'textencodedoraddress': True,
#     'title': True,
#     'uid': True,
#     'uniqueidentifier': True,
#     'uniquemember': True,
#     'usercertificate': True,
#     'userclass': True,
#     'userpkcs12': True,
#     'userpassword': True,
#     'usersmimecertificate': True,
#     'userid': True,
#     'x121address': True,
#     'x500uniqueidentifier': True
# }
#
# OIDC_TO_SATOSA = {
#     'sub': 'edupersontargetedid',
#     'name': 'name',
#     'given_name': 'givenname',
#     'family_name': 'surname',
#     'middle_name': 'osimiddlename',
#     'nickname': 'edupersonnickname',
#     'preferred_username': 'userid',
#     'profile_string': 'osihomeurl',
#     'picture': 'jpegphoto',
#     'website': 'osiworkurl',
#     'email': 'mail',
#     'email_verified': 'osiotheremail',
#     'gender': 'schacgender',
#     'birthdate': 'schacdateofbirth',
#     'zoneinfo': 'osipreferredtimezone',
#     'locale': 'preferredlanguage',
#     'phone_number': 'hometelephonenumber',
#     'phone_number_verified': 'osiotherhomephone',
#     'address': 'postaladdress',
#     'updated_at': 'osiicardtimelastupdated'
# }
#
# SATOSA_TO_OIDC = dict((value, key) for key, value in OIDC_TO_SATOSA.items())
#
# PYSAML_TO_SATOSA = {
#     'aRecord': 'arecord',
#     'aliasedEntryName': 'aliasedentryname',
#     'aliasedObjectName': 'aliasedobjectname',
#     'associatedDomain': 'associateddomain',
#     'associatedName': 'associatedname',
#     'audio': 'audio',
#     'authorityRevocationList': 'authorityrevocationlist',
#     'buildingName': 'buildingname',
#     'businessCategory': 'businesscategory',
#     'c': 'c',
#     'cACertificate': 'cacertificate',
#     'cNAMERecord': 'cnamerecord',
#     'carLicense': 'carlicense',
#     'certificateRevocationList': 'certificaterevocationlist',
#     'cn': 'cn',
#     'co': 'co',
#     'commonName': 'commonname',
#     'countryName': 'countryname',
#     'crossCertificatePair': 'crosscertificatepair',
#     'dITRedirect': 'ditredirect',
#     'dSAQuality': 'dsaquality',
#     'dc': 'dc',
#     'deltaRevocationList': 'deltarevocationlist',
#     'departmentNumber': 'departmentnumber',
#     'description': 'description',
#     'destinationIndicator': 'destinationindicator',
#     'displayName': 'displayname',
#     'distinguishedName': 'distinguishedname',
#     'dmdName': 'dmdname',
#     'dnQualifier': 'dnqualifier',
#     'documentAuthor': 'documentauthor',
#     'documentIdentifier': 'documentidentifier',
#     'documentLocation': 'documentlocation',
#     'documentPublisher': 'documentpublisher',
#     'documentTitle': 'documenttitle',
#     'documentVersion': 'documentversion',
#     'domainComponent': 'domaincomponent',
#     'drink': 'drink',
#     'eduOrgHomePageURI': 'eduorghomepageuri',
#     'eduOrgIdentityAuthNPolicyURI': 'eduorgidentityauthnpolicyuri',
#     'eduOrgLegalName': 'eduorglegalname',
#     'eduOrgSuperiorURI': 'eduorgsuperioruri',
#     'eduOrgWhitePagesURI': 'eduorgwhitepagesuri',
#     'eduPersonAffiliation': 'edupersonaffiliation',
#     'eduPersonEntitlement': 'edupersonentitlement',
#     'eduPersonNickname': 'edupersonnickname',
#     'eduPersonOrgDN': 'edupersonorgdn',
#     'eduPersonOrgUnitDN': 'edupersonorgunitdn',
#     'eduPersonPrimaryAffiliation': 'edupersonprimaryaffiliation',
#     'eduPersonPrimaryOrgUnitDN': 'edupersonprimaryorgunitdn',
#     'eduPersonPrincipalName': 'edupersonprincipalname',
#     'eduPersonScopedAffiliation': 'edupersonscopedaffiliation',
#     'eduPersonTargetedID': 'edupersontargetedid',
#     'email': 'email',
#     'emailAddress': 'emailaddress',
#     'employeeNumber': 'employeenumber',
#     'employeeType': 'employeetype',
#     'enhancedSearchGuide': 'enhancedsearchguide',
#     'facsimileTelephoneNumber': 'facsimiletelephonenumber',
#     'favouriteDrink': 'favouritedrink',
#     'fax': 'fax',
#     'federationFeideSchemaVersion': 'federationfeideschemaversion',
#     'friendlyCountryName': 'friendlycountryname',
#     'generationQualifier': 'generationqualifier',
#     'givenName': 'givenname',
#     'gn': 'gn',
#     'homePhone': 'homephone',
#     'homePostalAddress': 'homepostaladdress',
#     'homeTelephoneNumber': 'hometelephonenumber',
#     'host': 'host',
#     'houseIdentifier': 'houseidentifier',
#     'info': 'info',
#     'initials': 'initials',
#     'internationaliSDNNumber': 'internationalisdnnumber',
#     'janetMailbox': 'janetmailbox',
#     'jpegPhoto': 'jpegphoto',
#     'knowledgeInformation': 'knowledgeinformation',
#     'l': 'l',
#     'labeledURI': 'labeleduri',
#     'localityName': 'localityname',
#     'mDRecord': 'mdrecord',
#     'mXRecord': 'mxrecord',
#     'mail': 'mail',
#     'mailPreferenceOption': 'mailpreferenceoption',
#     'manager': 'manager',
#     'member': 'member',
#     'mobile': 'mobile',
#     'mobileTelephoneNumber': 'mobiletelephonenumber',
#     'nSRecord': 'nsrecord',
#     'name': 'name',
#     'norEduOrgAcronym': 'noreduorgacronym',
#     'norEduOrgNIN': 'noreduorgnin',
#     'norEduOrgSchemaVersion': 'noreduorgschemaversion',
#     'norEduOrgUniqueIdentifier': 'noreduorguniqueidentifier',
#     'norEduOrgUniqueNumber': 'noreduorguniquenumber',
#     'norEduOrgUnitUniqueIdentifier': 'noreduorgunituniqueidentifier',
#     'norEduOrgUnitUniqueNumber': 'noreduorgunituniquenumber',
#     'norEduPersonBirthDate': 'noredupersonbirthdate',
#     'norEduPersonLIN': 'noredupersonlin',
#     'norEduPersonNIN': 'noredupersonnin',
#     'o': 'o',
#     'objectclass': 'objectclass',
#     'osihomeurl': 'osihomeurl',
#     'osimiddlename': 'osimiddlename',
#     'osiotheremail': 'osiotheremail',
#     'osiotherhomephone': 'osiotherhomephone',
#     'osiworkurl': 'osiworkurl',
#     'organizationname': 'organizationname',
#     'organizationalstatus': 'organizationalstatus',
#     'organizationalunitname': 'organizationalunitname',
#     'otherMailbox': 'othermailbox',
#     'ou': 'ou',
#     'owner': 'owner',
#     'pager': 'pager',
#     'pagerTelephoneNumber': 'pagertelephonenumber',
#     'personalSignature': 'personalsignature',
#     'personalTitle': 'personaltitle',
#     'photo': 'photo',
#     'physicalDeliveryOfficeName': 'physicaldeliveryofficename',
#     'pkcs9email': 'pkcs9email',
#     'postOfficeBox': 'postofficebox',
#     'postalAddress': 'postaladdress',
#     'postalCode': 'postalcode',
#     'preferredDeliveryMethod': 'preferreddeliverymethod',
#     'preferredLanguage': 'preferredlanguage',
#     'presentationAddress': 'presentationaddress',
#     'protocolInformation': 'protocolinformation',
#     'pseudonym': 'pseudonym',
#     'registeredAddress': 'registeredaddress',
#     'rfc822Mailbox': 'rfc822mailbox',
#     'roleOccupant': 'roleoccupant',
#     'roomNumber': 'roomnumber',
#     'schacgender': 'schacgender',
#     'schacdateofbirth': 'schacdateofbirth',
#     'sOARecord': 'soarecord',
#     'searchGuide': 'searchguide',
#     'secretary': 'secretary',
#     'seeAlso': 'seealso',
#     'serialNumber': 'serialnumber',
#     'singleLevelQuality': 'singlelevelquality',
#     'sn': 'sn',
#     'st': 'st',
#     'stateOrProvinceName': 'stateorprovincename',
#     'street': 'street',
#     'streetAddress': 'streetaddress',
#     'subtreeMaximumQuality': 'subtreemaximumquality',
#     'subtreeMinimumQuality': 'subtreeminimumquality',
#     'supportedAlgorithms': 'supportedalgorithms',
#     'supportedApplicationContext': 'supportedapplicationcontext',
#     'surname': 'surname',
#     'telephoneNumber': 'telephonenumber',
#     'teletexTerminalIdentifier': 'teletexterminalidentifier',
#     'telexNumber': 'telexnumber',
#     'textEncodedORAddress': 'textencodedoraddress',
#     'title': 'title',
#     'uid': 'uid',
#     'uniqueIdentifier': 'uniqueidentifier',
#     'uniqueMember': 'uniquemember',
#     'userCertificate': 'usercertificate',
#     'userClass': 'userclass',
#     'userPKCS12': 'userpkcs12',
#     'userPassword': 'userpassword',
#     'userSMIMECertificate': 'usersmimecertificate',
#     'userid': 'userid',
#     'x121Address': 'x121address',
#     'x500UniqueIdentifier': 'x500uniqueidentifier',
# }
#
# SATOSA_TO_PYSAML = dict((value, key) for key, value in PYSAML_TO_SATOSA.items())


class DataConverter(object):
    def __init__(self, internal_attributes):
        self.to_internal_attributes = {}
        self.to_internal_attributes_lower = {}
        self.separator = internal_attributes["separator"]
        self.from_internal_attributes = internal_attributes["attributes"]
        for internal_key in self.from_internal_attributes:
            for type in self.from_internal_attributes[internal_key]:
                if type not in self.to_internal_attributes:
                    self.to_internal_attributes[type] = {}
                    self.to_internal_attributes_lower[type] = {}
                for external_key in self.from_internal_attributes[internal_key][type]:
                    self.to_internal_attributes[type][external_key] = internal_key
                    self.to_internal_attributes_lower[type][external_key.lower()] = internal_key

    def to_internal_filter(self, type, external_keys, case_insensitive=False):
        internal_keys = []
        for external_key in external_keys:
            if external_key in self.to_internal_attributes[type] or \
                    (case_insensitive and external_key in self.to_internal_attributes_lower[type]):
                if case_insensitive:
                    internal_key = self.to_internal_attributes_lower[type][external_key]
                else:
                    internal_key = self.to_internal_attributes[type][external_key]
                if internal_key not in internal_keys:
                    internal_keys.append(internal_key)
        return internal_keys

    def _get_attr_value_key(self, my_key, my_dict):
        tmp_attributes = {}
        for tmp_key in my_dict:
            new_key = "%s%s%s" % (my_key, self.separator, tmp_key)
            if isinstance(my_dict[tmp_key], dict):
                tmp_attributes.update(self._get_attr_value_key(new_key, my_dict[tmp_key]))
            else:
                tmp_attributes[new_key] = my_dict[tmp_key]
        return tmp_attributes

    def to_internal(self, type, external_dict):
        internal_dict = {}
        for external_key in external_dict.keys():
            if isinstance(external_dict[external_key], dict):
                if external_key in self.to_internal_attributes[type]:
                    internal_key = self.to_internal_attributes[type][external_key]
                    if internal_key not in internal_dict:
                        internal_dict[internal_key] = []
                    internal_dict[internal_key].append(json.dumps(external_dict[external_key]))
                else:
                    internal_dict.update(self.to_internal(type, self._get_attr_value_key(external_key, external_dict[external_key])))
            elif external_key in self.to_internal_attributes[type]:
                internal_key = self.to_internal_attributes[type][external_key]
                if internal_key not in internal_dict:
                    internal_dict[internal_key] = []
                if isinstance(external_dict[external_key], list):
                    internal_dict[internal_key] += external_dict[external_key]
                else:
                    internal_dict[internal_key].append(external_dict[external_key])
        return internal_dict

    def from_internal(self, type, internal_dict, list=True, external_keys=None):
        external_dict = {}
        for internal_key in internal_dict:
            if internal_key in self.from_internal_attributes:
                _external_keys = self.from_internal_attributes[internal_key][type]
                if _external_keys:
                    _external_key = None
                    if external_keys:
                        for _external_key in _external_keys:
                            if _external_key in external_keys:
                                break
                    if _external_key is None:
                        _external_key = _external_keys[0]
                    _external_dict = external_dict
                    if self.separator in _external_key:
                        _tmp_keys = _external_key.split(self.separator)
                        for _tmp_key in _tmp_keys:
                            if _tmp_key not in _external_dict:
                                _external_dict[_tmp_key] = {}
                            _external_dict = _external_dict[_tmp_key]
                    if list:
                        _external_dict[_external_key] = internal_dict[internal_key]
                    else:
                        if internal_dict[internal_key]:
                            _external_dict[_external_key] = internal_dict[internal_key][0]
        return external_dict


class UserIdHashType(Enum):
    transient = 1
    persistent = 2
    pairwise = 2
    public = 3


class UserIdHasher():
    STATE_KEY = "IDHASHER"

    @staticmethod
    def save_state(internal_request, state):
        state.add(UserIdHasher.STATE_KEY, internal_request.requestor)

    @staticmethod
    def set_id(salt, internal_response, state):
        requestor = state.get(UserIdHasher.STATE_KEY)
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

        return internal_response


class AuthenticationInformation(object):
    def __init__(self, auth_class_ref, timestamp, issuer):
        self.auth_class_ref = auth_class_ref
        self.timestamp = timestamp
        self.issuer = issuer


class InternalData(object):
    def __init__(self, user_id_hash_type):
        self.user_id_hash_type = user_id_hash_type


class InternalRequest(InternalData):
    def __init__(self, user_id_hash_type, requestor, requester_name=None):
        """

        :param user_id_hash_type:
        :param requestor: identifier of the requestor

        :type user_id_hash_type: UserIdHashType
        :type requestor: str
        """
        super(InternalRequest, self).__init__(user_id_hash_type)
        self.requestor = requestor
        if requester_name:  # TODO do you need to validate this?
            self.requester_name = requester_name
        else:
            self.requester_name = [{"text": requestor, "lang": "en"}]
        self._attribute_filter = []

    # def add_pysaml_attr_filter(self, filter_attr):
    #     self.add_filter(PYSAML_TO_SATOSA, filter_attr)

    def add_filter(self, filter_attr):
        self._attribute_filter = filter_attr


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

    def __init__(self, user_id_hash_type, auth_info=None):
        super(InternalResponse, self).__init__(user_id_hash_type)
        self._user_id = None
        self._attributes = {}
        self.auth_info = auth_info

    def get_attributes(self):
        return self._attributes

    def add_attributes(self, dict):
        """
        :type dict: dict[str, str]
        :param dict:
        :return:
        """
        self._attributes= dict

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
