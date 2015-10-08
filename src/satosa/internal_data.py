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
    'arecord': True,
    'aliasedentryname': True,
    'aliasedobjectname': True,
    'associateddomain': True,
    'associatedname': True,
    'audio': True,
    'authorityrevocationlist': True,
    'buildingname': True,
    'businesscategory': True,
    'c': True,
    'cacertificate': True,
    'cnamerecord': True,
    'carlicense': True,
    'certificaterevocationlist': True,
    'cn': True,
    'co': True,
    'commonname': True,
    'countryname': True,
    'crosscertificatepair': True,
    'ditredirect': True,
    'dsaquality': True,
    'dc': True,
    'deltarevocationlist': True,
    'departmentnumber': True,
    'description': True,
    'destinationindicator': True,
    'displayname': True,
    'distinguishedname': True,
    'dmdname': True,
    'dnqualifier': True,
    'documentauthor': True,
    'documentidentifier': True,
    'documentlocation': True,
    'documentpublisher': True,
    'documenttitle': True,
    'documentversion': True,
    'domaincomponent': True,
    'drink': True,
    'eduorghomepageuri': True,
    'eduorgidentityauthnpolicyuri': True,
    'eduorglegalname': True,
    'eduorgsuperioruri': True,
    'eduorgwhitepagesuri': True,
    'edupersonaffiliation': True,
    'edupersonentitlement': True,
    'edupersonnickname': True,
    'edupersonorgdn': True,
    'edupersonorgunitdn': True,
    'edupersonprimaryaffiliation': True,
    'edupersonprimaryorgunitdn': True,
    'edupersonprincipalname': True,
    'edupersonscopedaffiliation': True,
    'edupersontargetedid': True,
    'email': True,
    'emailaddress': True,
    'employeenumber': True,
    'employeetype': True,
    'enhancedsearchguide': True,
    'facsimiletelephonenumber': True,
    'favouritedrink': True,
    'fax': True,
    'federationfeideschemaversion': True,
    'friendlycountryname': True,
    'generationqualifier': True,
    'givenname': True,
    'gn': True,
    'homephone': True,
    'homepostaladdress': True,
    'hometelephonenumber': True,
    'host': True,
    'houseidentifier': True,
    'info': True,
    'initials': True,
    'internationalisdnnumber': True,
    'janetmailbox': True,
    'jpegphoto': True,
    'knowledgeinformation': True,
    'l': True,
    'labeleduri': True,
    'localityname': True,
    'mdrecord': True,
    'mxrecord': True,
    'mail': True,
    'mailpreferenceoption': True,
    'manager': True,
    'member': True,
    'mobile': True,
    'mobiletelephonenumber': True,
    'nsrecord': True,
    'name': True,
    'noreduorgacronym': True,
    'noreduorgnin': True,
    'noreduorgschemaversion': True,
    'noreduorguniqueidentifier': True,
    'noreduorguniquenumber': True,
    'noreduorgunituniqueidentifier': True,
    'noreduorgunituniquenumber': True,
    'noredupersonbirthdate': True,
    'noredupersonlin': True,
    'noredupersonnin': True,
    'o': True,
    'objectclass': True,
    'organizationname': True,
    'organizationalstatus': True,
    'organizationalunitname': True,
    'othermailbox': True,
    'ou': True,
    'owner': True,
    'pager': True,
    'pagertelephonenumber': True,
    'personalsignature': True,
    'personaltitle': True,
    'photo': True,
    'physicaldeliveryofficename': True,
    'pkcs9email': True,
    'postofficebox': True,
    'postaladdress': True,
    'postalcode': True,
    'preferreddeliverymethod': True,
    'preferredlanguage': True,
    'presentationaddress': True,
    'protocolinformation': True,
    'pseudonym': True,
    'registeredaddress': True,
    'rfc822mailbox': True,
    'roleoccupant': True,
    'roomnumber': True,
    'soarecord': True,
    'searchguide': True,
    'secretary': True,
    'seealso': True,
    'serialnumber': True,
    'singlelevelquality': True,
    'sn': True,
    'st': True,
    'stateorprovincename': True,
    'street': True,
    'streetaddress': True,
    'subtreemaximumquality': True,
    'subtreeminimumquality': True,
    'supportedalgorithms': True,
    'supportedapplicationcontext': True,
    'surname': True,
    'telephonenumber': True,
    'teletexterminalidentifier': True,
    'telexnumber': True,
    'textencodedoraddress': True,
    'title': True,
    'uid': True,
    'uniqueidentifier': True,
    'uniquemember': True,
    'usercertificate': True,
    'userclass': True,
    'userpkcs12': True,
    'userpassword': True,
    'usersmimecertificate': True,
    'userid': True,
    'x121address': True,
    'x500uniqueidentifier': True
}

OIDC_TO_SATOSA = {
    'sub': 'edupersontargetedid',
    'name': 'name',
    'given_name': 'givenname',
    'family_name': 'surname',
    'middle_name': None,
    'nickname': 'edupersonnickname',
    'preferred_username': 'userid',
    'profile_string': '',  # url of the end-user's profile page.
    'picture': None,  # url of the end-user's profile picture.
    'website': None,  # url of the end-user's web page or blog.
    'email': 'email',
    'email_verified': None,  # boolean - true if the end-user's e-mail address is verified;
    'gender': None,  # end-user's gender.
    'birthdate': None,  # end-user's birthday
    'zoneinfo': None,  # time zone database representing the end-user's time zone.
    'locale': None,  # end-user's locale
    'phone_number': None,
    'phone_number_verified': None,
    'address': None,
    'updated_at': None  # time the end-user's information was last updated.
}

SATOSA_TO_OIDC = dict((value, key) for key, value in OIDC_TO_SATOSA.items())

PYSAML_TO_SATOSA = {
    'arecord': 'arecord',
    'aliasedentryname': 'aliasedentryname',
    'aliasedobjectname': 'aliasedobjectname',
    'associateddomain': 'associateddomain',
    'associatedname': 'associatedname',
    'audio': 'audio',
    'authorityrevocationlist': 'authorityrevocationlist',
    'buildingname': 'buildingname',
    'businesscategory': 'businesscategory',
    'c': 'c',
    'cacertificate': 'cacertificate',
    'cnamerecord': 'cnamerecord',
    'carlicense': 'carlicense',
    'certificaterevocationlist': 'certificaterevocationlist',
    'cn': 'cn',
    'co': 'co',
    'commonname': 'commonname',
    'countryname': 'countryname',
    'crosscertificatepair': 'crosscertificatepair',
    'ditredirect': 'ditredirect',
    'dsaquality': 'dsaquality',
    'dc': 'dc',
    'deltarevocationlist': 'deltarevocationlist',
    'departmentnumber': 'departmentnumber',
    'description': 'description',
    'destinationindicator': 'destinationindicator',
    'displayname': 'displayname',
    'distinguishedname': 'distinguishedname',
    'dmdname': 'dmdname',
    'dnqualifier': 'dnqualifier',
    'documentauthor': 'documentauthor',
    'documentidentifier': 'documentidentifier',
    'documentlocation': 'documentlocation',
    'documentpublisher': 'documentpublisher',
    'documenttitle': 'documenttitle',
    'documentversion': 'documentversion',
    'domaincomponent': 'domaincomponent',
    'drink': 'drink',
    'eduorghomepageuri': 'eduorghomepageuri',
    'eduorgidentityauthnpolicyuri': 'eduorgidentityauthnpolicyuri',
    'eduorglegalname': 'eduorglegalname',
    'eduorgsuperioruri': 'eduorgsuperioruri',
    'eduorgwhitepagesuri': 'eduorgwhitepagesuri',
    'edupersonaffiliation': 'edupersonaffiliation',
    'edupersonentitlement': 'edupersonentitlement',
    'edupersonnickname': 'edupersonnickname',
    'edupersonorgdn': 'edupersonorgdn',
    'edupersonorgunitdn': 'edupersonorgunitdn',
    'edupersonprimaryaffiliation': 'edupersonprimaryaffiliation',
    'edupersonprimaryorgunitdn': 'edupersonprimaryorgunitdn',
    'edupersonprincipalname': 'edupersonprincipalname',
    'edupersonscopedaffiliation': 'edupersonscopedaffiliation',
    'edupersontargetedid': 'edupersontargetedid',
    'email': 'email',
    'emailaddress': 'emailaddress',
    'employeenumber': 'employeenumber',
    'employeetype': 'employeetype',
    'enhancedsearchguide': 'enhancedsearchguide',
    'facsimiletelephonenumber': 'facsimiletelephonenumber',
    'favouritedrink': 'favouritedrink',
    'fax': 'fax',
    'federationfeideschemaversion': 'federationfeideschemaversion',
    'friendlycountryname': 'friendlycountryname',
    'generationqualifier': 'generationqualifier',
    'givenname': 'givenname',
    'gn': 'gn',
    'homephone': 'homephone',
    'homepostaladdress': 'homepostaladdress',
    'hometelephonenumber': 'hometelephonenumber',
    'host': 'host',
    'houseidentifier': 'houseidentifier',
    'info': 'info',
    'initials': 'initials',
    'internationalisdnnumber': 'internationalisdnnumber',
    'janetmailbox': 'janetmailbox',
    'jpegphoto': 'jpegphoto',
    'knowledgeinformation': 'knowledgeinformation',
    'l': 'l',
    'labeleduri': 'labeleduri',
    'localityname': 'localityname',
    'mdrecord': 'mdrecord',
    'mxrecord': 'mxrecord',
    'mail': 'mail',
    'mailpreferenceoption': 'mailpreferenceoption',
    'manager': 'manager',
    'member': 'member',
    'mobile': 'mobile',
    'mobiletelephonenumber': 'mobiletelephonenumber',
    'nsrecord': 'nsrecord',
    'name': 'name',
    'noreduorgacronym': 'noreduorgacronym',
    'noreduorgnin': 'noreduorgnin',
    'noreduorgschemaversion': 'noreduorgschemaversion',
    'noreduorguniqueidentifier': 'noreduorguniqueidentifier',
    'noreduorguniquenumber': 'noreduorguniquenumber',
    'noreduorgunituniqueidentifier': 'noreduorgunituniqueidentifier',
    'noreduorgunituniquenumber': 'noreduorgunituniquenumber',
    'noredupersonbirthdate': 'noredupersonbirthdate',
    'noredupersonlin': 'noredupersonlin',
    'noredupersonnin': 'noredupersonnin',
    'o': 'o',
    'objectclass': 'objectclass',
    'organizationname': 'organizationname',
    'organizationalstatus': 'organizationalstatus',
    'organizationalunitname': 'organizationalunitname',
    'othermailbox': 'othermailbox',
    'ou': 'ou',
    'owner': 'owner',
    'pager': 'pager',
    'pagertelephonenumber': 'pagertelephonenumber',
    'personalsignature': 'personalsignature',
    'personaltitle': 'personaltitle',
    'photo': 'photo',
    'physicaldeliveryofficename': 'physicaldeliveryofficename',
    'pkcs9email': 'pkcs9email',
    'postofficebox': 'postofficebox',
    'postaladdress': 'postaladdress',
    'postalcode': 'postalcode',
    'preferreddeliverymethod': 'preferreddeliverymethod',
    'preferredlanguage': 'preferredlanguage',
    'presentationaddress': 'presentationaddress',
    'protocolinformation': 'protocolinformation',
    'pseudonym': 'pseudonym',
    'registeredaddress': 'registeredaddress',
    'rfc822mailbox': 'rfc822mailbox',
    'roleoccupant': 'roleoccupant',
    'roomnumber': 'roomnumber',
    'soarecord': 'soarecord',
    'searchguide': 'searchguide',
    'secretary': 'secretary',
    'seealso': 'seealso',
    'serialnumber': 'serialnumber',
    'singlelevelquality': 'singlelevelquality',
    'sn': 'sn',
    'st': 'st',
    'stateorprovincename': 'stateorprovincename',
    'street': 'street',
    'streetaddress': 'streetaddress',
    'subtreemaximumquality': 'subtreemaximumquality',
    'subtreeminimumquality': 'subtreeminimumquality',
    'supportedalgorithms': 'supportedalgorithms',
    'supportedapplicationcontext': 'supportedapplicationcontext',
    'surname': 'surname',
    'telephonenumber': 'telephonenumber',
    'teletexterminalidentifier': 'teletexterminalidentifier',
    'telexnumber': 'telexnumber',
    'textencodedoraddress': 'textencodedoraddress',
    'title': 'title',
    'uid': 'uid',
    'uniqueidentifier': 'uniqueidentifier',
    'uniquemember': 'uniquemember',
    'usercertificate': 'usercertificate',
    'userclass': 'userclass',
    'userpkcs12': 'userpkcs12',
    'userpassword': 'userpassword',
    'usersmimecertificate': 'usersmimecertificate',
    'userid': 'userid',
    'x121address': 'x121address',
    'x500uniqueidentifier': 'x500uniqueidentifier',
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
        self._attribute_filter = []

    def add_pysaml_attr_filter(self, filter_attr):
        self.add_filter(PYSAML_TO_SATOSA, filter_attr)

    def add_filter(self, map, filter_attr):
        for attr in filter_attr:
            try:
                self._attribute_filter.append(map[attr])
            except KeyError:
                self._attribute_filter.append(attr)

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
            lower_key = key.lower()
            if lower_key in map:
                s_key = map[lower_key]
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
