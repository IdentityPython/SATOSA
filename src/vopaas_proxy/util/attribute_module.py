# pylint: disable = missing-docstring
class NoUserData(Exception):
    pass


class AttributeModule(object):
    def get_attributes(self, idp_attributes):
        raise NotImplementedError


class IdentityAttributes(AttributeModule):
    def get_attributes(self, idp_attributes):
        return idp_attributes
