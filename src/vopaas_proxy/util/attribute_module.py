class NoUserData(Exception):
    pass


class AttributeModule(object):
    def get_attributes(self, idp_attributes):
        raise NotImplemented


class IdentityAttributes(AttributeModule):
    def get_attributes(self, idp_attributes):
        return idp_attributes
