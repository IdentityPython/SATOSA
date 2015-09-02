import json

from vopaas_proxy.util.attribute_module import AttributeModule, NoUserData


class TestModule(AttributeModule):
    def __init__(self, json_file, idp_attribute_name):
        self.idp_attribute_name = idp_attribute_name

        with open(json_file) as f:
            self.user_data = json.load(f)

        self.global_data = {'university': 'Small university', 'co': 'Sweden'}

    def get_attributes(self, idp_attributes):
        try:
            user_id = idp_attributes[self.idp_attribute_name][0]
        except KeyError:
            raise NoUserData(
                "Necessary attribute '{}' not returned by IdP.".format(
                    self.idp_attribute_name))

        try:
            user_data = self.user_data[user_id]
        except KeyError:
            raise NoUserData("Unknown user id '{}'".format(user_id))

        idp_attributes.update(user_data)
        idp_attributes.update(self.global_data)

        return self._rename_attributes(idp_attributes)

    def _rename_attributes(self, attributes):
        translation = {"email": "mail", "testA": "sn", "university": "o"}

        for attr_name, saml_name in translation.items():
            try:
                val = attributes.pop(attr_name)
                attributes[saml_name] = val
            except KeyError:
                pass

        return attributes
