from satosa.internal_data import DataConverter


class TestDataConverter:
    def test_nested_attribute_to_internal(self):
        mapping = {
            "attributes": {
                "address": {
                    "openid": ["address.formatted"],
                },
            },
        }

        data = {
            "address": {
                "formatted": "100 Universal City Plaza, Hollywood CA 91608, USA"
            }
        }

        internal_repr = DataConverter(mapping).to_internal("openid", data)
        assert internal_repr["address"] == [data["address"]["formatted"]]

    def test_deeply_nested_attribute_to_internal(self):
        mapping = {
            "attributes": {
                "address": {
                    "openid": ["address.formatted.text.value"],
                },
            },
        }

        data = {
            "address": {
                "formatted": {
                    "text": {
                        "value": "100 Universal City Plaza, Hollywood CA 91608, USA"
                    }
                }
            }
        }

        internal_repr = DataConverter(mapping).to_internal("openid", data)
        assert internal_repr["address"] == [data["address"]["formatted"]["text"]["value"]]

    def test_mapping_from_nested_attribute(self):
        mapping = {
            "attributes": {
                "address": {
                    "openid": ["address.formatted"],
                    "saml": ["postaladdress"]
                },
            },
        }

        data = {
            "address": {
                "formatted": "100 Universal City Plaza, Hollywood CA 91608, USA"
            }
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("openid", data)
        external_repr = converter.from_internal("saml", internal_repr)
        assert external_repr["postaladdress"] == [data["address"]["formatted"]]

    def test_mapping_from_deeply_nested_attribute(self):
        mapping = {
            "attributes": {
                "address": {
                    "openid": ["address.formatted.text.value"],
                    "saml": ["postaladdress"]
                },
            },
        }

        data = {
            "address": {
                "formatted": {
                    "text": {
                        "value": "100 Universal City Plaza, Hollywood CA 91608, USA"
                    }
                }
            }
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("openid", data)
        external_repr = converter.from_internal("saml", internal_repr)
        assert external_repr["postaladdress"] == [data["address"]["formatted"]["text"]["value"]]
