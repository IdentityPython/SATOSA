from collections import Counter

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

    def test_mapping_to_nested_attribute(self):
        mapping = {
            "attributes": {
                "address": {
                    "openid": ["address.formatted"],
                    "saml": ["postaladdress"]
                },
            },
        }

        data = {
            "postaladdress": "100 Universal City Plaza, Hollywood CA 91608, USA"
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("saml", data)
        external_repr = converter.from_internal("openid", internal_repr)
        assert external_repr["address"]["formatted"] == [data["postaladdress"]]

    def test_mapping_to_deeply_nested_attribute(self):
        mapping = {
            "attributes": {
                "address": {
                    "openid": ["address.formatted.text.value"],
                    "saml": ["postaladdress"]
                },
            },
        }

        data = {
            "postaladdress": "100 Universal City Plaza, Hollywood CA 91608, USA"
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("saml", data)
        external_repr = converter.from_internal("openid", internal_repr)
        assert external_repr["address"]["formatted"]["text"]["value"] == [data["postaladdress"]]

    def test_multiple_source_attribute_values(self):
        mapping = {
            "attributes": {
                "mail": {
                    "saml": ["mail", "emailAddress", "email"]
                },
            },
        }

        data = {
            "mail": "test1@example.com",
            "email": "test2@example.com",
            "emailAddress": "test3@example.com",
        }

        expected = Counter(["test1@example.com", "test2@example.com", "test3@example.com"])

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("saml", data)
        assert Counter(internal_repr["mail"]) == expected
        external_repr = converter.from_internal("saml", internal_repr)
        assert Counter(external_repr[mapping["attributes"]["mail"]["saml"][0]]) == expected

    def test_to_internal_filter(self):
        mapping = {
            "attributes": {
                "mail": {
                    "p1": ["email"],
                },
                "identifier": {
                    "p1": ["uid"],
                },
            },
        }

        data = {"uid": "12345", "email": "test@example.com"}

        converter = DataConverter(mapping)
        filter = converter.to_internal_filter("p1", data, False)
        assert Counter(filter) == Counter(["mail", "identifier"])

    def test_to_internal_filter_case_insensitive(self):
        mapping = {
            "attributes": {
                "mail": {
                    "p1": ["emailaddress"],
                },
                "identifier": {
                    "p1": ["uid"],
                },
            },
        }

        data = {"Uid": "12345", "eMaILAdDreSS": "test@example.com"}

        converter = DataConverter(mapping)
        filter = converter.to_internal_filter("p1", data, True)
        assert Counter(filter) == Counter(["mail", "identifier"])

    def test_to_internal_with_missing_attribute_value(self):
        mapping = {
            "attributes": {
                "mail": {
                    "p1": ["emailaddress"],
                },
            }
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("p1", {})
        assert not internal_repr


    def test_map_one_source_attribute_to_multiple_internal_attributes(self):
        mapping = {
            "attributes": {
                "mail": {
                    "p1": ["email"],
                },
                "identifier": {
                    "p1": ["email"],
                },
            },
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("p1", {"email": "test@example.com"})
        assert internal_repr == {"mail": ["test@example.com"], "identifier": ["test@example.com"]}
