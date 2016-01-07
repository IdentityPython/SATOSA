from collections import Counter

import pytest

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
                "formatted": ["100 Universal City Plaza, Hollywood CA 91608, USA"]
            }
        }

        internal_repr = DataConverter(mapping).to_internal("openid", data)
        assert internal_repr["address"] == data["address"]["formatted"]

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
                        "value": ["100 Universal City Plaza, Hollywood CA 91608, USA"]
                    }
                }
            }
        }

        internal_repr = DataConverter(mapping).to_internal("openid", data)
        assert internal_repr["address"] == data["address"]["formatted"]["text"]["value"]

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
                "formatted": ["100 Universal City Plaza, Hollywood CA 91608, USA"]
            }
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("openid", data)
        external_repr = converter.from_internal("saml", internal_repr)
        assert external_repr["postaladdress"] == data["address"]["formatted"]

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
                        "value": ["100 Universal City Plaza, Hollywood CA 91608, USA"]
                    }
                }
            }
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("openid", data)
        external_repr = converter.from_internal("saml", internal_repr)
        assert external_repr["postaladdress"] == data["address"]["formatted"]["text"]["value"]

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
            "postaladdress": ["100 Universal City Plaza, Hollywood CA 91608, USA"]
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("saml", data)
        external_repr = converter.from_internal("openid", internal_repr)
        assert external_repr["address"]["formatted"] == data["postaladdress"]

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
            "postaladdress": ["100 Universal City Plaza, Hollywood CA 91608, USA"]
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("saml", data)
        external_repr = converter.from_internal("openid", internal_repr)
        assert external_repr["address"]["formatted"]["text"]["value"] == data["postaladdress"]

    def test_multiple_source_attribute_values(self):
        mapping = {
            "attributes": {
                "mail": {
                    "saml": ["mail", "emailAddress", "email"]
                },
            },
        }

        data = {
            "mail": ["test1@example.com"],
            "email": ["test2@example.com"],
            "emailAddress": ["test3@example.com"],
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

        converter = DataConverter(mapping)
        filter = converter.to_internal_filter("p1", ["uid", "email"], False)
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

        converter = DataConverter(mapping)
        filter = converter.to_internal_filter("p1", ["Uid", "eMaILAdDreSS"], True)
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
        internal_repr = converter.to_internal("p1", {"email": ["test@example.com"]})
        assert internal_repr == {"mail": ["test@example.com"], "identifier": ["test@example.com"]}

    def test_to_internal_profile_missing_attribute_mapping(self):
        mapping = {
            "attributes": {
                "mail": {
                    "foo": ["email"],
                },
                "id": {
                    "foo": ["id"],
                    "bar": ["uid"],
                }
            },
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("bar", {"email": ["test@example.com"], "uid": ["uid"]})
        assert "mail" not in internal_repr  # no mapping for the 'mail' attribute in the 'bar' profile
        assert internal_repr["id"] == ["uid"]

    def test_to_internal_filter_profile_missing_attribute_mapping(self):
        mapping = {
            "attributes": {
                "mail": {
                    "foo": ["email"],
                },
                "id": {
                    "foo": ["id"],
                    "bar": ["uid"],
                }
            },
        }

        converter = DataConverter(mapping)
        filter = converter.to_internal_filter("bar", ["email", "uid"])
        assert Counter(filter) == Counter(["id"])


    @pytest.mark.parametrize("attribute_value", [
        {"email": "test@example.com"},
        {"email": ["test@example.com"]}
    ])
    def test_to_internal_same_attribute_value_from_list_and_single_value(self, attribute_value):
        mapping = {
            "attributes": {
                "mail": {
                    "foo": ["email"],
                },
            },
        }

        converter = DataConverter(mapping)
        internal_repr = converter.to_internal("foo", attribute_value)
        assert internal_repr["mail"] == ["test@example.com"]


