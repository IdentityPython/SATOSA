from collections import Counter

import pytest

from satosa.attribute_mapping import AttributeMapper


class TestAttributeMapperNestedDataDifferentAttrProfile:
    def test_nested_mapping_nested_data_to_internal(self):
        mapping = {
            "attributes": {
                "name": {
                    "openid": ["name"]
                },
                "givenname": {
                    "openid": ["given_name", "name.firstName"]
                },
            },
        }

        data = {
            "name": {
                "firstName": "value-first",
                "lastName": "value-last",
            },
            "email": "someuser@apple.com",
        }

        converter = AttributeMapper(mapping)
        internal_repr = converter.to_internal("openid", data)
        assert internal_repr["name"] == [data["name"]]
        assert internal_repr["givenname"] == [data["name"]["firstName"]]


    def test_nested_mapping_simple_data_to_internal(self):
        mapping = {
            "attributes": {
                "name": {
                    "openid": ["name"]
                },
                "givenname": {
                    "openid": ["given_name", "name.firstName"]
                },
            },
        }

        data = {
            "name": "value-first",
            "email": "someuser@google.com",
        }

        converter = AttributeMapper(mapping)
        internal_repr = converter.to_internal("openid", data)
        assert internal_repr["name"] == [data["name"]]
        assert internal_repr.get("givenname") is None


class TestAttributeMapper:
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

        internal_repr = AttributeMapper(mapping).to_internal("openid", data)
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

        internal_repr = AttributeMapper(mapping).to_internal("openid", data)
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

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
        filter = converter.to_internal_filter("p1", ["uid", "email"])
        assert Counter(filter) == Counter(["mail", "identifier"])

    def test_to_internal_with_missing_attribute_value(self):
        mapping = {
            "attributes": {
                "mail": {
                    "p1": ["emailaddress"],
                },
            }
        }

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
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

        converter = AttributeMapper(mapping)
        filter = converter.to_internal_filter("bar", ["email", "uid"])
        assert filter == ["id"]  # mail should not included since its missing in 'bar' profile

    def test_to_internal_with_unknown_attribute_profile(self):
        mapping = {
            "attributes": {
                "mail": {
                    "foo": ["email"],
                },
            }
        }

        converter = AttributeMapper(mapping)
        internal_repr = converter.to_internal("bar", {"email": ["test@example.com"]})
        assert internal_repr == {}

    def test_to_internal_filter_with_unknown_profile(self):
        mapping = {
            "attributes": {
                "mail": {
                    "foo": ["email"],
                }
            }
        }

        converter = AttributeMapper(mapping)
        filter = converter.to_internal_filter("bar", ["email"])
        assert filter == []

    def test_from_internal_with_unknown_profile(self):
        mapping = {
            "attributes": {
                "mail": {
                    "foo": ["email"],
                },
            },
        }

        converter = AttributeMapper(mapping)
        external_repr = converter.from_internal("bar", {"mail": "bob"})
        assert external_repr == {}

    def test_simple_template_mapping(self):
        mapping = {
            "attributes": {
                "last_name": {
                    "p1": ["sn"],
                    "p2": ["sn"]
                },
                "first_name": {
                    "p1": ["givenName"],
                    "p2": ["givenName"]
                },
                "name": {
                    "p2": ["cn"]
                }

            },
            "template_attributes": {
                "name": {
                    "p2": ["${first_name[0]} ${last_name[0]}"]
                }
            }
        }

        converter = AttributeMapper(mapping)
        internal_repr = converter.to_internal("p2", {"givenName": ["Valfrid"], "sn": ["Lindeman"]})
        assert "name" in internal_repr
        assert len(internal_repr["name"]) == 1
        assert internal_repr["name"][0] == "Valfrid Lindeman"
        external_repr = converter.from_internal("p2", internal_repr)
        assert external_repr["cn"][0] == "Valfrid Lindeman"

    def test_scoped_template_mapping(self):
        mapping = {
            "attributes": {
                "unscoped_affiliation": {
                    "p1": ["eduPersonAffiliation"]
                },
                "uid": {
                    "p1": ["eduPersonPrincipalName"],
                },
                "affiliation": {
                    "p1": ["eduPersonScopedAffiliation"]
                }
            },
            "template_attributes": {
                "affiliation": {
                    "p1": ["${unscoped_affiliation[0]}@${uid[0] | scope}"]
                }
            }
        }

        converter = AttributeMapper(mapping)
        internal_repr = converter.to_internal("p1", {
            "eduPersonAffiliation": ["student"],
            "eduPersonPrincipalName": ["valfrid@lindeman.com"]})
        assert "affiliation" in internal_repr
        assert len(internal_repr["affiliation"]) == 1
        assert internal_repr["affiliation"][0] == "student@lindeman.com"

    def test_template_attribute_overrides_existing_attribute(self):
        mapping = {
            "attributes": {
                "last_name": {
                    "p1": ["sn"],
                },
                "first_name": {
                    "p1": ["givenName"],
                },
                "name": {
                    "p1": ["cn"]
                }
            },
            "template_attributes": {
                "name": {
                    "p1": ["${first_name[0]} ${last_name[0]}"]
                }
            }
        }

        converter = AttributeMapper(mapping)
        data = {"sn": ["Surname"],
                "givenName": ["Given"],
                "cn": ["Common Name"]}
        internal_repr = converter.to_internal("p1", data)
        external_repr = converter.from_internal("p1", internal_repr)
        assert len(internal_repr["name"]) == 1
        assert internal_repr["name"][0] == "Given Surname"
        assert external_repr["cn"][0] == "Given Surname"

    def test_template_attribute_preserves_existing_attribute_if_template_cant_be_rendered(self):
        mapping = {
            "attributes": {
                "last_name": {
                    "p1": ["sn"],
                },
                "first_name": {
                    "p1": ["givenName"],
                },
                "name": {
                    "p1": ["cn"]
                }
            },
            "template_attributes": {
                "name": {
                    "p1": ["${unknown[0]} ${last_name[0]}"]
                }
            }
        }

        converter = AttributeMapper(mapping)
        data = {"sn": ["Surname"],
                "givenName": ["Given"],
                "cn": ["Common Name"]}
        internal_repr = converter.to_internal("p1", data)
        assert len(internal_repr["name"]) == 1
        assert internal_repr["name"][0] == "Common Name"

    def test_template_attribute_with_multiple_templates_tries_them_all_templates(self):
        mapping = {
            "attributes": {
                "last_name": {
                    "p1": ["sn"],
                },
                "first_name": {
                    "p1": ["givenName"],
                },
                "name": {
                    "p1": ["cn"]
                }
            },
            "template_attributes": {
                "name": {
                    "p1": ["${first_name[0]} ${last_name[0]}", "${unknown[0]} ${unknown[1]}",
                           "${first_name[1]} ${last_name[1]}", "${foo} ${bar}"]
                }
            }
        }

        converter = AttributeMapper(mapping)
        data = {"sn": ["Surname1", "Surname2"],
                "givenName": ["Given1", "Given2"],
                "cn": ["Common Name"]}
        internal_repr = converter.to_internal("p1", data)
        assert len(internal_repr["name"]) == 2
        assert internal_repr["name"][0] == "Given1 Surname1"
        assert internal_repr["name"][1] == "Given2 Surname2"

    def test_template_attribute_fail_does_not_insert_None_attribute_value(self):
        mapping = {
            "attributes": {
                "last_name": {
                    "p1": ["sn"],
                },
                "first_name": {
                    "p1": ["givenName"],
                },
                "name": {
                    "p1": ["cn"]
                }
            },
            "template_attributes": {
                "name": {
                    "p1": ["${first_name[0]} ${last_name[0]}"]
                }
            }
        }

        converter = AttributeMapper(mapping)
        internal_repr = converter.to_internal("p1", {})
        assert len(internal_repr) == 0

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

        converter = AttributeMapper(mapping)
        internal_repr = converter.to_internal("foo", attribute_value)
        assert internal_repr["mail"] == ["test@example.com"]
