import pytest

from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.micro_services.attribute_modifications import FilterAttributeValues


class TestFilterAttributeValues:

    def create_filter_service(self, attribute_filters):
        filter_service = FilterAttributeValues(config=dict(attribute_filters=attribute_filters),
                                               name="test_filter",
                                               base_url="https://satosa.example.com")
        filter_service.next = lambda ctx, data: data
        return filter_service

    def test_filter_all_attributes_from_all_target_providers_for_all_requesters(self):
        attribute_filters = {
            "": {  # all providers
                "": {  # all requesters
                    "": "foo:bar"  # all attributes
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo:bar", "1:foo:bar:2"],
            "a3": ["a:foo:bar:b"]
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": [], "a2": ["foo:bar", "1:foo:bar:2"],
                                       "a3": ["a:foo:bar:b"]}

    def test_filter_one_attribute_from_all_target_providers_for_all_requesters(self):
        attribute_filters = {
            "": {
                "": {
                    "a2": "^foo:bar$"
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo:bar", "1:foo:bar:2"],
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": ["foo:bar"]}

    def test_filter_one_attribute_from_all_target_providers_for_one_requester(self):
        requester = "test_requester"
        attribute_filters = {
            "": {
                requester:
                    {"a1": "foo:bar"}
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(auth_info=AuthenticationInformation())
        resp.requester = requester
        resp.attributes = {
            "a1": ["abc:xyz", "1:foo:bar:2"],
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": ["1:foo:bar:2"]}

    def test_filter_attribute_not_in_response(self):
        attribute_filters = {
            "": {
                "":
                    {"a0": "foo:bar"}
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz", "1:foo:bar:2"],
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": ["abc:xyz", "1:foo:bar:2"]}

    def test_filter_one_attribute_for_one_target_provider(self):
        target_provider = "test_provider"
        attribute_filters = {
            target_provider: {
                "":
                    {"a1": "foo:bar"}
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(auth_info=AuthenticationInformation(issuer=target_provider))
        resp.attributes = {
            "a1": ["abc:xyz", "1:foo:bar:2"],
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": ["1:foo:bar:2"]}

    def test_filter_one_attribute_for_one_target_provider_for_one_requester(self):
        target_provider = "test_provider"
        requester = "test_requester"
        attribute_filters = {
            target_provider: {
                requester:
                    {"a1": "foo:bar"}
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(auth_info=AuthenticationInformation(issuer=target_provider))
        resp.requester = requester
        resp.attributes = {
            "a1": ["abc:xyz", "1:foo:bar:2"],
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": ["1:foo:bar:2"]}

    def test_filter_one_attribute_from_all_target_providers_for_all_requesters_in_extended_notation(
            self):
        attribute_filters = {
            "": {
                "": {
                    "a2": {
                        "regexp": "^foo:bar$"
                    }
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo:bar", "1:foo:bar:2"],
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": ["foo:bar"]}

    def test_invalid_filter_type(self):
        attribute_filters = {
            "": {
                "": {
                    "a2": {
                        "invalid_filter": None
                    }
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo:bar", "1:foo:bar:2"],
        }
        with pytest.raises(SATOSAError):
            filtered = filter_service.process(None, resp)

    def test_shibmdscope_match_value_filter_with_no_md_store_in_context(self):
        attribute_filters = {
            "": {
                "": {
                    "a2": {
                        "shibmdscope_match_value": None
                    }
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo:bar", "1:foo:bar:2"],
        }
        ctx = Context()
        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": []}
