from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.micro_services.attribute_modifications import FilterAttributeValues


class TestFilterAttributeValues:
    def create_filter_service(self, attribute_filters):
        filter_service = FilterAttributeValues(config=dict(attribute_filters=attribute_filters), name="test_filter")
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

        resp = InternalResponse(AuthenticationInformation(None, None, None))
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo:bar", "1:foo:bar:2"],
            "a3": ["a:foo:bar:b"]
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": [], "a2": ["foo:bar", "1:foo:bar:2"], "a3": ["a:foo:bar:b"]}

    def test_filter_one_attribute_from_all_target_providers_for_all_requesters(self):
        attribute_filters = {
            "": {
                "": {
                    "a2": "^foo:bar$"
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalResponse(AuthenticationInformation(None, None, None))
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

        resp = InternalResponse(AuthenticationInformation(None, None, None))
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

        resp = InternalResponse(AuthenticationInformation(None, None, None))
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

        resp = InternalResponse(AuthenticationInformation(None, None, target_provider))
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

        resp = InternalResponse(AuthenticationInformation(None, None, target_provider))
        resp.requester = requester
        resp.attributes = {
            "a1": ["abc:xyz", "1:foo:bar:2"],
        }
        filtered = filter_service.process(None, resp)
        assert filtered.attributes == {"a1": ["1:foo:bar:2"]}
