from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.micro_services.attribute_policy import AttributePolicy


class TestAttributePolicy:
    def create_attribute_policy_service(self, attribute_policies):
        attribute_policy_service = AttributePolicy(
            config=attribute_policies,
            name="test_attribute_policy",
            base_url="https://satosa.example.com"
        )
        attribute_policy_service.next = lambda ctx, data: data
        return attribute_policy_service

    def test_attribute_policy(self):
        requester = "requester"
        attribute_policies = {
            "attribute_policy": {
                "requester_everything_allowed": {},
                "requester_nothing_allowed": {
                    "allowed": {}
                },
                "requester_subset_allowed": {
                    "allowed": {
                        "attr1",
                        "attr2",
                    },
                },
            },
        }
        attributes = {
            "attr1": ["foo"],
            "attr2": ["foo", "bar"],
            "attr3": ["foo"]
        }
        results = {
            "requester_everything_allowed": attributes.keys(),
            "requester_nothing_allowed": set(),
            "requester_subset_allowed": {"attr1", "attr2"},
        }
        for requester, result in results.items():
            attribute_policy_service = self.create_attribute_policy_service(
                attribute_policies)

            ctx = Context()
            ctx.state = dict()

            resp = InternalData(auth_info=AuthenticationInformation())
            resp.requester = requester
            resp.attributes = {
                "attr1": ["foo"],
                "attr2": ["foo", "bar"],
                "attr3": ["foo"]
            }

            filtered = attribute_policy_service.process(ctx, resp)
            assert(filtered.attributes.keys() == result)
