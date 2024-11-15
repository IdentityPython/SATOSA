import pytest
from tests.util import FakeIdP, create_metadata_from_config_dict, FakeSP
from saml2.mdstore import MetadataStore
from saml2.config import Config
from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.micro_services.attribute_modifications import FilterAttributeValues


class TestFilterAttributeValues:
    def create_filter_service(self, attribute_filters):
        filter_service = FilterAttributeValues(config=dict(attribute_filters=attribute_filters), name="test_filter",
                                               base_url="https://satosa.example.com")
        filter_service.next = lambda ctx, data: data
        return filter_service

    def create_idp_metadata_conf_with_shibmd_scopes(self, idp_entityid, shibmd_scopes):
        idp_conf = {
            "entityid": idp_entityid,
            "service": {
                "idp":{}
            }
        }

        if shibmd_scopes is not None:
            idp_conf["service"]["idp"]["scope"] = shibmd_scopes

        metadata_conf = {
            "inline": [create_metadata_from_config_dict(idp_conf)]
        }
        return metadata_conf

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

    def test_filter_one_attribute_from_all_target_providers_for_all_requesters_in_extended_notation(self):
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

    def test_shibmdscope_match_value_filter_with_empty_md_store_in_context(self):
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
        mdstore = MetadataStore(None, None)
        ctx.decorate(Context.KEY_METADATA_STORE, mdstore)
        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": []}

    def test_shibmdscope_match_value_filter_with_idp_md_with_no_scope(self):
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
            "a2": ["foo.bar", "1.foo.bar.2"],
        }

        idp_entityid = 'https://idp.example.org/'
        resp.auth_info.issuer = idp_entityid

        mdstore = MetadataStore(None, Config())
        mdstore.imp(self.create_idp_metadata_conf_with_shibmd_scopes(idp_entityid, None))
        ctx = Context()
        ctx.decorate(Context.KEY_METADATA_STORE, mdstore)

        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": []}

    def test_shibmdscope_match_value_filter_with_idp_md_with_single_scope(self):
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
            "a2": ["foo.bar", "1.foo.bar.2"],
        }

        idp_entityid = 'https://idp.example.org/'
        resp.auth_info.issuer = idp_entityid

        mdstore = MetadataStore(None, Config())
        mdstore.imp(self.create_idp_metadata_conf_with_shibmd_scopes(idp_entityid, ["foo.bar"]))
        ctx = Context()
        ctx.decorate(Context.KEY_METADATA_STORE, mdstore)

        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": ["foo.bar"]}

    def test_shibmdscope_match_value_filter_with_idp_md_with_single_regexp_scope(self):
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
            "a2": ["test.foo.bar", "1.foo.bar.2"],
        }

        idp_entityid = 'https://idp.example.org/'
        resp.auth_info.issuer = idp_entityid

        mdstore = MetadataStore(None, Config())
        mdstore.imp(self.create_idp_metadata_conf_with_shibmd_scopes(idp_entityid, [r"[^.]*\.foo\.bar$"]))
        # mark scope as regexp (cannot be done via pysaml2 YAML config)
        mdstore[idp_entityid]['idpsso_descriptor'][0]['extensions']['extension_elements'][0]['regexp'] = 'true'
        ctx = Context()
        ctx.decorate(Context.KEY_METADATA_STORE, mdstore)

        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": ["test.foo.bar"]}

    def test_shibmdscope_match_value_filter_with_idp_md_with_multiple_scopes(self):
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
            "a2": ["foo.bar", "1.foo.bar.2", "foo.baz", "foo.baz.com"],
        }

        idp_entityid = 'https://idp.example.org/'
        resp.auth_info.issuer = idp_entityid

        mdstore = MetadataStore(None, Config())
        mdstore.imp(self.create_idp_metadata_conf_with_shibmd_scopes(idp_entityid, ["foo.bar", "foo.baz"]))
        ctx = Context()
        ctx.decorate(Context.KEY_METADATA_STORE, mdstore)

        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": ["foo.bar", "foo.baz"]}

    def test_shibmdscope_match_scope_filter_with_single_scope(self):
        attribute_filters = {
            "": {
                "": {
                    "a2": {
                        "shibmdscope_match_scope": None
                    }
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo.bar", "value@foo.bar", "1.foo.bar.2", "value@foo.bar.2", "value@extra@foo.bar"],
        }

        idp_entityid = 'https://idp.example.org/'
        resp.auth_info.issuer = idp_entityid

        mdstore = MetadataStore(None, Config())
        mdstore.imp(self.create_idp_metadata_conf_with_shibmd_scopes(idp_entityid, ["foo.bar"]))
        ctx = Context()
        ctx.decorate(Context.KEY_METADATA_STORE, mdstore)

        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": ["value@foo.bar"]}

    def test_multiple_filters_for_single_attribute(self):
        attribute_filters = {
            "": {
                "": {
                    "a2": {
                        "regexp": "^value1@",
                        "shibmdscope_match_scope": None
                    }
                }
            }
        }
        filter_service = self.create_filter_service(attribute_filters)

        resp = InternalData(AuthenticationInformation())
        resp.attributes = {
            "a1": ["abc:xyz"],
            "a2": ["foo.bar", "value1@foo.bar", "value2@foo.bar", "1.foo.bar.2", "value@foo.bar.2", "value@extra@foo.bar"],
        }

        idp_entityid = 'https://idp.example.org/'
        resp.auth_info.issuer = idp_entityid

        mdstore = MetadataStore(None, Config())
        mdstore.imp(self.create_idp_metadata_conf_with_shibmd_scopes(idp_entityid, ["foo.bar"]))
        ctx = Context()
        ctx.decorate(Context.KEY_METADATA_STORE, mdstore)

        filtered = filter_service.process(ctx, resp)
        assert filtered.attributes == {"a1": ["abc:xyz"], "a2": ["value1@foo.bar"]}
