from unittest.mock import mock_open, patch

import pytest

from satosa.metadata_creation.description import ContactPersonDesc, UIInfoDesc, OrganizationDesc, MetadataDescription


class TestContactPersonDesc(object):
    def test_to_dict(self):
        desc = ContactPersonDesc()
        desc.contact_type = "test"
        desc.given_name = "First"
        desc.sur_name = "Tester"
        desc.add_email_address("first_tester@example.com")

        serialized = desc.to_dict()
        assert serialized["contact_type"] == "test"
        assert serialized["given_name"] == "First"
        assert serialized["sur_name"] == "Tester"
        assert serialized["email_address"] == ["first_tester@example.com"]


class TestUIInfoDesc(object):
    def test_to_dict(self):
        desc = UIInfoDesc()
        desc.add_description("test", "en")
        desc.add_display_name("my company", "en")
        desc.add_logo("logo.jpg", 80, 80, "en")

        serialized = desc.to_dict()
        ui_info = serialized["service"]["ui_info"]
        assert ui_info["description"] == [{"text": "test", "lang": "en"}]
        assert ui_info["display_name"] == [{"text": "my company", "lang": "en"}]
        assert ui_info["logo"] == [{"text": "logo.jpg", "width": 80, "height": 80, "lang": "en"}]

    def test_to_dict_for_logo_without_lang(self):
        desc = UIInfoDesc()
        desc.add_logo("logo.jpg", 80, 80, None)

        serialized = desc.to_dict()
        ui_info = serialized["service"]["ui_info"]
        assert ui_info["logo"] == [{"text": "logo.jpg", "width": 80, "height": 80}]

    def test_to_dict_with_empty(self):
        desc = UIInfoDesc()
        assert desc.to_dict() == {}


class TestOrganizationDesc(object):
    def test_to_dict(self):
        desc = OrganizationDesc()
        desc.add_display_name("Foo Testing", "en")
        desc.add_name("Testing Co.", "en")
        desc.add_url("https://test.example.com", "en")

        serialized = desc.to_dict()
        org_info = serialized["organization"]
        assert org_info["display_name"] == [("Foo Testing", "en")]
        assert org_info["name"] == [("Testing Co.", "en")]
        assert org_info["url"] == [("https://test.example.com", "en")]

    def test_to_dict_with_empty(self):
        desc = OrganizationDesc()
        assert desc.to_dict() == {}


class TestMetadataDescription(object):
    def test_to_dict(self):
        org_desc = OrganizationDesc()
        org_desc.add_display_name("Foo Testing", "en")
        org_desc.add_name("Testing Co.", "en")
        org_desc.add_url("https://test.example.com", "en")

        contact_desc = ContactPersonDesc()
        contact_desc.contact_type = "test"
        contact_desc.given_name = "First"
        contact_desc.sur_name = "Tester"
        contact_desc.add_email_address("first_tester@example.com")

        ui_desc = UIInfoDesc()
        ui_desc.add_description("test", "en")
        ui_desc.add_display_name("my company", "en")
        ui_desc.add_logo("http://example.com/logo.jpg", 80, 80, "en")

        desc = MetadataDescription("my_entity")
        desc.organization = org_desc
        desc.add_contact_person(contact_desc)
        desc.ui_info = ui_desc

        serialized = desc.to_dict()
        assert serialized["entityid"] == "my_entity"
        assert serialized["organization"]
        assert serialized["contact_person"]
        assert serialized["service"]["ui_info"]

    def test_set_organization_rejects_bad_input(self):
        desc = MetadataDescription("my_entity")
        with pytest.raises(TypeError):
            desc.organization = "bad input"

    def test_add_contact_person_rejects_bad_input(self):
        desc = MetadataDescription("my_entity")
        with pytest.raises(TypeError):
            desc.add_contact_person("bad input")

    def test_set_ui_info_rejects_bad_input(self):
        desc = MetadataDescription("my_entity")
        with pytest.raises(TypeError):
            desc.ui_info = "bad input"
