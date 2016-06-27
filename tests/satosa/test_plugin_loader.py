import json

import pytest
import yaml

from satosa.exception import SATOSAConfigurationError
from satosa.micro_service.service_base import RequestMicroService, ResponseMicroService, MicroService
from satosa.plugin_base.endpoint import BackendModulePlugin, FrontendModulePlugin, InterfaceModulePlugin
from satosa.plugin_loader import _member_filter, backend_filter, frontend_filter, _micro_service_filter, \
    _request_micro_service_filter, _response_micro_service_filter, _load_plugin_config


class TestFilters(object):
    class BackendTestPlugin(BackendModulePlugin):
        pass

    class FrontendTestPlugin(FrontendModulePlugin):
        pass

    class RequestTestMicroService(RequestMicroService):
        pass

    class ResponseTestMicroService(ResponseMicroService):
        pass

    @pytest.mark.parametrize('cls', [
        BackendModulePlugin,
        FrontendModulePlugin,
        InterfaceModulePlugin
    ])
    def test_member_filter_rejects_base_classes(self, cls):
        assert not _member_filter(cls)

    @pytest.mark.parametrize('cls', [
        BackendTestPlugin,
        FrontendTestPlugin
    ])
    def test_member_filter_accepts_subclasses(self, cls):
        assert _member_filter(cls)

    def test_backend_filter_rejects_frontend_plugin(self):
        assert not backend_filter(TestFilters.FrontendTestPlugin)

    def test_backend_filter_accepts_backend_plugin(self):
        assert backend_filter(TestFilters.BackendTestPlugin)

    def test_frontend_filter_rejects_backend_plugin(self):
        assert not frontend_filter(TestFilters.BackendTestPlugin)

    def test_frontend_filter_accepts_backend_plugin(self):
        assert frontend_filter(TestFilters.FrontendTestPlugin)

    @pytest.mark.parametrize('cls', [
        ResponseMicroService,
        RequestMicroService,
        MicroService
    ])
    def test_microservice_filter_rejects_base_classes(self, cls):
        assert not _micro_service_filter(cls)

    def test_request_micro_service_filter_rejects_response_micro_service(self):
        assert not _request_micro_service_filter(TestFilters.ResponseTestMicroService)

    def test_request_micro_service_filter_accepts_request_micro_service(self):
        assert _request_micro_service_filter(TestFilters.RequestTestMicroService)

    def test_response_micro_service_filter_rejects_request_micro_service(self):
        assert not _response_micro_service_filter(TestFilters.RequestTestMicroService)

    def test_response_micro_service_filter_accepts_response_micro_service(self):
        assert _response_micro_service_filter(TestFilters.ResponseTestMicroService)


class TestLoadPluginConfig(object):
    def test_load_json(self):
        data = {"foo": "bar"}
        config = _load_plugin_config(json.dumps(data))
        assert config == data

    def test_can_load_yaml(self):
        data = {"foo": "bar"}
        config = _load_plugin_config(yaml.dump(data, default_flow_style=False))
        assert config == data

    def test_handles_malformed_data(self):
        data = """{foo: bar"""  # missing closing bracket
        with pytest.raises(SATOSAConfigurationError):
            _load_plugin_config(data)