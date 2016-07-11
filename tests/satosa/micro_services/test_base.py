import functools
from unittest.mock import Mock

import pytest

from satosa.exception import SATOSAAuthenticationError
from satosa.micro_services.base import process_microservice_queue, ResponseMicroService


class TestProcessMicroserviceQueue:
    def service_func(self, context, data, value):
        if "result" not in data:
            data["result"] = value
        else:
            data["result"] += value
        return data

    @pytest.fixture(autouse=True)
    def create_microservice_queue(self):
        self.queue = []
        for i in range(3):
            character = chr(ord('a') + i)
            service = Mock(spec=ResponseMicroService)
            service.process = functools.partial(self.service_func, value=character)
            self.queue.append(service)

    def test_process_queue(self, context):
        data = process_microservice_queue(self.queue, context, {})
        assert data["result"] == "abc"

    def test_process_queue_with_failing_result_raises_exception(self, context):
        fail_service = Mock()
        fail_service.process = Mock(side_effect=Exception)
        self.queue.append(fail_service)

        with pytest.raises(SATOSAAuthenticationError):
            process_microservice_queue(self.queue, context, {})