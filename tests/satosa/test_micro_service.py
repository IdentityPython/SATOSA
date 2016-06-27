import pytest

from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError
from satosa.microservices.service_base import MicroService, build_micro_service_queue
from satosa.state import State


def create_process_func(data_str):
    def process(context, data):
        return "{}{}".format(data, data_str)

    return process


def create_process_fail_func(data_str):
    def process(context, data):
        raise Exception("error")

    return process


def test_micro_service():
    """
    Test the micro service flow
    """
    data_list = ["1", "2", "3"]
    service_list = []
    for d in data_list:
        service = MicroService()
        service.process = create_process_func(d)
        service_list.append(service)

    service_queue = build_micro_service_queue(service_list)
    test_data = "test_data"
    context = Context()
    context.state = State()
    data = service_queue.process_service_queue(context, test_data)

    for d in data_list:
        test_data = "{}{}".format(test_data, d)

    assert data == test_data


def test_mirco_service_error():
    """
    Test that the process_service_queue raises a SATOSAAuthenticationError if anything goes wrong with a micro service
    """
    data_list = ["1", "2", "3"]
    service_list = []

    fail_service = MicroService()
    fail_service.process = create_process_fail_func("4")
    service_list.append(fail_service)

    for d in data_list:
        service = MicroService()
        service.process = create_process_func(d)
        service_list.append(service)

    service_queue = build_micro_service_queue(service_list)
    test_data = "test_data"
    context = Context()
    context.state = State()

    with pytest.raises(SATOSAAuthenticationError):
        service_queue.process_service_queue(context, test_data)
