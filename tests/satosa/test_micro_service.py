from satosa.context import Context
from satosa.micro_service.service_base import MicroService, build_micro_service_queue

__author__ = 'mathiashedstrom'


def create_process_func(data_str):
    def process(context, data):
        return "{}{}".format(data, data_str)

    return process


def test_micro_service():
    data_list = ["1", "2", "3"]
    service_list = []
    for d in data_list:
        service = MicroService()
        service.process = create_process_func(d)
        service_list.append(service)

    service_queue = build_micro_service_queue(service_list)
    test_data = "test_data"
    context = Context()
    data = service_queue.process_service_queue(context, test_data)

    for d in data_list:
        test_data = "{}{}".format(test_data, d)

    assert data == test_data
