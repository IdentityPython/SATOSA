from .base import RequestMicroService


class DecideBackendByRequester(RequestMicroService):
    """
    Select which backend should be used based on who the requester is.
    """

    def __init__(self, config, **kwargs):
        """
        Constructor.
        :param config: mapping from requester identifier to
        backend module name under the key 'requester_mapping'
        :type config: Dict[str, Dict[str, str]]
        """
        super().__init__()
        self.requester_mapping = config['requester_mapping']

    def process(self, context, data):
        """
        Will modify the context.target_backend attribute based on the requester identifier.
        :param context: request context
        :param data: the internal request
        """
        context.target_backend = self.requester_mapping[data.requester]
