from unittest import TestCase

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State
from satosa.micro_services.idp_hinting import IdpHinting


class TestIdpHinting(TestCase):
    def setUp(self):
        context = Context()
        context.state = State()
        internal_data = InternalData()

        config = {
              'allowed_params': ["idp_hinting", "idp_hint", "idphint"]
        }

        plugin = IdpHinting(
            config=config,
            name='test_idphinting',
            base_url='https://satosa.example.org',
        )
        plugin.next = lambda ctx, data: (ctx, data)

        self.config = config
        self.context = context
        self.data = internal_data
        self.plugin = plugin

    def test_no_query_params(self):
        self.context.qs_params = {}
        new_context, new_data = self.plugin.process(self.context, self.data)
        assert not new_context.get_decoration(Context.KEY_TARGET_ENTITYID)

    def test_hint_in_params(self):
        _target = 'https://localhost:8080'
        self.context.qs_params = {'idphint': _target}
        new_context, new_data = self.plugin.process(self.context, self.data)
        assert new_context.get_decoration(Context.KEY_TARGET_ENTITYID) == _target

    def test_no_hint_in_params(self):
        _target = 'https://localhost:8080'
        self.context.qs_params = {'param_not_in_allowed_params': _target}
        new_context, new_data = self.plugin.process(self.context, self.data)
        assert not new_context.get_decoration(Context.KEY_TARGET_ENTITYID)

    def test_issuer_already_set(self):
        _pre_selected_target = 'https://local.localhost:8080'
        self.context.decorate(Context.KEY_TARGET_ENTITYID, _pre_selected_target)
        _target = 'https://localhost:8080'
        self.context.qs_params = {'idphint': _target}
        new_context, new_data = self.plugin.process(self.context, self.data)
        assert new_context.get_decoration(Context.KEY_TARGET_ENTITYID) == _pre_selected_target
        assert new_context.get_decoration(Context.KEY_TARGET_ENTITYID) != _target
