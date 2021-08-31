from unittest import TestCase

import pytest

from satosa.context import Context
from satosa.state import State
from satosa.micro_services.idp_hinting import IdpHinting


class TestIdpHinting(TestCase):
    def setUp(self):
        context = Context()
        context.state = State()

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
        self.plugin = plugin

    def test_idp_hinting(self):
        self.context.request = {}
        _target = 'https://localhost:8080'
        self.context.qs_params = {'idphint': _target}
        res = self.plugin.process(self.context, data={})
        assert res[0].internal_data.get('target_entity_id') == _target

    def test_no_idp_hinting(self):
        self.context.request = {}
        res = self.plugin.process(self.context, data={})
        assert not res[0].internal_data.get('target_entity_id')
