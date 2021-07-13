from unittest import TestCase

import pytest

from satosa.context import Context
from satosa.state import State
from satosa.micro_services.disco import DiscoToTargetIssuer
from satosa.micro_services.disco import DiscoToTargetIssuerError


class TestDiscoToTargetIssuer(TestCase):
    def setUp(self):
        context = Context()
        context.state = State()

        config = {
            'disco_endpoints': [
                '.*/disco',
            ],
        }

        plugin = DiscoToTargetIssuer(
            config=config,
            name='test_disco_to_target_issuer',
            base_url='https://satosa.example.org',
        )
        plugin.next = lambda ctx, data: (ctx, data)

        self.config = config
        self.context = context
        self.plugin = plugin

    def test_when_entity_id_is_not_set_raise_error(self):
        self.context.request = {}
        with pytest.raises(DiscoToTargetIssuerError):
            self.plugin._handle_disco_response(self.context)

    def test_when_entity_id_is_set_target_issuer_is_set(self):
        entity_id = 'idp.example.org'
        self.context.request = {
            'entityID': entity_id,
        }
        newctx, newdata = self.plugin._handle_disco_response(self.context)
        assert newctx.get_decoration(Context.KEY_TARGET_ENTITYID) == entity_id
