#
# Ubiquitous Moodle
#
# @author Luke Carrier <luke@carrier.im>
# @copyright 2018 The Ubiquitous Authors
#

from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import MagicMock, patch, NO_MOCK, NO_MOCK_REASON

from tests.unit.modules.test_ufw import UfwAssertionsMixin

import salt.states.ufw as ufw
import salt.modules.ufw as ufwmod


@skipIf(NO_MOCK, NO_MOCK_REASON)
class UfwTestCase(TestCase, LoaderModuleMockMixin, UfwAssertionsMixin):
    def setup_loader_modules(self):
        return {ufw: {}}

    def test_delta_ruleset_add(self):
        current_rules = {
            1: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 22,
            },
        }
        new_rules = {
            1: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 22,
            },
            2: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 80,
            },
        }

        expected = {
            2: {
                'old': None,
                'new': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 80,
                }),
            },
        }
        ufw.__salt__['ufw.complete_rule'] = ufwmod.complete_rule
        delta = ufw._delta_ruleset(current_rules, new_rules)
        self.assertEqual(expected, delta)

    def test_delta_ruleset_remove(self):
        current_rules = {
            1: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 22,
            },
            2: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 80,
            },
        }

        new_rules = {
            1: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 80,
            },
        }

        expected = {
            1: {
                'old': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 22,
                }),
                'new': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 80,
                }),
            },
            2: {
                'old': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 22,
                }),
                'new': None,
            },
        }
        ufw.__salt__['ufw.complete_rule'] = ufwmod.complete_rule
        delta = ufw._delta_ruleset(current_rules, new_rules)
        self.assertEqual(expected, delta)

    def test_delta_ruleset_change(self):
        current_rules = {
            1: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 80,
            },
            2: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 443,
            },
            3: {
                'policy': 'allow',
                'direction': 'outgoing',
                'port': 11211,
            },
        }

        new_rules = {
            1: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 22,
            },
            2: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 80,
            },
            3: {
                'policy': 'allow',
                'direction': 'incoming',
                'port': 443,
            },
        }

        expected = {
            1: {
                'old': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 80,
                }),
                'new': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 22,
                }),
            },
            2: {
                'old': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 443,
                }),
                'new': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 80,
                }),
            },
            3: {
                'old': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'outgoing',
                    'port': 11211,
                }),
                'new': ufwmod.complete_rule({
                    'policy': 'allow',
                    'direction': 'incoming',
                    'port': 443,
                }),
            },
        }
        ufw.__salt__['ufw.complete_rule'] = ufwmod.complete_rule
        delta = ufw._delta_ruleset(current_rules, new_rules)
        self.assertEqual(expected, delta)
