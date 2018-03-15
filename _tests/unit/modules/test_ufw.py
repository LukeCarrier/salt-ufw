#
# Ubiquitous Moodle
#
# @author Luke Carrier <luke@carrier.im>
# @copyright 2018 The Ubiquitous Authors
#

from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase

import salt.modules.ufw as ufw


CONF_UFW = '''
# /etc/ufw/ufw.conf
#

# Set to yes to start on boot. If setting this remotely, be sure to add a rule
# to allow your remote connection before starting ufw. Eg: 'ufw allow 22/tcp'
ENABLED=no

# Please use the 'ufw' command to set the loglevel. Eg: 'ufw logging medium'.
# See 'man ufw' for details.
LOGLEVEL="low"
'''


class UfwAssertionsMixin:
    '''
    Additional assertions for the UFW firewall modules.
    '''
    def assertUfwRuleEqual(self, expected, actual):
        '''
        Assert that the specified rule contains the specified property values.

        expected
            Expected properties.
        actual
            Actual properties.
        '''
        return self.assertEqual(
                ufw.complete_rule(expected), ufw.complete_rule(actual))

    def assertUfwRulesetEqual(self, expected, actual):
        '''
        Assert that all roles in the specified ruleset are equal.

        expected
            Expected rules.
        actual
            Actual rules.
        '''
        expected = [ufw.complete_rule(x) for x in expected]
        actual = [ufw.complete_rule(x) for x in actual]

        return self.assertEqual(expected, actual)


class UfwTestCase(TestCase, LoaderModuleMockMixin, UfwAssertionsMixin):
    def setup_loader_modules(self):
        return {ufw: {}}

    def test_get_conf_values_from_string(self):
        result = ufw._get_conf_values_from_string(CONF_UFW)
        self.assertEqual(len(result), 2)
        self.assertEqual(result['ENABLED'], 'no')
        self.assertEqual(result['LOGLEVEL'], 'low')

    def test_parse_rule_simple_port(self):
        rule = ufw._parse_rule('allow 80'.split(' '))
        self.assertUfwRuleEqual(rule, {
            'policy': 'allow',
            'direction': 'incoming',
            'port': 80,
        })

    def test_parse_rule_simple_port_protocol(self):
        rule = ufw._parse_rule('reject 80/tcp'.split(' '))
        self.assertUfwRuleEqual(rule, {
            'policy': 'reject',
            'direction': 'incoming',
            'port': 80,
            'protocol': 'tcp',
        })

    def test_parse_rule_complex_comment(self):
        rule = ufw._parse_rule('allow proto tcp from any port 80 comment \'web app\''.split(' '))
        self.assertUfwRuleEqual(rule, {
            'policy': 'allow',
            'port': 80,
            'protocol': 'tcp',
            'source': 'any',
            'comment': 'web app',
        })

    def test_parse_rule_complex_protocol_port(self):
        rule = ufw._parse_rule('allow proto tcp from 10.0.0.0/8 port 443'.split(' '))
        self.assertUfwRuleEqual(rule, {
            'policy': 'allow',
            'source': '10.0.0.0/8',
            'port': 443,
            'protocol': 'tcp',
        })

    def test_parse_rule_complex_host_port(self):
        rule = ufw._parse_rule('allow from 10.0.0.0/8 port 80'.split(' '))
        self.assertUfwRuleEqual(rule, {
            'policy': 'allow',
            'port': 80,
            'source': '10.0.0.0/8',
        })
