#
# Ubiquitous Moodle
#
# @author Luke Carrier <luke@carrier.im>
# @copyright 2018 The Ubiquitous Authors
#

import logging

import salt
import salt.utils

log = logging.getLogger(__name__)

def __virtual__():
    '''
    Load the module only if ufw is installed.
    '''
    if not salt.utils.which('ufw'):
        return False
    return True


def _delta_ruleset(current_rules, new_rules):
    '''
    Compute the delta between two rulesets.

    current_rules
        The starting set of rules.
    new_rules
        The desired set of rules.
    '''

    delta = {}

    current_rules = {i: __salt__['ufw.complete_rule'](x) for i, x in current_rules.items()}
    new_rules = {i: __salt__['ufw.complete_rule'](x) for i, x in new_rules.items()}

    for index, (current, new) in enumerate(zip(current_rules, new_rules)):
        if current_rules[current] != new_rules[current]:
            delta[current] = {
                'old': current_rules[current],
                'new': new_rules[current],
            }

    for index in range(len(new_rules), len(current_rules)):
        delta[index + 1] = {
            'old': current_rules[index],
            'new': None,
        }

    for index in range(len(current_rules), len(new_rules)):
        rule_number = index + 1
        delta[rule_number] = {
            'old': None,
            'new': new_rules[rule_number],
        }

    return delta


def _number_rules(rules):
    '''
    Arrange a list of rules into a numbered dictionary.

    rules
        List of rules.
    '''
    return dict(zip(range(1, len(rules) + 1), rules))


def enabled(name):
    '''
    Enable the firewall if it is disabled.
    '''
    ret = {
        'name': name,
        'result': False,
        'changes': {},
        'comment': '',
    }

    ret['result'] = __salt__['ufw.status']()['active']
    if not ret['result']:
        ret['result'] = __salt__['ufw.enable']()
        if ret['result']:
            ret['comment'] = 'UFW enabled'
            ret['changes'] = {
                'old': False,
                'new': True,
            }

    return ret


def disabled(name):
    '''
    Disable the firewall if it is enabled.
    '''
    ret = {
        'name': name,
        'result': False,
        'changes': {},
        'comment': '',
    }

    ret['result'] = __salt__['ufw.status']()['active']
    if not ret['result']:
        ret['result'] = __salt__['ufw.disable']()
        if ret['result']:
            ret['comment'] = 'UFW disabled'
            ret['changes'] = {
                'old': True,
                'new': False,
            }

    return ret


def logging(name):
    '''
    Set the log level.

    name
        One of "off", "low", "medium", "high" or "full".
    '''
    ret = {
        'name': name,
        'result': False,
        'changes': {},
        'comment': '',
    }

    current_level = __salt__['ufw.status']()['logging']
    ret['result'] = current_level == name

    if not ret['result']:
        ret['result'] = __salt__['ufw.logging'](name)
        if ret['result']:
            ret['changes'] = {
                'old': current_level,
                'new': name,
            }

    return ret


def default(name, policy):
    '''
    Set the policy for the given direction.

    name
        One of "incoming", "outgoing" or "routed".
    policy
        One of "allow", "deny" or "reject".
    '''
    ret = {
        'name': name,
        'result': False,
        'changes': {},
        'comment': '',
    }

    current_policy = __salt__['ufw.status']()['default'][name]
    ret['result'] = current_policy == policy
    if not ret['result']:
        ret['result'] = __salt__['ufw.default'](name, policy)
        if ret['result']:
            ret['comment'] = 'Policy for direction {0} changed from {1} to {2}'.format(
                    name, current_policy, policy)
            ret['changes'] = {
                'old': current_policy,
                'new': policy,
            }

    return ret

def ruleset(name, rules=None, rules_pillar=None):
    '''
    Set the firewall rules according to the specified ruleset.

    rules
        A list of rule dictionaries.
    rules_pillar
        An index within the pillar from which to source a list of rule
        dictionaries.
    '''
    ret = {
        'name': name,
        'result': False,
        'changes': {},
        'comment': '',
    }

    if not rules:
        rules = __salt__['pillar.get'](rules_pillar)
    current_rules = __salt__['ufw.status']()['rules']

    delta = _delta_ruleset(current_rules, _number_rules(rules))

    for number, rule in delta.items():
        if delta['old']:
            log.debug('[UFW] delete {0}'.format(number))
            #__salt__['ufw.delete'](number)
        if delta['new']:
            args = rule.copy()
            func = 'ufw.{0}'.format(args.pop('policy'))
            log.debug('[UFW] insert {0} {1} {2} {3}'.format(
                    number, rule['policy'], rule['direction'], rule['port']))
            #__salt__[func](args)

    return ret
