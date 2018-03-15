#
# Ubiquitous Moodle
#
# @author Luke Carrier <luke@carrier.im>
# @copyright 2018 The Ubiquitous Authors
#

import re

import salt
import salt.utils


CONF_DEFAULTS = '/etc/default/ufw'
CONF_UFW = '/etc/ufw/ufw.conf'

RE_CONF_OPTION = r'^(\w+)="?(\w+)"?'

RULE_PREFIX = 'ufw '

MAP_DIRECTION_IPT_CHAIN = {
    'incoming': 'INPUT',
    'outgoing': 'OUTPUT',
    'routed': 'FORWARD',
}

MAP_POLICY_IPT_POLICY = {
    'allow': 'ACCEPT',
    'deny': 'DROP',
    'reject': 'REJECT',
}
MAP_IPT_POLICY_POLICY = dict((v, k) for k, v in MAP_POLICY_IPT_POLICY.items())


def __virtual__():
    '''
    Load the module only if ufw is installed.
    '''
    if not salt.utils.which('ufw'):
        return False
    return True


def _get_conf_values_from_string(contents):
    '''
    Get all options from the file contents.

    contents
        Raw contents of the configuration file.
    '''
    return {x.group(1): x.group(2) for x in re.finditer(
            RE_CONF_OPTION, contents, re.MULTILINE)}


def _get_conf_values_from_file(filename):
    '''
    Get all options from the contents of the specified file.

    filename
        The name of the file from which to source all options.
    '''
    with open(filename, 'r') as f:
        return _get_conf_values_from_string(f.read())


def _default_rule():
    '''
    Get the default rule.

    Template for rules, used as a base for rules. Makes for much easier test
    assertions.
    '''
    return {
        'policy': None,
        'direction': 'incoming',
        'port': None,
        'protocol': None,
        'source': None,
        'destination': None,
        'interface': None,
        'comment': None,
    }


def complete_rule(props):
    '''
    Add default values for missing properties in a rule.

    props
        A dictionary containing rule properties.
    '''
    rule = _default_rule()
    rule.update(props)
    return rule


def _parse_rule(components):
    '''
    Assemble a rule object from a given rule.

    components
        A rule object, split by " ".
    '''
    rule = _default_rule()
    rule['policy'] = components.pop(0)

    while components:
        component = components.pop(0)

        if component == 'comment':
            rule['comment'] = ''
            while components:
                rule['comment'] += ' ' + components.pop(0)
                if rule['comment'].endswith('\''):
                    rule['comment'] = rule['comment'][2:-1]
                    break
        elif component == 'from':
            rule['source'] = components.pop(0)
        elif component == 'on':
            rule['interface'] = components.pop(0)
        elif component == 'port':
            rule['port'] = int(components.pop(0))
        elif component == 'proto':
            rule['protocol'] = components.pop(0)
        elif component == 'to':
            rule['destination'] = components.pop(0)
        else:
            try:
                rule['port'] = int(component)
            except ValueError:
                port, rule['protocol'] = component.split('/')
                rule['port'] = int(port)

    return rule


def _run_ufw_cmd(args):
    '''
    Run a command against ufw with the specified args.
    '''
    return __salt__['cmd.run_all'](['ufw'] + args)


def enable():
    '''
    Enable the firewall.
    '''
    ret = _run_ufw_cmd(['--force', 'enable'])
    return ret['retcode'] == 0


def disable():
    '''
    Disable the firewall.
    '''
    ret = _run_ufw_cmd(['--force', 'disable'])
    return ret['retcode'] == 0


def default(direction, policy):
    '''
    Set the default policy.

    direction
        One of "incoming", "outgoing" or "routed".

    policy
        One of "allow", "deny" or "reject".
    '''
    ret = _run_ufw_cmd(['default', policy, direction])
    return ret['retcode'] == 0


def logging(level):
    '''
    Enable logging.

    level
        One of "off", "low", "medium", "high" or "full".
    '''
    ret = _run_ufw_cmd(['logging', level])
    return ret['retcode'] == 0


def allow(service):
    '''
    Allow the given service.

    service
        The name or port specifier for the service.
    '''
    ret = _run_ufw_cmd(['allow', service])
    return ret['retcode'] == 0


def deny(service):
    '''
    Deny the given service.

    service
        The name or port specifier for the service.
    '''
    ret = _run_ufw_cmd(['deny', service])
    return ret['retcode'] == 0


def reject(service):
    '''
    Reject the given service.

    service
        The name or port specifier for the service.
    '''
    ret = _run_ufw_cmd(['reject', service])
    return ret['retcode'] == 0


def limit():
    pass


def delete():
    pass


def insert():
    pass


def route():
    pass


def route_delete():
    pass


def route_insert():
    pass


def reload():
    '''
    Reload the firewall ruleset.
    '''
    ret = _run_ufw_cmd(['reload'])
    return ret['retcode'] == 0


def reset():
    '''
    Reset the firewall to its defaults.
    '''
    ret = _run_ufw_cmd(['--force', 'reset'])
    return ret['retcode'] == 0


def status():
    '''
    Get the current rule set.
    '''
    ret = {
        'active': None,
        'logging': None,
        'default': {},
        'rules': {},
    }

    # Status output won't contain rule or default policy information if the
    # firewall is disabled, so parse the configuration files directly.
    defaults = _get_conf_values_from_file(CONF_DEFAULTS)
    ufw = _get_conf_values_from_file(CONF_UFW)

    ret['active'] = ufw['ENABLED'] == 'yes'
    ret['logging'] = ufw['LOGLEVEL']
    for direction, chain in MAP_DIRECTION_IPT_CHAIN.items():
        policy = defaults['DEFAULT_{0}_POLICY'.format(chain)]
        ret['default'][direction] = MAP_IPT_POLICY_POLICY[policy]

    ret_rules = _run_ufw_cmd(['show', 'added'])
    for index, line in enumerate(ret_rules['stdout'].split('\n')):
        rule_number = index + 1
        if not line.startswith(RULE_PREFIX):
            continue
        components = line.split(' ')[1:]
        rule = _parse_rule(components)
        ret['rules'][rule_number] = rule

    return ret


def version():
    '''
    Get the ufw version.
    '''
    ret = _run_ufw_cmd(['version'])
    return ret['stdout']
