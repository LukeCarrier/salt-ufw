# UFW management for Salt

An attempt at getting stateful management of UFW, the Uncomplicated Firewall,
into Salt. Unfortunately we won't be committing further time to it until some
issues in UFW are resolved.

---

## Issues preventing progress

* UFW's user added rules are often expanded into two separate rules, one for
  IPv4 and another for IPv6. This means that a single rule can end up becoming
  two rules in the iptables backend.
* UFW doesn't allow adding IPv6 rules before IPv4 rules.
  [[#1368411](https://bugs.launchpad.net/ufw/+bug/1368411)]
