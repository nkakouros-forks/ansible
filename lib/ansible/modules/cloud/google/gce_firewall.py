#!/usr/bin/python
# Copyright 2013 Google Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: gce_firewall
version_added: "2.4"
short_description: create/destroy GCE firewall rules
description:
    - This module can create and destroy Google Compute Engine firewall rules
      U(https://cloud.google.com/compute/docs/vpc/firewalls).
      Installation/configuration instructions for the gce_* modules can
      be found at U(https://docs.ansible.com/ansible/guide_gce.html).
requirements:
    - "python >= 2.6"
    - "apache-libcloud >= 0.14.0"
author:
    - "Eric Johnson (@erjohnso) <erjohnso@google.com>""
    - "Tom Melendez (@supertom) <supertom@google.com>"
    - "Nikolaos Kakouros (@tterranigma) <tterranigma@gmail.com>"
options
    name:
        description:
            - The name of the firewall rule.
        required: true
    network:
        description:
            - The network that the rule will be applied to.
        default: default
    allowed:
        description:
            - The protocol:ports to allow ('tcp:80' or 'tcp:80,443' or 'tcp:80-800;udp:1-25').
            - A value of 'all' allows everything.
        required: true
    src_range:
        description:
            - The source IPv4 address range that the rule will filter.
            - It must be an array of subnet addresses in CIDR notation, eg 10.0.0.0/17
            - Mutually exclusive with src_tags.
        required: true
        aliases: ['src_cidr']
    src_tags:
        description:
            - Traffic originating from these instances will be filtered through the rule.
            - It must be an array of valid instance tags.
            - Mutually exclusive with src_range.
        required: true
    target_tags:
        description:
            - The target instances that will be protected by this rule.
        default: all
    state:
        description:
            - Desired state of the firewall.
        default: "present"
        choices: ["present", "absent"]
'''

EXAMPLES = '''
# Create Firewall Rule with Source Tags
- name: Create Firewall Rule w/Source Tags on the default network
  gce_net:
    name: "my-firewall-rule"
    allowed: tcp:80
    src_tags: "foo,bar"

# Allow all traffic for "exposed" instance on a network
- name: Create Firewall Rule w/Source Range
  gce_net:
    name: "my-firewall-rule"
    network: second-net
    allowed: tcp:80
    src_range: ['10.1.1.1/32']
    target_tags: exposed
'''

RETURN = '''
name:
  description: Name of the firewall rule.
  returned: always
  type: string
  sample: "my-firewall"

network:
    description: Name of the network.
    returned: always
    type: string
    sample: "my-network"

allowed:
    description: Rules (ports and protocols) specified by this firewall rule.
    returned: always
    type: string
    sample: "tcp:80;icmp"

src_range:
    description: IP address blocks a firewall rule applies to.
    returned: when specified
    type: list
    sample: [ '10.1.1.12/8' ]

src_tags:
    description: Instance Tags firewall rule applies to.
    returned: when specified while creating a firewall rule
    type: list
    sample: [ 'foo', 'bar' ]

target_tags:
    description: Instance Tags with these tags receive traffic allowed by firewall rule.
    returned: when specified while creating a firewall rule
    type: list
    sample: [ 'foo', 'bar' ]

state:
    description: State of the item operated on.
    returned: always
    type: string
    sample: "present"
'''

################################################################################
# Imports
################################################################################

try:
    from libcloud import __version__ as LIBCLOUD_VERSION
    from libcloud.compute.providers import Provider
    from libcloud.common.google import GoogleBaseError, QuotaExceededError, \
            ResourceExistsError, ResourceNotFoundError

    _ = Provider.GCE
    HAS_LIBCLOUD = True
except ImportError:
    HAS_LIBCLOUD = False

try:
    # module specific imports
    from distutils.version import LooseVersion

    # import module snippets
    from ansible.module_utils.basic import AnsibleModule
    from ansible.module_utils.gce import gce_connect
except:
    module.fail_json(
        msg     = "An unexpected error has occured while importing asible libraries.",
        changed = False
    )


################################################################################
# Constants
################################################################################

# firewall methods were introduced in 0.14.0
MINIMUM_LIBCLOUD_VERSION = '0.14.0'

PROVIDER = Provider.GCE


################################################################################
# Functions
################################################################################

def format_allowed_section(allowed):
    """Format each section of the allowed list"""
    if allowed.count(":") == 0:
        protocol = allowed
        ports = []
    elif allowed.count(":") == 1:
        protocol, ports = allowed.split(":")
    else:
        return []
    if ports.count(","):
        ports = ports.split(",")
    elif ports:
        ports = [ports]
    return_val = {"IPProtocol": protocol}
    if ports:
        return_val["ports"] = ports
    return return_val

def format_allowed(allowed):
    """Format the 'allowed' value so that it is GCE compatible."""
    return_value = []
    if allowed.count(";") == 0:
        return [format_allowed_section(allowed)]
    else:
        sections = allowed.split(";")
        for section in sections:
            return_value.append(format_allowed_section(section))
    return return_value

def sorted_allowed_list(allowed_list):
    """Sort allowed_list (output of format_allowed) by protocol and port."""
    # sort by protocol
    allowed_by_protocol = sorted(allowed_list,key=lambda x: x['IPProtocol'])
    # sort the ports list
    return sorted(allowed_by_protocol, key=lambda y: y.get('ports', []).sort())

def check_libcloud():
    # Apache libcloud needs to be installed and at least the minimum version.
    if not HAS_LIBCLOUD:
        module.fail_json(
            msg     = 'This module requires Apache libcloud %s or greater' % MINIMUM_LIBCLOUD_VERSION,
            changed = False
        )
    elif LooseVersion(LIBCLOUD_VERSION) < MINIMUM_LIBCLOUD_VERSION:
        module.fail_json(
            msg     = 'This module requires Apache libcloud %s or greater' % MINIMUM_LIBCLOUD_VERSION,
            changed = False
        )


################################################################################
# Main
################################################################################

def main():
    changed = False
    check_libcloud()

    module = AnsibleModule(
        argument_spec = dict(
            name        = dict(required=True),
            network     = dict(required=True),
            allowed     = dict(),
            src_range   = dict(type='list'),
            src_tags    = dict(type='list'),
            target_tags = dict(default='all', type='list'),
            state       = dict(default='present', choices=['present', 'absent']),
        ),
        required_if = [
            ('src_range', None, ['src_tags'])
        ],
        mutually_exclusive = [
            ['src_range', 'src_tags'],
        ],
        supports_check_mode = True,
    )

    # check if src_range is set when src_tags is not (not covered by the above)
    if module.params['src_tags'] is None and module.params['src_range'] is None:
        module.fail_json(
            msg     = "missing required arguments: src_range",
            changed = True
        )

    params = {
        'name':        module.params['name'],
        'network':     module.params['network'],
        'allowed':     module.params['allowed'],
        'src_range':   module.params['src_range'],
        'src_tags':    module.params['src_tags'],
        'target_tags': module.params['target_tags'],
        'state':       module.params['state'],
    }

    gce = gce_connect(module, PROVIDER)

    if params['state'] == 'present':
        # check if the network exists
        try:
            network = gce.ex_get_network(params['network'])
        except ResourceNotFoundError:
            module.fail_json(
                msg     = "No network '%s' found." % params['network'],
                changed = False
            )

        allowed_list = format_allowed(params['allowed'])

        # Fetch existing rule and if it exists, compare attributes
        # update if attributes changed. Create if doesn't exist.
        try:
            fw = gce.ex_get_firewall(params['name'])
        except ResourceNotFoundError:
            # Firewall rule not found so we try to create it.
            if not module.check_mode:
                gce.ex_create_firewall(params['name'], allowed_list, network=params['network'],
                    source_ranges=params['src_range'], source_tags=params['src_tags'], target_tags=params['target_tags'])
            changed = True
        else:
            # If old and new attributes are different, we update the firewall rule.
            # This implicitly lets us clear out attributes as well.

            # GCE does not support changing the network of a rule. If changed in
            # the playbook, we will trigger an error to be explicit to the user.
            # We could delete the rule and create a new one, thus "updating",
            # but the use case is extremely limited
            if fw.extra['network_name'] != params['network']:
                module.fail_json(
                    msg     = "Changing the network of a rule is not supported.",
                    changed = False
                )

            # allowed_list is required and must not be None for firewall rules.
            if allowed_list and (sorted_allowed_list(allowed_list) != sorted_allowed_list(fw.allowed)):
                fw.allowed = allowed_list
                changed = True

            # If not set, fw.source_tags will be None. Same for params['src_range']
            if fw.source_ranges != params['src_range']:
                # If these attributes are lists, we sort them first, then compare.
                # Otherwise, we update if they differ.
                if isinstance(params['src_range'], list):
                    if sorted(fw.source_ranges) != sorted(params['src_range']):
                        fw.source_ranges = params['src_range']
                        changed = True
                else:
                    fw.source_ranges = params['src_range']
                    changed = True

            # source_tags might be None; cast it to an empty list
            fw.source_tags = fw.source_tags or []

            if fw.source_tags != params['src_tags']:
                if isinstance(params['src_tags'], list):
                    if sorted(fw.source_tags) != sorted(params['src_tags']):
                        fw.source_tags = params['src_tags']
                        changed = True
                else:
                    fw.source_tags = params['src_tags']
                    changed = True

            # target_tags might be None; cast it to an empty list
            fw.target_tags = fw.target_tags or []

            if fw.target_tags != params['target_tags']:
                if isinstance(params['target_tags'], list):
                    if sorted(fw.target_tags) != sorted(params['target_tags']):
                        fw.target_tags = params['target_tags']
                        changed = True
                else:
                    fw.target_tags = params['target_tags']
                    changed = True

            if changed is True:
                if not module.check_mode:
                    gce.ex_update_firewall(fw)
                changed = True

    if params['state'] == 'absent':
        if params['name']:
            fw = None
            try:
                fw = gce.ex_get_firewall(params['name'])
            except ResourceNotFoundError:
                pass
            if fw:
                if not module.check_mode:
                    gce.ex_destroy_firewall(fw)
                changed = True

    json_output = {'changed': changed}
    json_output.update(params)

    module.exit_json(**json_output)

if __name__ == '__main__':
    main()
