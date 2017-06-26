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
module: gce_net
version_added: "1.5"
short_description: create/destroy GCE networks and firewall rules
description:
    - This module can create and destroy Google Compute Engine networks and
      firewall rules U(https://cloud.google.com/compute/docs/networking).
      The I(name) parameter is reserved for referencing a network while the
      I(fwname) parameter is used to reference firewall rules.
      IPv4 Address ranges must be specified using the CIDR
      U(http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) format.
      Installation/configuration instructions for the gce* modules can
      be found at U(https://docs.ansible.com/ansible/guide_gce.html).
requirements:
    - "python >= 2.6"
    - "apache-libcloud >= 1.0.0"
author:
- "Eric Johnson (@erjohnso) <erjohnso@google.com>""
- "Tom Melendez (@supertom) <supertom@google.com>"
- "Nikolaos Kakouros (@tterranigma) <tterranigma@gmail.com>"
options:
    name:
        description:
            - The name of the network.
        required: true
    mode:
        version_added: "2.2"
        description:
            - Network mode for Google Cloud.
            - "legacy" indicates a network with an IP address range.
            - "auto" automatically generates subnetworks in different regions.
            - "custom" uses networks to group subnets of user specified IP address ranges.
            - See U(https://cloud.google.com/compute/docs/networking#network_types) for more information.
        choices: ["legacy", "auto", "custom"]
        default: "legacy"
    subnet_name:
        version_added: "2.2"
        description:
            - The name of the subnet to create.
            - Required when I(mode=custom)
            - Only used when I(mode=custom)
    subnet_region:
        version_added: "2.2"
        description:
            - The region in which to create the subnet.
            - Required when I(mode=custom)
            - Only used when I(mode=custom)
    subnet_desc:
        version_added: "2.2"
        description:
            - A description for the subnet.
            - Only used when I(mode=custom)
    ipv4_range:
        description:
            - The IPv4 address range in CIDR notation for the network.
            - Required when I(mode=legacy) or I(mode=custom)
            - Only used when I(mode=legacy) or I(mode=custom)
        aliases: ['cidr']
    fwname:
        description:
            - The name of the firewall rule.
        aliases: ['fwrule']
    allowed:
        description:
            - The protocol:ports to allow ('tcp:80' or 'tcp:80,443' or 'tcp:80-800;udp:1-25').
            - This parameter is mandatory when creating or updating a firewall rule.
        default: null
    src_range:
        description:
            - The source IPv4 address range in CIDR notation.
        aliases: ['src_cidr']
    src_tags:
        description:
            - The source instance tags for creating a firewall rule.
    target_tags:
        version_added: "1.9"
        description:
            - The target instance tags for creating a firewall rule.
    state:
        description:
            - Desired state of the network or firewall.
        default: "present"
        choices: ["active", "present", "absent", "deleted"]
'''

EXAMPLES = '''
# Create a 'legacy' Network
- name: Create Legacy Network
  gce_net:
    name: legacynet
    ipv4_range: '10.24.17.0/24'
    mode: legacy
    state: present

# Create an 'auto' Network
- name: Create Auto Network
  gce_net:
    name: autonet
    mode: auto
    state: present

# Create a 'custom' Network
- name: Create Custom Network
  gce_net:
    name: customnet
    mode: custom
    subnet_name: "customsubnet"
    subnet_region: us-east1
    ipv4_range: '10.240.16.0/24'
    state: "present"

# Create Firewall Rule with Source Tags
- name: Create Firewall Rule w/Source Tags
  gce_net:
    name: default
    fwname: "my-firewall-rule"
    allowed: tcp:80
    state: "present"
    src_tags: "foo,bar"

# Create Firewall Rule with Source Range
- name: Create Firewall Rule w/Source Range
  gce_net:
    name: default
    fwname: "my-firewall-rule"
    allowed: tcp:80
    state: "present"
    src_range: ['10.1.1.1/32']

# Create Custom Subnetwork
- name: Create Custom Subnetwork
  gce_net:
    name: privatenet
    mode: custom
    subnet_name: subnet_example
    subnet_region: us-central1
    ipv4_range: '10.0.0.0/16'
'''

RETURN = '''
allowed:
    description: Rules (ports and protocols) specified by this firewall rule.
    returned: When specified
    type: string
    sample: "tcp:80;icmp"

fwname:
    description: Name of the firewall rule.
    returned: When specified
    type: string
    sample: "my-fwname"

ipv4_range:
    description: IPv4 range of the specified network or subnetwork.
    returned: when specified or when a subnetwork is created
    type: string
    sample: "10.0.0.0/16"

name:
    description: Name of the network.
    returned: always
    type: string
    sample: "my-network"

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

state:
    description: State of the item operated on.
    returned: always
    type: string
    sample: "present"

subnet_name:
    description: Name of the subnetwork.
    returned: when specified or when a subnetwork is created
    type: string
    sample: "my-subnetwork"

subnet_region:
    description: Region of the specified subnet.
    returned: when specified or when a subnetwork is created
    type: string
    sample: "us-east1"

target_tags:
    description: Instance Tags with these tags receive traffic allowed by firewall rule.
    returned: when specified while creating a firewall rule
    type: list
    sample: [ 'foo', 'bar' ]
'''

################################################################################
# Imports
################################################################################

try:
    from libcloud import __version__ as LIBCLOUD_VERSION
    # from libcloud.compute.providers import get_driver
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
    from ansible.module_utils.basic import *
    from ansible.module_utils.gce import *
except:
    module.fail_json(
        msg     = "An unexpected error has occured while importing asible libraries.",
        changed = False
    )


################################################################################
# Constants
################################################################################

# ex_create_route was introduced in libcloud 0.17.0
MINIMUM_LIBCLOUD_VERSION = '1.0.0'

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
            name                  = dict(required=True),
            mode                  = dict(default='auto', choices=['legacy', 'auto', 'custom']),
            subnet_name           = dict(),
            subnet_region         = dict(),
            subnet_desc           = dict(),
            ipv4_range            = dict(),
            fwname                = dict(),
            allowed               = dict(),
            src_range             = dict(default=[], type='list'),
            src_tags              = dict(default=[], type='list'),
            target_tags           = dict(default=[], type='list'),
            state                 = dict(default='present'),
        ),
        required_if = [
            ('mode', 'custom', ['subnet_name', 'ipv4_range', 'subnet_region']),
            ('mode', 'legacy', ['ipv4_range']),
        ],
        required_together = ['subnet_name', 'subnet_region'],
        mutually_exclusive = ['src_range', 'src_tags']
    )

    gce = gce_connect(module)

    params = {
        'name'          : module.params['name'],
        'mode'          : module.params['mode'],
        'subnet_name'   : module.params['subnet_name'],
        'subnet_region' : module.params['subnet_region'],
        'subnet_desc'   : module.params['subnet_desc'],
        'ipv4_range'    : module.params['ipv4_range'],
        'fwname'        : module.params['fwname'],
        'allowed'       : module.params['allowed'],
        'src_range'     : module.params['src_range'],
        'src_tags'      : module.params['src_tags'],
        'target_tags'   : module.params['target_tags'],
        'state'         : module.params['state'],
    }

    json_output = {'state': params['state']}

    if params['state'] in ['active', 'present']:
        network = None
        subnet = None

        # check if given network and subnet already exist
        try:
            network = gce.ex_get_network(params['name'])
        except ResourceNotFoundError:
            pass
        else:
            json_output['name'] = params['name']
            if params['mode'] == 'legacy':
                json_output['ipv4_range'] = network.cidr
            if params['mode'] == 'custom':
                try:
                    subnet = gce.ex_get_subnetwork(params['subnet_name'], region=params['subnet_region'])
                except ResourceNotFoundError:
                    pass
                else:
                    json_output['subnet_name'] = params['subnet_name']
                    json_output['ipv4_range'] = subnet.cidr

        # user wants to create a new network that doesn't yet exist
        if params['name'] and not network:
            args = [params['ipv4_range'] if params['mode'] =='legacy' else None]
            kwargs = {'mode': params['mode']}

            network = gce.ex_create_network(params['name'], *args, **kwargs)
            json_output['name'] = params['name']
            json_output['ipv4_range'] = params['ipv4_range']
            changed = True

        # user also wants to create a new subnet
        if params['name'] and params['subnet_name'] and not subnet:
            subnet = gce.ex_create_subnetwork(params['subnet_name'], cidr=params['ipv4_range'],
                network=params['name'], region=params['subnet_region'], description=params['subnet_desc'])
            json_output['subnet_name'] = params['subnet_name']
            json_output['ipv4_range'] = params['ipv4_range']
            changed = True

        if params['fwname']:
            # user creating a firewall rule
            if not params['allowed'] and not params['src_range'] and not params['src_tags']:
                if changed and network:
                    module.fail_json(
                        msg     = "Network created, but missing required firewall rule parameter(s)",
                        changed = True
                    )

                module.fail_json(
                    msg     = "Missing required firewall rule parameter(s)",
                    changed = False
                )

            allowed_list = format_allowed(params['allowed'])

            # Fetch existing rule and if it exists, compare attributes
            # update if attributes changed.  Create if doesn't exist.
            try:
                fw = gce.ex_get_firewall(params['fwname'])
            # Firewall rule not found so we try to create it.
            except ResourceNotFoundError:
                gce.ex_create_firewall(params['fwname'], allowed_list, network=params['name'],
                    source_ranges=params['src_range'], source_tags=params['src_tags'], target_tags=params['target_tags'])
                changed = True
            else:
                fw_changed = False

                # If old and new attributes are different, we update the firewall rule.
                # This implicitly lets us clear out attributes as well.
                # allowed_list is required and must not be None for firewall rules.
                if allowed_list and (sorted_allowed_list(allowed_list) != sorted_allowed_list(fw.allowed)):
                    fw.allowed = allowed_list
                    fw_changed = True

                # source_ranges might not be set in the project; cast it to an empty list
                fw.source_ranges = fw.source_ranges or []

                # If these attributes are lists, we sort them first, then compare.
                # Otherwise, we update if they differ.
                if fw.source_ranges != params['src_range']:
                    if isinstance(params['src_range'], list):
                        if sorted(fw.source_ranges) != sorted(params['src_range']):
                            fw.source_ranges = params['src_range']
                            fw_changed = True
                    else:
                        fw.source_ranges = params['src_range']
                        fw_changed = True

                # source_tags might not be set in the project; cast it to an empty list
                fw.source_tags = fw.source_tags or []

                if fw.source_tags != params['src_tags']:
                    if isinstance(params['src_tags'], list):
                        if sorted(fw.source_tags) != sorted(params['src_tags']):
                            fw.source_tags = params['src_tags']
                            fw_changed = True
                    else:
                        fw.source_tags = params['src_tags']
                        fw_changed = True

                # target_tags might not be set in the project; cast it to an empty list
                fw.target_tags = fw.target_tags or []

                if fw.target_tags != params['target_tags']:
                    if isinstance(params['target_tags'], list):
                        if sorted(fw.target_tags) != sorted(params['target_tags']):
                            fw.target_tags = params['target_tags']
                            fw_changed = True
                    else:
                        fw.target_tags = params['target_tags']
                        fw_changed = True

                if fw_changed is True:
                    gce.ex_update_firewall(fw)
                    changed = True

            json_output['fwname']      = params['fwname']
            json_output['allowed']     = params['allowed']
            json_output['src_range']   = params['src_range']
            json_output['src_tags']    = params['src_tags']
            json_output['target_tags'] = params['target_tags']

    if params['state'] in ['absent', 'deleted']:
        if params['fwname']:
            json_output['fwname'] = params['fwname']
            fw = None
            try:
                fw = gce.ex_get_firewall(params['fwname'])
            except ResourceNotFoundError:
                pass
            if fw:
                gce.ex_destroy_firewall(fw)
                changed = True
        elif params['subnet_name']:
            json_output['subnet_name'] = params['subnet_name']
            subnet = None
            try:
                subnet = gce.ex_get_subnetwork(params['subnet_name'], region=params['subnet_region'])
            except ResourceNotFoundError:
                pass
            if subnet:
                gce.ex_destroy_subnetwork(subnet)
                changed = True
        elif params['name']:
            json_output['name'] = params['name']
            network = None
            try:
                network = gce.ex_get_network(params['name'])
            except ResourceNotFoundError:
                pass
            if network:
                gce.ex_destroy_network(network)
                changed = True

    json_output['changed'] = changed
    module.exit_json(**json_output)

if __name__ == '__main__':
    main()
