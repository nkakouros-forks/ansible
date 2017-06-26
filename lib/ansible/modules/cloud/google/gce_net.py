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
short_description: create/destroy GCE networks and subnets
description:
    - This module can create and destroy Google Compute Engine networks and
      subnets U(https://cloud.google.com/compute/docs/vpc/).
      Installation/configuration instructions for the gce_* modules can
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
    state:
        description:
            - Desired state of the network.
        default: "present"
        choices: ["present", "absent"]
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

# Create a 'custom' Network
- name: Create Custom Network
  gce_net:
    name: customnet
    mode: custom
    subnet_name: "customsubnet"
    subnet_region: us-east1
    ipv4_range: '10.240.16.0/24'

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
name:
    description: Name of the network.
    returned: always
    type: string
    sample: "my-network"

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

ipv4_range:
    description: IPv4 range of the specified network or subnetwork.
    returned: when specified or when a subnetwork is created
    type: string
    sample: "10.0.0.0/16"

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

# subnet methods were introduced in 1.0.0
MINIMUM_LIBCLOUD_VERSION = '1.0.0'

PROVIDER = Provider.GCE


################################################################################
# Functions
################################################################################

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
            state                 = dict(default='present', choices=['present', 'absent']),
        ),
        required_if = [
            ('mode', 'custom', ['subnet_name', 'ipv4_range', 'subnet_region']),
            ('mode', 'legacy', ['ipv4_range']),
        ],
        required_together = ['subnet_name', 'subnet_region'],
    )

    params = {
        'name':          module.params['name'],
        'mode':          module.params['mode'],
        'subnet_name':   module.params['subnet_name'],
        'subnet_region': module.params['subnet_region'],
        'subnet_desc':   module.params['subnet_desc'],
        'ipv4_range':    module.params['ipv4_range'],
        'state':         module.params['state'],
    }

    gce = gce_connect(module, PROVIDER)

    if params['state'] == 'present':
        network = None
        subnet = None

        # check if given network and subnet already exist
        try:
            network = gce.ex_get_network(params['name'])
        except ResourceNotFoundError:
            # user wants to create a new network that doesn't yet exist
            args = [params['ipv4_range'] if params['mode'] =='legacy' else None]
            kwargs = {'mode': params['mode']}
            network = gce.ex_create_network(params['name'], *args, **kwargs)
            changed = True

        if params['mode'] == 'custom':
            try:
                subnet = gce.ex_get_subnetwork(params['subnet_name'], region=params['subnet_region'])
            except ResourceNotFoundError:
                # user also wants to create a new subnet
                subnet = gce.ex_create_subnetwork(params['subnet_name'], cidr=params['ipv4_range'],
                    network=params['name'], region=params['subnet_region'], description=params['subnet_desc'])
                changed = True

    if params['state'] == 'absent':
        if params['subnet_name']:
            subnet = None
            try:
                subnet = gce.ex_get_subnetwork(params['subnet_name'], region=params['subnet_region'])
            except ResourceNotFoundError:
                pass
            if subnet:
                gce.ex_destroy_subnetwork(subnet)
                changed = True
        elif params['name']:
            network = None
            try:
                network = gce.ex_get_network(params['name'])
            except ResourceNotFoundError:
                pass
            if network:
                gce.ex_destroy_network(network)
                changed = True

    json_output = {'changed': changed}
    json_output.update(params)

    module.exit_json(**json_output)

if __name__ == '__main__':
    main()
