#!/usr/bin/python

from __future__ import absolute_import
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: vmware_guest_network
short_description: Modify networks
description: >
   A longer description here
version_added: '2.8'
author:
- Author name
requirements:
- python >= 2.6
- PyVmomi
options:
  name:
    description:
    - Name of the virtual machine to work with.
    - Virtual machine names in vCenter are not necessarily unique, which may be problematic, see I(name_match).
    - 'If multiple virtual machines with same name exists, then I(folder) is required parameter to
       identify uniqueness of the virtual machine.'
    - This parameter is required if I(uuid) is not supplied
    - This parameter is case sensitive.
    required: yes
  name_match:
    description:
    - If multiple virtual machines matching the name, use the first or last found.
    default: 'first'
    choices: [ first, last ]
  uuid:
    description:
    - UUID of the virtual machine to manage if known, this is VMware's unique identifier.
    - This parameter is required if I(name) is not supplied.
  folder:
    description:
    - Absolute path to find an the virtual machine.
    - The folder should include the datacenter. ESX's datacenter is ha-datacenter.
    - This parameter is case sensitive.
    - 'If multiple machines are found with same name, this parameter is used to identify
       uniqueness of the virtual machine.'
    - 'Examples:'
    - '*  folder: /ha-datacenter/vm'
    - '*  folder: ha-datacenter/vm'
    - '*  folder: /datacenter1/vm'
    - '*  folder: datacenter1/vm'
    - '*  folder: /datacenter1/vm/folder1'
    - '*  folder: datacenter1/vm/folder1'
    - '*  folder: /folder1/datacenter1/vm'
    - '*  folder: folder1/datacenter1/vm'
    - '*  folder: /folder1/datacenter1/vm/folder2'
  wait_for_ip_address:
    description:
    - Wait until vCenter detects an IPv4 address for the virtual machine.
    - This requires vmware-tools (vmtoolsd) to properly work
    - "vmware-tools needs to be installed on the given virtual machine in order to work with this parameter."
    default: 'yes'
    type: bool
  force:
    description:
    - Power off the machine before applying changes if it is not already powered on.
    default: 'no'
    type: bool
  datacenter:
    description:
    - Destination datacenter for the deploy operation.
    - This parameter is case sensitive.
    default: ha-datacenter
  mac_addresses:
    description:
    - mac address(es) to set for the virtual machine.
    - 'Can be in the following format:'
    - ' - (string) single mac address'
    - ' - (list) list of strings for multiple mac addresses'
    - ' - (list) list of dicts containing the key "mac" (useful when you want to use the same object
          as when creating the machine with wmare_guest). All other keys in the dict are ignored.'
    - 'IMPORTANT: Number of mac addresses provided must match the number of NICs on the VM'
  gather_facts:
    description:
    - Gather facts about the instance and return them after finished running
    default: 'yes'
    type: bool
extends_documentation_fragment: vmware.documentation
'''

EXAMPLES = r'''
- name: Set mac addresses using the values from M(vmware_guest)'s I(networks)
  vmware_guest:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    validate_certs: no
    folder: /DC1/vm/
    name: "{{ inventory_hostname }}"
    state: poweredon
    mac_addresses:
    - name: VM Network 1
      mac: aa:bb:dd:aa:00:14
      ip: 10.10.10.100
      netmask: 255.255.255.0
      device_type: vmxnet3
    - name: VM Network 2
      mac: aa:bb:dd:aa:00:15
      ip: 10.10.11.100
      netmask: 255.255.255.0
      device_type: vmxnet3
    wait_for_ip_address: yes
  delegate_to: localhost

- name: Set mac addresses using a list of strings
  vmware_guest:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    validate_certs: no
    folder: /testvms
    name: testvm_2
    state: poweredon
    mac_addresses:
    - aa:bb:dd:aa:00:14
    - aa:bb:dd:aa:00:15
    - aa:bb:dd:aa:00:16
    wait_for_ip_address: yes
  delegate_to: localhost

- name: Set mac address for machine with single NIC
  vmware_guest:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    validate_certs: no
    name: testvm-2
    mac_addresses:
    - aa:bb:cc:dd:ee:ff
  delegate_to: localhost
'''

RETURN = r'''
instance:
    description: metadata about the virtual machine
    returned: when I(gather_facts) is true
    type: dict
    sample: None
'''

import re
import time
import socket
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import (gather_vm_facts, vmware_argument_spec, PyVmomi,
                                         wait_for_poweroff, wait_for_task, _get_vm_prop)
from pyVmomi import vim

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True

def is_valid_mac_addr(mac_addr):
    """ Check if mac address is valid
    Args:
        mac_addr: string to validate as MAC address

    Returns: (Boolean) True if string is valid MAC address, otherwise False
    """
    mac_addr_regex = re.compile('[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$')
    return bool(mac_addr_regex.match(mac_addr))

class PyVmomiHelper(PyVmomi):
    def __init__(self, module):
        super(PyVmomiHelper, self).__init__(module)

    @staticmethod
    def gather_vm_ipv4_addresses(vm):
        """ Collect all ipv4 addresses of a VM

        Args:
            vm: pyVmomi.VmomiSupport.vim.VirtualMachine object to get addresses for

        Returns: (dict) IPv4 addresses split up by mac addresses of NIC
        """
        net_dict = {}
        vmnet = _get_vm_prop(vm, ('guest', 'net')) or []
        for device in vmnet:
            net_dict[device.macAddress] = [addr for addr in device.ipAddress
                                           if is_valid_ipv4_address(addr)]
        return net_dict

    def run_command(self, vm, executable, args=''):
        """ Run a command on VMWare guest

        Args:
            vm: pyVmomi.VmomiSupport.vim.VirtualMachine object to run command on
            executable: Full path to executable to run
            args: (Optional) arguments for the command
        """
        username = self.params.get('guest_user')
        password = self.params.get('guest_user_pw')

        creds = vim.vm.guest.NamePasswordAuthentication(username=username, password=password)
        pm = self.content.guestOperationsManager.processManager
        ps = vim.vm.guest.ProcessManager.ProgramSpec(
                programPath=executable,
                arguments=args)
        return pm.StartProgramInGuest(vm, creds, ps)


    def gather_vm_facts(self, vm):
        """ Wrapper around vmware module util's gather facts that sends always sends
        the content of this object.

        Args:
            vm: pyVmomi.VmomiSupport.vim.VirtualMachine object to gather facts about

        Returns: (dict) Facts about the virtual machine object in VMWare
        """
        return gather_vm_facts(self.content, vm)


    def wait_for_vm_ip(self, vm, timeout=300, interval=15):
        """ Wait for a virtual machine to get assigned an IPv4 address

        Args:
            vm: pyVmomi.VmomiSupport.vim.VirtualMachine object to wait for
            timeout: (Optional) maximum number of seconds to wait for an address
            interval: (Optional) seconds between polls

        Returns: (bool) True if IPv4 address detected, False if timeout
        """
        while timeout > 0:
            addresses = self.gather_vm_ipv4_addresses(vm)
            for nic, addr_list in addresses.items():
                if isinstance(addr_list, list) and len(addr_list) > 0:
                    return True
                elif isinstance(addr_list, list):
                    self.module.fail_json(msg='addr_list is %d entries long' % len(addr_list))
                else:
                    self.module.fail_json(msg='addr_list is of type %s' % type(addr_list))
            time.sleep(interval)
            timeout -= interval

        return False

    def set_vm_mac_addresses(self, vm, mac_addresses):
        """ Set the mac address(es) of a virtual machine based on the params of the module

        Args:
            vm: pyVmomi.VmomiSupport.vim.VirtualMachine object to set the mac address(es) for

        Returns: (dict) results to be returned by the module
        """

        result = dict()

        vm_nics = [device for device in vm.config.hardware.device
                   if isinstance(device, vim.vm.device.VirtualEthernetCard)]


        # Verify that provided list of mac addresses have the same length as machine's list of network interfaces.
        if not len(vm_nics) == len(mac_addresses):
            self.module.fail_json(msg='Number of provided network interfaces to set mac address '
                                      'for (%d) does not match number of network interfaces '
                                      'available on virtual machine (%d).'
                                      % (len(vm_nics), len(mac_addresses)))



        device_changes = []
        # Iterate through the NICs/mac addresses and queue changes
        for i in range(0, len(vm_nics)):
            desired_mac_addr = mac_addresses[i]
            current_nic = vm_nics[i]

            # Skip NIC if mac address already in desired state
            if desired_mac_addr == current_nic.macAddress:
                continue

            nicspec = vim.vm.device.VirtualDeviceSpec()
            nicspec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            nicspec.device = current_nic
            nicspec.device.addressType = 'manual'
            nicspec.device.macAddress = desired_mac_addr
            device_changes.append(nicspec)

        num_changes = len(device_changes)


        # Return early if no changes are detected
        if num_changes == 0:
            result['msg'] = 'All mac addresses are already in desired state'
            return result

        result['msg'] = "%d mac address%s changed" % (num_changes, '' if num_changes == 1 else 'es')
        result['changed'] = True

        # Return early if check mode is enabled
        if self.module.check_mode:
            return result


        # Verify that VM is powered off before applying changes
        if vm.summary.runtime.powerState.lower() == 'poweredon':
            if self.params['force']:
                vm.PowerOff()
                wait_for_poweroff(vm)
            else:
                self.module.fail_json(msg='Virtual machine %s is powered on. Please power off machine '
                                          'or use "force" parameter.' % vm.name)

        # Apply changes and wait for the task to finish
        config_spec = vim.vm.ConfigSpec(deviceChange=device_changes)
        task = vm.ReconfigVM_Task(config_spec)
        wait_for_task(task)


        return result

    def sanitize_network_params(self):
        """
        Sanitize user provided network provided params

        Returns: A sanitized list of network params, else fails

        """
        network_interfaces = []
        for network in self.params['networks']:
            network['state'] = network.get('state', 'present')

            if 'mac' not in network and 'device_config_id' not in network:
                self.module.fail_json(msg='Please specify either "mac" or "device_config_id".')

            if nic['state'] == 'present':
                if 'name' not in network and 'vlan' not in network:
                    #TODO Error message
                    self.module.fail_json(msg="Network name or VLAN ID is required when not absent")

                #TODO Implement cache
                if 'name' in network and self.cache.get_network(network['name']) is None:
                    self.module.fail_json(msg="Network '%(name)s' does not exist." % network)
                elif 'vlan' in network:
                    dvps = self.cache.get_all_objs(self.content, [vim.dvs.DistributedVirtualPortgroup])
                    for dvp in dvps:
                        if hasattr(dvp.config.defaultPortConfig, 'vlan') and \
                                isinstance(dvp.config.defaultPortConfig.vlan.vlanId, int) and \
                                str(dvp.config.defaultPortConfig.vlan.vlanId) == str(network['vlan']):
                            network['name'] = dvp.config.name
                            break
                        if 'dvswitch_name' in network and \
                                dvp.config.distributedVirtualSwitch.name == network['dvswitch_name'] and \
                                dvp.config.name == network['vlan']:
                            network['name'] = dvp.config.name
                            break

                        if dvp.config.name == network['vlan']:
                            network['name'] = dvp.config.name
                            break
                    else:
                        self.module.fail_json(msg="VLAN '%(vlan)s' does not exist." % network)

            if 'type' in network:
                if network['type'] not in ['dhcp', 'static']:
                    self.module.fail_json(msg="Network type '%(type)s' is not a valid parameter."
                                              " Valid parameters are ['dhcp', 'static']." % network)
                if network['type'] != 'static' and ('ip' in network or 'netmask' in network):
                    self.module.fail_json(msg='Static IP information provided for network "%(name)s",'
                                              ' but "type" is set to "%(type)s".' % network)
            else:
                # Type is optional parameter, if user provided IP or Subnet assume
                # network type as 'static'
                if 'ip' in network or 'netmask' in network:
                    network['type'] = 'static'
                else:
                    # User wants network type as 'dhcp'
                    network['type'] = 'dhcp'

            if network.get('type') == 'static':
                if 'ip' in network and 'netmask' not in network:
                    self.module.fail_json(msg="'netmask' is required if 'ip' is"
                                              " specified under VM network list.")
                if 'ip' not in network and 'netmask' in network:
                    self.module.fail_json(msg="'ip' is required if 'netmask' is"
                                              " specified under VM network list.")

            validate_device_types = ['pcnet32', 'vmxnet2', 'vmxnet3', 'e1000', 'e1000e', 'sriov']
            if 'device_type' in network and network['device_type'] not in validate_device_types:
                self.module.fail_json(msg="Device type specified '%s' is not valid."
                                          " Please specify correct device"
                                          " type from ['%s']." % (network['device_type'],
                                                                  "', '".join(validate_device_types)))

            if 'mac' in network and not PyVmomiDeviceHelper.is_valid_mac_addr(network['mac']):
                self.module.fail_json(msg="Device MAC address '%s' is invalid."
                                          " Please provide correct MAC address." % network['mac'])

            network_devices.append(network)

        return network_devices

    def apply_vm_network_interface_changes(self, vm):
        current_network_interfaces = [device for device in vm.config.hardware.devices
                                      if isinstance(device, vim.vm.device.VirtualEthernetCard)]

        desired_network_interfaces = self.sanitize_network_params()

        # Queue all changes from "networks" param
        for desired_nic in desired_network_interfaces:
            if 'device_config_id' in desired_nic:
                current_nic = next(lambda nic: nic.key == desired_nic['device_config_id'],
                                   current_network_interfaces)
            elif 'mac' in desired_nic:
                current_nic = next(lambda nic: nic.macAddress == desired_nic['mac'],
                                   current_network_interfaces)
            else:
                #TODO: Check this before
                self.module.fail_json('No identifier specified for nic.')

            if current_nic is None:
                # New NIC
                pass
            else:
                # Queue changes
                pass



def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(
        state=dict(type='str', default='present',
                   choices=['present', 'absent']),
        name=dict(type='str'),
        name_match=dict(type='str', choices=['first', 'last'], default='first'),
        uuid=dict(type='str'),
        folder=dict(type='str'),
        datacenter=dict(type='str', default='ha-datacenter'),
        wait_for_ip_address=dict(type='bool', default=True),
        networks=dict(type='list', required=True),
        force=dict(type='bool', default=False),
        gather_facts=dict(type='bool', default=True),
        remove_other=dict(type='bool', default=False),
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=[
                               ['name', 'uuid']
                           ])

    networks = module.params['networks']

    """
        # Convert `mac_addresses` to list of strings if necessary.
        if all([isinstance(obj, dict) and 'mac' in obj for obj in mac_addresses]):
            mac_addresses = [obj['mac'] for obj in mac_addresses]
        elif all([isinstance(obj, str) for obj in mac_addresses]):
            pass
        # Fail if list does not follow requirements
        else:
            module.fail_json(msg='C(mac_addresses) list must either contain '
                                 'only strings or only dicts with the key \'mac\'.')

        # Verify that all mac addresses are legal
        for mac_address in mac_addresses:
            if not is_valid_mac_addr(mac_address):
                module.fail_json(msg='\'%s\' is not a valid mac address.' % mac_address)
    """

    result = {'failed': False, 'changed': False}

    pyv = PyVmomiHelper(module)

    # Find virtual machine based on the module params
    vm = pyv.get_vm()

    # Exit if the VM does not exist
    if not vm:
        identifier_str = ('name "%s"' % module.params['name'] if  module.params['name']
                          else 'uuid %s' % module.params['uuid'])
        module.fail_json(msg='Virtual machines with %s not found.' % identifier_str)

    vm_nics = [device for device in vm.config.hardware.device
               if isinstance(device, vim.vm.device.VirtualEthernetCard)]

    if module.params['gather_facts']:
        result['instance'] = pyv.gather_vm_facts(vm)

    module.exit_json(**result)

if __name__ == '__main__':
    main()
