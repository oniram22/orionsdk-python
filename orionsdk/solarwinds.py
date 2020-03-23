# -*- coding: utf-8 -*-
"""SolarWinds Class Overview

The following class is used to create an object that is an abstraction of a SolarWinds Orion instance.  The object
provides simple getter and setter methods for common SolarWinds actions.  These methods abstract out the underlying
SWIS SDK and SWQL calls making SolarWinds automation more accessible to a broader audience.

"""

import logging
from orionsdk import SwisClient


class SolarWinds:

    def __init__(self, npm_server, username, password, logger=None):

        self.logger = logger or logging.getLogger('__name__')

        # Create the SWIS client for use throughout the instance.
        self.swis = SwisClient(npm_server, username, password)
        self.logger.info("__init__ - SolarWinds object successfully instantiated.")

    @staticmethod
    def validate_login_credentials(server, username, password):
        """ Checks to see if the supplied login credentials will work with the provided SolarWinds Orion server.
            This is a static method that can be used as a test authentication prior to instantiating the SolarWinds
            object.

            Args:
                server(string): The name or IP of the target SolarWinds Orion server.
                username(string): The username to validate.
                password(string): The password to validate.

            Returns:
                True: The login to the target server was successful using the supplied credentials.
                False: The login to the target server was not successful using the supplied credentials.

        """

        try:
            # Query a basic SolarWinds table as a test.
            swisclient = SwisClient(server, username, password)
            swisclient.query("SELECT Name, Version, IsActive FROM Orion.Module")
            return True

        except Exception:
            return False

    ###################################################################################################################
    ##  SolarWinds IP Address Manager (IPAM)                                                                         ##
    ###################################################################################################################

    def add_dns_a_record_with_ptr_to_ipam(self, name, ip_address, server, domain):
        """ Add a DNS A and PTR record to the specified domain using the provided name and IP address.

            Args:
                name(string): The name to be used for the new DNS record.
                ip_address(string):  The IP address to be used for the new DNS record.
                server(string): The name or IP of the DNS server that hosts the domain.
                domain(string): The domain that the new DNS record will be added to.

            Returns:
                True: The DNS record was successfully added to the domain.
                False: The DNS record was not successfully added to the domain.

        """

        try:
            results = self.swis.invoke('IPAM.IPAddressManagement', 'AddDnsARecordWithPtr', name, ip_address, server,
                                       domain)
            self.logger.info("add_dns_a_record_with_ptr_to_ipam - AddDnsARecordWithPtr invoke results: %s", results)

            if results != "Operation was successful":
                return False

        except Exception as error:
            self.logger.info("add_dns_a_record_with_ptr_to_ipam - AddDnsARecordWithPtr invoke error: %s", error)
            return False

        return True

    def add_subnet_to_ipam(self, subnet_address, subnet_cidr, folder_id="", subnet_name="", comments="", vlan_id="",
                           location=""):
        """ Add the provided subnet to IPAM if it does not already exist.  Then set the folder location, comments,
            vlan_id, and location information.

            Args:
                subnet_address(string): The IPv4 network address of the subnet.
                subnet_cidr(string): The IPv4 mask of the subnet in CIDR notation.
                folder_id(string): The ID of the parent folder where the subnet should be placed.
                subnet_name(string): The name to use for the subnet object.
                comments(string): The comments to add to the subnet object.
                vlan_id(string): The vlan ID to add to the subnet object.
                location(string): The location to add to the subnet object.

            Returns:
                True: The subnet was successfully added to IPAM.
                False: The subnet either already existed or was not successfully added to IPAM.
        """

        # Check to see if the subnet already exists.
        uri = self.get_ipam_subnet_uri(subnet_address, subnet_cidr)

        # If the subnet exists return False, otherwise create it.
        if uri:
            return False
        else:
            try:
                results = self.swis.invoke('IPAM.SubnetManagement', 'CreateSubnet', subnet_address, subnet_cidr)
                self.logger.info("add_subnet_to_ipam - CreateSubnet invoke results: %s", results)

            except Exception as error:
                self.logger.info("add_subnet_to_ipam - CreateSubnet invoke error: %s", error)
                return False

            uri = self.get_ipam_subnet_uri(subnet_address, subnet_cidr)

        # Update the subnets attributes.
        try:
            if subnet_name:
                self.swis.update(uri, FriendlyName=subnet_name)

            if vlan_id:
                self.swis.update(uri, VLAN=vlan_id)

            if comments:
                self.swis.update(uri, comments=comments)

            if location:
                self.swis.update(uri, location=location)

            if folder_id:
                self.swis.update(uri, ParentId=folder_id)

        except Exception as error:
            self.logger.info("add_subnet_to_ipam - update error: %s", error)
            return False

        return True

    def get_next_available_ip_for_subnet(self, subnet_address, subnet_mask):
        """ Gets the the next available IP address for the provided subnet.

        Args:
            subnet_address(string): The IPv4 network address for the subnet.
            subnet_mask(string): The IPv4 subnet mask for the subnet.

        Returns:
            (string): The next available IP address in the specified subnet.  If no IP is found or the
                subnet does not exists, the string "Not Found" is returned.

    """

        try:
            results = self.swis.invoke('IPAM.SubnetManagement', 'GetFirstAvailableIp', subnet_address, subnet_mask)
            self.logger.info("get_next_available_ip_from_subnet - GetFirstAvailableIP invoke results: %s", results)

        except Exception as error:
            self.logger.info("get_next_available_ip_for_subnet - GetFirstAvailableIP invoke error: %s", error)
            return "Not Found"

        return results

    def get_ipam_folder_id(self, folder_name):
        """ Gets the folder ID for a given top level folder name.

            Args:
                folder_name(string): The name of the top level folder.

            Returns:
                (string): The ID for the top level folder.  If no folder is found it returns an empty string.

        """

        try:
            results = self.swis.query('SELECT Groupid FROM IPAM.GroupNode WHERE FriendlyName=@folder_name',
                                      folder_name=folder_name)
            self.logger.info("get_ipam_folder_id - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_ipam_folder_id - query error: %s", error)
            return ""

        return results['results'][0]['Groupid']

    def get_ipam_subfolder_id(self, parent_id, subfolder_name):
        """ Gets the subfolder ID for a given parent ID and subfolder name.

            parent_id(string): The ID of the top level parent folder.
            subfolder_name(string): The name of the subfolder.

            Returns:
                (string): The ID for the subfolder.  If no folder is found it returns an empty string.

        """

        try:
            results = self.swis.query(
                'SELECT Groupid FROM IPAM.GroupNode WHERE Parentid = @parent_id AND FriendlyName=@subfolder_name',
                parent_id=parent_id, subfolder_name=subfolder_name)
            self.logger.info("get_ipam_subfolder_id - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_ipam_subfolder_id - query error: %s", error)
            return ""

        return results['results'][0]['Groupid']

    def get_ipam_subnet_uri(self, subnet_address, subnet_cidr):
        """ Gets the subnet URI for a given IP address and CIDR.

            Args:
                subnet_address(string): The IPv4 network address of the subnet.
                subnet_cidr(string): The IPv4 mask of the subnet in CIDR notation.

            Returns:
                (string): The URI of the subnet.  If no subnet is not found it returns an empty string.

        """

        try:
            results = self.swis.query('SELECT Uri FROM IPAM.Subnet WHERE Address=@address AND CIDR=@cidr',
                                      address=subnet_address, cidr=subnet_cidr)
            self.logger.info("get_ipam_subnet_uri - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_ipam_subnet_uri - query error: %s", error)
            return ""

        return results['results'][0]['Uri']

    def reserve_ip_address(self, ip_address):
        """ Set the status of the specified IP address in IPAM to Reserved .

        Args:
            ip_address(string): The IPv4 address to reserve.

        Returns:
            True: The IP address is reserved.
            False: The IP address is not reserved.

    """

        try:
            results = self.swis.invoke('IPAM.SubnetManagement', 'ChangeIPStatus', ip_address, "Reserved")
            self.logger.info("reserve_ip_address - ChangeIPStatus invoke results: %s", results)

        except Exception as error:
            self.logger.info("reserve_ip_address - ChangeIPStatus invoke error: %s", error)
            return False

        return True

    ###################################################################################################################
    ##  SolarWinds Network Performance Monitor (NPM)                                                                 ##
    ###################################################################################################################

    def add_custom_poller_by_name(self, node_name, poller_name):
        """ Adds a custom poller to a node.

            Args:
                node_name(string): The name of the node to add the custom poller to.
                poller_name(string): The name of the custom poller to add.

            Returns:
                True: The custom poller is successfully added.
                False: The custom poller is not successfully added.

        """

        node_id = self.get_node_id(node_name)

        # Retrieve the custom poller ID.
        try:
            results = self.swis.query(
                'SELECT CustomPollerID FROM Orion.NPM.CustomPollers WHERE UniqueName = @poller_name',
                poller_name=poller_name)
            self.logger.info("add_custom_poller_by_name - query results: %s", results)

            if not results['results']:
                return False

        except Exception as error:
            self.logger.info("add_custom_poller_by_name - query error: %s", error)
            return False

        # Add the poller to the node.
        poller_properties = {
            'NodeID': node_id,
            'customPollerID': results['results'][0]['CustomPollerID']
        }

        try:
            results = self.swis.create('Orion.NPM.CustomPollerAssignmentOnNode', **poller_properties)
            self.logger.info("add_custom_poller_by_name - CustomPollerAssignmentOnNode create results: %s", results)

            if not results:
                return False

        except Exception as error:
            self.logger.info("add_custom_poller_by_name - CustomPollerAssignmentOnNode create error: %s", error)
            return False

        return True

    def add_dependency(self, dependency_name, parent_name, child_name):
        """ Adds a new dependency using the provided parent and child.

            Args:
                dependency_name(string): The dependency name for the new dependency.
                parent_name(string): Name of the parent to use in the dependency.  Can be a node or group.
                child_name(string): Name of the child to use in the dependency.  Can be a node or group.

            Returns:
                True: The dependency was successfully created.
                False: The dependency was not created or already existed.

        """

        if not self.does_dependency_exist(dependency_name):
            # Determine if the parent is a node or group.
            if self.does_node_exist(parent_name):
                self.logger.info("add_dependency - The parent is a node.")
                parent_id = self.get_node_id(parent_name)
                parent_uri = self.get_node_uri(parent_name)
                parent_entity_type = 'Orion.Nodes'
            elif self.does_group_exist(parent_name):
                self.logger.info("add_dependency - The parent is a group.")
                parent_id = self.get_group_id(parent_name)
                parent_uri = self.get_group_uri(parent_name)
                parent_entity_type = 'Orion.Groups'
            else:
                return False

            # Determine if the child is a node or group.
            if self.does_node_exist(child_name):
                self.logger.info("add_dependency - The child is a node.")
                child_id = self.get_node_id(child_name)
                child_uri = self.get_node_uri(child_name)
                child_entity_type = 'Orion.Nodes'
            elif self.does_group_exist(child_name):
                self.logger.info("add_dependency - The child is a group.")
                child_id = self.get_group_id(child_name)
                child_uri = self.get_group_uri(child_name)
                child_entity_type = 'Orion.Groups'
            else:
                return False

            # Create the dependency.
            dependency_properties = {
                'Name': dependency_name,
                'ParentUri': parent_uri,
                'ParentEntityType': parent_entity_type,
                'ParentNetObjectId': parent_id,
                'ChildUri': child_uri,
                'ChildEntityType': child_entity_type,
                'ChildNetObjectId': child_id
            }

            try:
                results = self.swis.create('Orion.Dependencies', **dependency_properties)
                self.logger.info("add_dependency - Orion.Dependencies create results: %s", results)

                if not results:
                    return False

            except Exception as error:
                self.logger.info("add_dependency - Orion.Dependencies create error: %s", error)
                return False

            return True

    def add_group(self, group_name, owner='Core', refresh_frequency=60, status_rollup=0,
                  group_description='', polling_enabled=True, group_members=None):
        """ Adds a new empty group using the provided parameters.

            Args:
                group_name(string): The group name to use.
                owner(string): Must be 'Core'.
                refresh_frequency(int): How often the group membership is updated.
                status_rollup(int): Status rollup mode.
                    # 0 = Mixed status shows warning
                    # 1 = Show worst status
                    # 2 = Show best status
                group_description(string): The description to use for the group.
                polling_enabled(boolean): Whether polling of the group is enabled or disabled.
                group_members(list): A list of group members and/or dynamic filters.

            Returns:
                True: The group is successfully added.
                False: The group was not successfully added.

        """

        if group_members is None:
            group_members = []
        if not self.does_group_exist(group_name):
            try:
                results = self.swis.invoke('Orion.Container', 'CreateContainer', group_name, owner, refresh_frequency,
                                           status_rollup, group_description, polling_enabled, group_members)
                self.logger.info("add_group - invoke results: %s", results)

                if not results:
                    return False

            except Exception as error:
                self.logger.info("add_group - invoke error: %s", error)
                return False

        return True

    def add_group_custom_property(self, property_name, description, value_type, size):
        """ Add a new group custom property using the provided parameters.

            Args:
                property_name(string): The name of the new group property.
                description(string): The description for the new group property.
                value_type(string): The value type for the new group property (string, integer, datetime, single,
                    double, boolean)
                size(integer): The maximum length for string value types.  Ignored for other value types.

            Returns:
                True: The custom property was successfully updated.
                False: The custom property was not successfully updated.

        """

        try:
            results = self.swis.invoke('Orion.GroupCustomProperties', 'CreateCustomProperty', property_name,
                                       description, value_type, size, "", "", "", "", "", "")
            self.logger.info("add_group_custom_property - CreateCustomProperty invoke results: %s", results)

        except Exception as error:
            self.logger.info("add_group_custom_property - CreateCustomProperty invoke error: %s", error)
            return False

        return True

    def add_interface(self, node_name, interface_name):
        """ Checks to see if the interface exists and if it does, it adds it to the node so its monitored.

            Args:
                node_name(string): The name of the node to add the interface to.
                interface_name(string): The name of the interface to add to the node.

            Returns:
                True: The interface is successfully added to the node.
                False: The interface is not successfully added to the node.

        """

        node_id = self.get_node_id(node_name)

        if not node_id:
            return False

        discovered_interfaces = self.get_discovered_interfaces(node_name)
        discovered_interface = [

            x for x
            in discovered_interfaces
            if x['Caption'].startswith(interface_name)

        ]

        if not discovered_interface:
            return False

        try:
            results = self.swis.invoke('Orion.NPM.Interfaces', 'AddInterfacesOnNode', node_id, discovered_interface,
                                       'AddDefaultPollers')
            self.logger.info("add_interface - AddInterfacesOnNode invoke results: %s", results)

        except Exception as error:
            self.logger.info("add_interface - AddInterfacesOnNode invoke error: %s", error)
            return False

        return True

    def add_node_to_group(self, node_name, group_name):
        """ Adds a node to an existing group.

            Args:
                node_name(string): The name of the node to add to the group.
                group_name(string): The name of the group to which to add the node.

            Returns:
                True: The node is successfully added to the group.
                False: The node was not successfully added to the group.

        """

        # If the node or group does not exist.
        if not self.does_node_exist(node_name) or not self.does_group_exist(group_name):
            return False

        # If the node is not already in the group, add it.
        if not self.is_node_in_group(node_name, group_name):

            try:
                member_definition = {"Name": node_name, "Definition": self.get_node_uri(node_name)}
                results = self.swis.invoke('Orion.Container', 'AddDefinition', int(self.get_group_id(group_name)),
                                           member_definition)
                self.logger.info("add_node_to_group - AddDefinition invoke results: %s", results)

            except Exception as error:
                self.logger.info("add_node_to_group - AddDefinition invoke error: %s", error)
                return False

        return True

    def add_node_using_icmp(self, node_name, ip_address, poll_interval=120):
        """ Creates a new node using the provided name an IP address.  The new node will be configured for ICMP
            monitoring only.  Once created, only the ICMP pollers are attached.

            Args:
                node_name(string): The name of the node object.
                ip_address(string): The IPv4 address of the new node object.
                poll_interval(string): The polling interval for the node in seconds.

            Returns:
                True: The node is successfully added.
                False: The node is not successfully added.

        """

        if not self.does_node_exist(node_name):
            node_properties = {
                'IPAddress': ip_address,
                'Caption': node_name,
                'EngineID': 1,
                'PollInterval': poll_interval,
                'ObjectSubType': 'ICMP'
            }

            try:
                # Create the base node object.
                results = self.swis.create('Orion.Nodes', **node_properties)
                self.logger.info("add_node_using_icmp - create results: %s", results)

            except Exception as error:
                self.logger.info("add_node_to_group - create error: %s", error)
                return False

            # Assign pollers to node.
            self.add_poller_to_node(node_name, 'N.Status.ICMP.Native')
            self.add_poller_to_node(node_name, 'N.ResponseTime.ICMP.Native')

        return True

    def add_node_using_snmp_v3(self, node_name, ip_address, snmpv3_username, snmpv3_priv_method, snmpv3_priv_pwd,
                               snmpv3_auth_method, snmpv3_auth_pwd, poll_interval=120):
        """ Creates a new node using the provided name an IP address.  The new node will be configured for SNMP
            monitoring using the provided SNMPv3 credentials.  Once created, only the base SNMP pollers are attached.

            Args:
                node_name(string): The name of the node object.
                ip_address(string): The IPv4 address of the new node object.
                snmpv3_username(string): The SNMPv3 username that will be used.
                snmpv3_priv_method(string): The SNMPv3 privilege method that will be used.
                snmpv3_priv_pwd (string): The SNMPv3 privilege password that will be used.
                snmpv3_auth_method(string): The SNMPv3 authentication method that will be used.
                snmpv3_auth_pwd (string): The SNMPv3 authentication password that will be used.
                poll_interval(string): The polling interval for the node in seconds.

            Returns:
                True: The node is successfully added.
                False: The node is not successfully added.

        """

        if not self.does_node_exist(node_name):
            node_properties = {
                'IPAddress': ip_address,
                'EngineID': 1,
                'ObjectSubType': 'SNMP',
                'PollInterval': poll_interval,
                'SNMPVersion': 3,
                'SNMPV3Username': snmpv3_username,
                'SNMPV3PrivMethod': snmpv3_priv_method,
                'SNMPV3PrivKeyIsPwd': True,
                'SNMPV3PrivKey': snmpv3_priv_pwd,
                'SNMPV3AuthMethod': snmpv3_auth_method,
                'SNMPV3AuthKeyIsPwd': True,
                'SNMPV3AuthKey': snmpv3_auth_pwd,
                'DNS': '',
                'SysName': '',
                'Caption': node_name
            }

            # Create the base node object.
            try:
                results = self.swis.create('Orion.Nodes', **node_properties)
                self.logger.info("add_node_using_snmp_v3 - create results: %s", results)

            except Exception as error:
                self.logger.info("add_node_using_snmp_v3 - create error: %s", error)
                return False

            # Assign pollers to node.
            self.add_poller_to_node(node_name, 'N.Status.ICMP.Native')
            self.add_poller_to_node(node_name, 'N.Status.SNMP.Native', False)
            self.add_poller_to_node(node_name, 'N.ResponseTime.ICMP.Native')
            self.add_poller_to_node(node_name, 'N.ResponseTime.SNMP.Native', False)
            self.add_poller_to_node(node_name, 'N.Details.SNMP.Generic')
            self.add_poller_to_node(node_name, 'N.Uptime.SNMP.Generic')

            return True

    def add_poller_to_node(self, node_name, poller_name, enabled=True):
        """ Adds the poller to the node.

            Args:
                node_name(string): The name of the node to add the poller to.
                poller_name(string): The name of the poller to add.
                enabled(boolean): Whether or not to enable the poller after it is added.

            Returns:
                True: The poller is successfully added.
                False: The poller is not successfully added.

        """

        if not self.is_poller_attached_to_node(node_name, poller_name):
            net_object_id = str(self.get_node_id(node_name))
            net_object = 'N:' + net_object_id

            poller_properties = {
                'PollerType': poller_name,
                'NetObject': net_object,
                'NetObjectType': 'N',
                'NetObjectID': net_object_id,
                'Enabled': enabled
            }

            try:
                results = self.swis.create('Orion.Pollers', **poller_properties)
                self.logger.info("add_poller_to_node - create results: %s", results)

            except Exception as error:
                self.logger.info("add_poller_to_node - create error: %s", error)
                return False

        return True

    def delete_group_by_id(self, group_id):
        """ Delete the group that has the given group id.

            Args:
                group_id(string): The ID of the group to be deleted.

            Returns:
                True: The group is successfully deleted.
                False: The group is not successfully deleted.

        """

        if not self.does_group_exist(self.get_group_name(group_id)):
            return False

        try:
            results = self.swis.invoke('Orion.Container', 'DeleteContainer', int(group_id))
            self.logger.info("delete_group_by_id - DeleteContainer invoke results: %s", results)

        except Exception as error:
            self.logger.info("delete_group_by_id - DeleteContainer invoke error: %s", error)
            return False

        return True

    def delete_group_by_name(self, group_name):
        """ Delete a group that has the specified group name.

            Args:
                group_name(string): The name of the group to be deleted.

            Returns:
                True: The group is successfully deleted.
                False: The group is not successfully deleted.

        """

        if not self.does_group_exist(group_name):
            return False

        if not self.delete_group_by_id(self.get_group_id(group_name)):
            return False

        return True

    def does_dependency_exist(self, dependency_name):
        """ Checks to see if a dependency exists or not.

            Args:
                dependency_name(string): The name of the dependency to check for.

            Returns:
                True: The dependency exists.
                False: The dependency does not exist.

        """

        if not self.get_dependency_id(dependency_name):
            return False

        return True

    def does_group_exist(self, group_name):
        """ Checks to see if a group exists or not.

            Args:
                group_name(string): The name of the group to check for.

            Returns:
                True: The group exists.
                False: The group does not exist.

        """

        if not self.get_group_id(group_name):
            return False

        return True

    def does_interface_exist(self, node_name, interface_name):
        """ Checks to see if a node has the given interface associated with it.

            Args:
                node_name(string): The name of the node to check for the interface.
                interface_name(string): The name of the interface to check for.

            Returns:
                True: The interface exists on the node.
                False: THe interface does not exist on the node.

        """

        if not self.get_interface_id(node_name, interface_name):
            return False

        return True

    def does_node_exist(self, node_name):
        """ Checks to see if the node exists.

            Args:
                node_name(string): The name of the node to check for.

            Returns:
                True: The node exists.
                False: The node does not exist.

        """

        if not self.get_node_id(node_name):
            return False

        return True

    def enable_hardware_health_on_node(self, node_name):
        """ Enables the hardware health monitoring on the node.

            Args:
                node_name(string): The name of the node to enable hardware health monitoring on.

            Returns:
                True: The hardware health monitoring was successfully enabled.
                False: The hardware health monitoring was not successfully enabled.

        """

        if not self.does_node_exist(node_name):
            return False

        net_object_id = str(self.get_node_id(node_name))
        net_object = 'N:' + net_object_id

        try:
            results = self.swis.invoke('Orion.HardwareHealth.HardwareInfo', 'EnableHardwareHealth', net_object, 9)
            self.logger.info("enable_hardware_health - EnableHardwareHealth invoke results: %s", results)

        except Exception as error:
            self.logger.info("enable_hardware_health - EnableHardwareHealth invoke error: %s", error)
            return False

        return True

    def get_dependency_id(self, dependency_name):
        """ Gets the ID for a dependency.

            Args:
                dependency_name(string): The name of the dependency for which to get the ID.

            Returns:
                (string): The ID of the dependency.  If no dependency is found a blank string is returned.

        """

        try:
            results = self.swis.query('SELECT DependencyId FROM Orion.Dependencies WHERE Name = @dependency_name',
                                      dependency_name=dependency_name)
            self.logger.info("get_dependency_id - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_dependency_id - query error: %s", error)
            return ""

        return results['results'][0]['DependencyId']

    def get_discovered_interfaces(self, node_name):
        """ Gets all of the discovered interfaces for a node.

            Args:
                node_name(string): The name of the node which to discover the interfaces.

            Returns:
                (list): The discovered interfaces for the node.  The list contains a dictionary consisting of the
                    following keys for each discovered interface.  If the node is not found a empty list is returned.

                    ifIndex
                    Caption
                    ifType
                    ifSubType
                    InterfaceID
                    Manageable
                    ifSpeed
                    ifAdminStatus
                    ifOperStatus

        """

        node_id = self.get_node_id(node_name)

        try:
            results = self.swis.invoke('Orion.NPM.Interfaces', 'DiscoverInterfacesOnNode', node_id)
            self.logger.info("get_discovered_interfaces - DiscoverInterfacesOnNode invoke results: %s", results)

            if not results['DiscoveredInterfaces']:
                return []

        except Exception as error:
            self.logger.info("get_discovered_interfaces - DiscoverInterfacesOnNode invoke error: %s", error)
            return []

        return results['DiscoveredInterfaces']

    def get_group_custom_properties(self, group_name):
        """ Gets the custom properties and associated values for the provided group.

            Args:
                group_name(string): The name of the group to get the custom properties and values for.

            Returns:
                (dictionary): The custom properties and associated values for the group.  Each key/value pair in the
                    dictionary contains a custom property and its value.  If the node is not found an empty dictionary
                    is returned.

        """

        group_uri = self.get_group_uri(group_name)

        try:
            results = self.swis.read(group_uri + '/CustomProperties')
            self.logger.info("get_group_custom_properties - read results: %s", results)

            if not results:
                return {}

        except Exception as error:
            self.logger.info("get_group_custom_properties - read error: %s", error)
            return {}

        return results

    def get_group_id(self, group_name):
        """ Gets the ID for a group.

            Args:
                group_name(string): The name of the group for which to get the ID.

            Returns:
                (string): The ID of the group.  If no group is found a blank string is returned.
                
        """

        try:
            results = self.swis.query('SELECT ContainerID FROM Orion.Container WHERE Name = @group_name',
                                      group_name=group_name)
            self.logger.info("get_group_id - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_group_id - query error: %s", error)
            return ""

        return results['results'][0]['ContainerID']

    def get_group_name(self, group_id):
        """ Gets the group for an ID.

            Args:
                group_id(string): The ID of the group for which to get the name.

            Returns:
                (string): The name of the group. If no group is found a blank string is returned.

        """

        try:
            results = self.swis.query('SELECT DisplayName FROM Orion.Groups WHERE ContainerID = @group_id',
                                      group_id=group_id)
            self.logger.info("get_group_name - query results: %s.", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_group_name - query error: %s.", error)
            return ""

        return results['results'][0]['DisplayName']

    def get_group_uri(self, group_name):
        """ Gets the URI for a group.

            Args:
                group_name(string): The name of the group for which to get the URI.

            Returns:
                (string): The URI of the group.  If no group is found a blank string is returned.

        """

        try:
            results = self.swis.query('SELECT Uri FROM Orion.Container WHERE Name = @group_name',
                                      group_name=group_name)
            self.logger.info("get_group_uri - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_group_uri - query error: %s", error)
            return ""

        return results['results'][0]['Uri']

    def get_interface_id(self, node_name, interface_name):
        """ Gets the ID for an interface.

            Args:
                node_name(string): A name of the node for which to get the ID.
                interface_name(string): The name of the interface for which to get the ID.

            Returns:
                (string): The ID of the interface.  If no node or interfaces is found a blank string is returned.

        """

        node_id = self.get_node_id(node_name)

        try:
            results = self.swis.query('SELECT InterfaceID FROM Orion.NPM.Interfaces WHERE NodeID=@node_id AND '
                                      'Name = @interface_name', node_id=node_id, interface_name=interface_name)
            self.logger.info("get_interface_id - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_interface_id - query error: %s", error)
            return ""

        return results['results'][0]['InterfaceID']

    def get_interface_uri(self, node_name, interface_name):
        """ Gets the URI for an interface.

            Args:
                node_name(string): The name of the node for which to get the URI.
                interface_name(string): The name of the interface for which to get the URI.

            Returns:
                (string): The URI of the interface.  If no node or interfaces is found a blank string is returned.

        """

        node_id = self.get_node_id(node_name)

        try:
            results = self.swis.query(
                'SELECT Uri FROM Orion.NPM.Interfaces WHERE NodeID=@node_id AND InterfaceName=@interface_name',
                node_id=node_id, interface_name=interface_name)
            self.logger.info("get_interface_uri - query results: %s", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_interface_uri - query error: %s", error)
            return ""

        return results['results'][0]['Uri']

    def get_list_of_all_nodes(self):
        """ Gets a list of all of the nodes.

            Args:
                None.

            Returns:
                (list): A list of the nodes.

        """

        try:
            results = self.swis.query('SELECT Caption FROM Orion.Nodes')
            self.logger.info("get_list_of_all_nodes - query results: %s.", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_all_nodes - query error: %s.", error)
            return []

        node_name_list = []
        for node in results['results']:
            node_name_list.append(node['Caption'])

        return node_name_list

    def get_list_of_custom_pollers_for_node(self, node_name):
        """ Gets a list of the custom pollers attached to a node.

            Args:
                node_name(string): The name of the node for which to get a list of custom pollers.

            Returns:
                (list): A list of dictionaries where each dictionary is a single key/value pair containing the custom
                    property name and value.  If no node is found a blank list is returned.

        """

        node_id = self.get_node_id(node_name)

        try:
            results = self.swis.query('SELECT CustomPollerName FROM Orion.NPM.CustomPollerAssignment WHERE NodeID '
                                      '= @node_id', node_id=node_id)
            self.logger.info("get_list_of_custom_pollers_by_name - query results: %s", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_custom_pollers_by_name - query error: %s", error)
            return []

        return results['results']

    def get_list_of_groups_for_custom_property_value(self, custom_property_name, custom_property_value):
        """ Gets a list of the groups that have the provided custom property name and value.

            Args:
                custom_property_name(string): The name of the custom property to match on.
                custom_property_value(string): The value of the custom property to match on.

            Returns:
                (list): A list of group names.  If no groups are found a blank list is returned.

        """

        try:
            results = "SELECT ContainerID FROM Orion.GroupCustomProperties WHERE " + custom_property_name + "='" \
                        + custom_property_value + "'"
            results = self.swis.query(results)
            self.logger.info("get_list_of_group_for_custom_property_value- query results: %s.", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_group_for_custom_property_value- query error: %s.", error)
            return []

        group_list = []
        for group in results['results']:
            group_list.append(self.get_group_name(group['ContainerID']))

        return group_list

    def get_list_of_interfaces(self, node_name):
        """ Gets a list of the monitored interfaces for a node.

            Args:
                node_name(string): The name of the node which to get the monitored interfaces.
            Returns:
                (list): A list of dictionaries where each dictionary is a single key/value pair containing a key 'Name'
                    with the interface name as the value.  If no node is found a blank list is returned.
        """

        node_id = self.get_node_id(node_name)

        try:
            results = self.swis.query('SELECT Name FROM Orion.NPM.Interfaces WHERE NodeID = @node_id', node_id=node_id)
            self.logger.info("get_list_of_interfaces_by_name - query results: %s", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_interfaces_by_name - query error: %s", error)
            return []

        return results['results']

    def get_list_of_locations(self):
        """ Gets a list of all of the defined locations.

            Args:
                None.

            Returns:
                (list): A list of all of the defined locations.

        """

        try:
            results = self.swis.query("SELECT DISTINCT Location FROM Orion.Nodes WHERE Location <> ''")
            self.logger.info("get_list_of_locations - query results: %s", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_locations - error results: %s", error)
            return []

        location_list = []
        for location in results['results']:
            location_list.append(location['Location'])

        return location_list

    def get_list_of_nodes_by_substring(self, substring):
        """ Gets a list of nodes with the provided substring in their names.

            Args:
                substring(string): The substring to search for in the node names.

            Returns:
                (list): A list of node names.

        """

        try:
            results = self.swis.query("SELECT Caption FROM Orion.Nodes WHERE Caption LIKE @substring",
                                      substring="%" + substring + "%")
            self.logger.info("get_list_of_nodes_by_substring - query results: %s.", results)

            if not results['results']:
                return []
            
        except Exception as error:
            self.logger.info("get_list_of_nodes_by_substring - query error: %s.", error)
            return []
            
        node_list = []
        for node in results['results']:
            node_list.append(node['Caption'])
            
        return node_list

    def get_list_of_nodes_by_vendor(self, vendor):
        """ Gets a list of the nodes from the provided vendor.

            Args:
                vendor(string): Name of the vendor to match on.

            Returns:
                (list): A list of node names that match on the vendor.

        """

        try:
            results = self.swis.query('SELECT Caption FROM Orion.Nodes WHERE Vendor = @vendor', vendor=vendor)
            self.logger.info("get_list_of_nodes_by_vendor - query results: %s.", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_nodes_by_vendor - query error: %s.", error)
            return []

        node_list = []
        for node in results['results']:
            node_list.append(node['Caption'])

        return node_list

    def get_list_of_nodes_for_custom_property_value(self, custom_property_name, custom_property_value):
        """ Gets a list of the nodes that have the provided custom property name and value.

            Args:
                custom_property_name(string): The name of the custom property to match on.
                custom_property_value(string): The value of the custom property to match on.

            Returns:
                (list): A list of nodes names.  If no nodes are found a blank list is returned.

        """

        try:
            sql_query = "SELECT NodeID FROM Orion.NodesCustomProperties WHERE " + custom_property_name + "='" \
                        + custom_property_value + "'"
            results = self.swis.query(sql_query)
            self.logger.info("get_list_of_nodes_for_custom_property_value - query results: %s.", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_nodes_for_custom_property_value - query error: %s.", error)
            return []

        node_list = []
        for node in results['results']:
            node_list.append(self.get_node_name(node['NodeID']))

        return node_list

    def get_list_of_values_for_custom_property(self, custom_property_name):
        """ Get a list all of the in use values for the provided custom property.

            Args:
                custom_property_name(string): The name of the custom_property for which we want the list of values.

            Returns:
                (list): A list of all of the in use values.  If the custom property is not found, a blank list is
                    returned.

        """

        try:
            results = self.swis.query('SELECT Value FROM Orion.CustomPropertyValues WHERE Field=@custom_property_name',
                                      custom_property_name=custom_property_name)
            self.logger.info("get_list_of_values_for_custom_property - query results: %s.", results)

            if not results['results']:
                return []

        except Exception as error:
            self.logger.info("get_list_of_values_for_custom_property - query error: %s.", error)
            return []

        value_list = []
        for value in results['results']:
            value_list.append(value['Value'])

        return value_list

    def get_node_custom_properties(self, node_name):
        """ Gets all of the custom properties and values for a node.

            Args:
                node_name(string): A node name which should equal the caption used in SolarWinds for the node object.

            Returns:
                (dictionary): A dictionary where each key is the name of a custom property and the
                    value is the custom property value.  If no node is found a blank dictionary is returned.

        """

        node_uri = self.get_node_uri(node_name)

        try:
            results = self.swis.read(node_uri + '/CustomProperties')
            self.logger.info("get_node_custom_properties - read results: %s", results)

            if not results:
                return {}

        except Exception as error:
            self.logger.info("get_node_custom_properties - read error: %s", error)
            return {}

        return results

    def get_node_id(self, node_name):
        """ Gets the ID for a node.

            Args:
                node_name(string): The name of the node for which to get the ID.

            Returns:
                (string): The ID of the node.  If no node is found a blank string is returned.

        """

        try:
            results = self.swis.query('SELECT NodeID FROM Orion.Nodes WHERE Caption = @caption', caption=node_name)
            self.logger.info("get_node_id - query results: %s.", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_node_id - error results: %s.", error)
            return ""

        return results['results'][0]['NodeID']

    def get_node_location(self, node_name):
        """ Gets the location for a node.

            Args:
                node_name(string): The name of the node for which to get the location.

            Returns:
                (string): The location of the node.  If no node is found a blank string is returned.

        """

        try:
            results = self.swis.query('SELECT Location FROM Orion.Nodes WHERE Caption = @caption', caption=node_name)
            self.logger.info("get_node_location - query results: %s.", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_node_location - query error: %s.", error)
            return ""

        return results['results'][0]['Location']

    def get_node_name(self, node_id):
        """ Gets the node for an ID.

            Args:
                node_id(string): The ID of the node for which to get the name.

            Returns:
                (string): The name of the node. If no node is found a blank string is returned.

        """

        try:
            results = self.swis.query('SELECT Caption FROM Orion.Nodes WHERE NodeID = @node_id', node_id=node_id)
            self.logger.info("get_node_name - query results: %s.", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_node_name - query error: %s.", error)
            return ""

        return results['results'][0]['Caption']

    def get_node_uri(self, node_name):
        """ Gets the URI for a node.

            Args:
                node_name(string): The name of the node for which to get the URI.

            Returns:
                (string): The URI of the node.  If no node is found a blank string is returned.

        """

        try:
            results = self.swis.query('SELECT Caption, Uri FROM Orion.Nodes WHERE Caption = @caption',
                                      caption=node_name)
            self.logger.info("get_node_uri - query results: %s.", results)

            if not results['results']:
                return ""

        except Exception as error:
            self.logger.info("get_node_uri - query error: %s.", error)
            return ""

        return results['results'][0]['Uri']

    def get_value_for_group_custom_property(self, group_name, custom_property_name):
        """ Get the value for the provided group custom property.

            Args:
                group_name(string): The name of the group for which to get the custom property value.
                custom_property_name(string): The name of the custom property for which to get the custom property
                    value.

            Returns:
                (string): The value for specified group custom property.  If no group or custom property is found a
                    blank string is returned.

        """

        return self.get_group_custom_properties(group_name)[custom_property_name]

    def get_value_for_node_custom_property(self, node_name, custom_property_name):
        """ Get the value for the provided node custom property.

            Args:
                node_name(string): The name of the node for which to get the custom property value.
                custom_property_name(string): The name of the custom property for which to get the custom property
                    value.

            Returns:
                (string): The value for specified node custom property.  If no node or custom property is found a
                    blank string is returned.

        """

        return self.get_node_custom_properties(node_name)[custom_property_name]

    def is_node_in_group(self, node_name, group_name):
        """ Checks to see if a node is a member of a group.

            Args:
                node_name(string): The name of the node to check for.
                group_name(string): The name of the group to check for the nodes membership.

            Returns:
                True: The node is in the group.
                False: The node is not in the group.

        """

        try:
            results = self.swis.query('SELECT Name FROM Orion.ContainerMembers WHERE ContainerID = @group_id and '
                                      'FullName = @node_name', group_id=self.get_group_id(group_name),
                                      node_name=node_name)
            self.logger.info("is_node_in_group - query results: %s", results)

            if not results['results']:
                return False

        except Exception as error:
            self.logger.info("is_node_in_group - query error: %s", error)
            return False

        return True

    def is_poller_attached_to_node(self, node_name, poller_name):
        """ Checks to see if a poller is attached to a node.

            Args:
                node_name(string): The name of the node to check.
                poller_name(string): The name of the poller to check for.

            Returns:
                True: The poller is attached to the node.
                False: The poller is not attached to the node.

        """

        net_object_id = str(self.get_node_id(node_name))
        net_object = 'N:' + net_object_id

        try:
            results = self.swis.query('SELECT PollerType FROM Orion.Pollers WHERE NetObject = @net_object AND '
                                      'PollerType = @poller_name', net_object=net_object, poller_name=poller_name)
            self.logger.info("is_poller_attached_to_node - query results: %s", results)

            if not results['results']:
                return False

        except Exception as error:
            self.logger.info("is_poller_attached_to_node - query error: %s", error)
            return False

        return True

    def remove_custom_poller_by_name(self, node_name, poller_name):
        """ Remove a custom poller from a node.

            Args:
                node_name(string): The name of the node from which to remove the custom poller.
                poller_name(string): The name of the custom poller to remove from the node.

            Returns:
                True: The custom poller was successfully removed.
                False: The custom poller was not successfully removed.

        """

        node_id = self.get_node_id(node_name)

        # Get the custom poller ID.
        try:
            results_id = self.swis.query('SELECT CustomPollerID FROM Orion.NPM.CustomPollers WHERE UniqueName = '
                                         '@poller_name', poller_name=poller_name)
            self.logger.info("remove_custom_poller_by_name - id query results: %s", results_id)

        except Exception as error:
            self.logger.info("remove_custom_poller_by_name - id query error: %s", error)
            return False

        # Get the URI for the custom poller instance attached to the node.
        try:
            results_uri = self.swis.query('SELECT Uri FROM Orion.NPM.CustomPollerAssignmentOnNode WHERE '
                                          'NodeID=@node_id AND CustomPollerID=@custom_poller_id', node_id=node_id,
                                          custom_poller_id=results_id['results'][0]['CustomPollerID'])
            self.logger.info("remove_custom_poller_by_name - uri query results: %s", results_uri)

        except Exception as error:
            self.logger.info("remove_custom_poller_by_name - uri query error: %s", error)
            return False

        # Delete the custom poller with the provided URI.
        try:
            results = self.swis.delete(results_uri['results'][0]['Uri'])
            self.logger.info("remove_custom_poller_by_name - delete results: %s", results)

        except Exception as error:
            self.logger.info("remove_custom_poller_by_name - delete error: %s", error)
            return False

        return True

    def remove_interface(self, node_name, interface_name):
        """ Checks to see if the interface exists and if it does, it removes it from the node.

            Args:
                node_name(string): The name of the node to remove the interface from.
                interface_name(string): The name of the interface to remove from the node.

            Returns:
                True: The interface is successfully removed from the node.
                False: The interface is not successfully removed the node.

        """

        if not self.does_interface_exist(node_name, interface_name):
            return False

        interface_uri = self.get_interface_uri(node_name, interface_name)

        try:
            results = self.swis.delete(interface_uri)
            self.logger.info("remove_interface - delete results: %s", results)

        except Exception as error:
            self.logger.info("remove_interface - delete error: %s", error)
            return False

        return True

    def set_group_custom_property(self, group_name, custom_property_name, custom_property_value):
        """ Sets a group custom property to the provided value.

            Args:
                group_name(string): The name of the group to set the custom property value on.
                custom_property_name(string): The name of the custom property to set the value on.
                custom_property_value(string): The custom property value to set the custom property to.

            Returns:
                True: The custom property is successfully set to the provided value.
                False: The custom property is not successfully set to the provided value.

        """

        group_uri = self.get_group_uri(group_name)

        custom_property = {
            custom_property_name: custom_property_value
        }

        try:
            results = self.swis.update(group_uri + '/CustomProperties', **custom_property)
            self.logger.info("set_group_custom_property - update results: %s", results)

        except Exception as error:
            self.logger.info("set_group_custom_property - update error: %s", error)
            return False

        return True

    def set_node_custom_property(self, node_name, custom_property_name, custom_property_value):
        """ Sets a node custom property to the provided value.

            Args:
                node_name(string): The name of the node to set the custom property value on.
                custom_property_name(string): The name of the custom property to set the value on.
                custom_property_value(string): The custom property value to set the custom property to.

            Returns:
                True: The custom property is successfully set to the provided value.
                False: The custom property is not successfully set to the provided value.

        """

        node_uri = self.get_node_uri(node_name)

        custom_property = {
            custom_property_name: custom_property_value
        }

        try:
            results = self.swis.update(node_uri + '/CustomProperties', **custom_property)
            self.logger.info("set_node_custom_property - update results: %s", results)

        except Exception as error:
            self.logger.info("set_node_custom_property - update error: %s", error)
            return False

        return True

    ###################################################################################################################
    ##  SolarWinds Network Configuration Manager (NCM)                                                               ##
    ###################################################################################################################

    def add_node_to_ncm(self, node_name):
        """ Adds the node to the NCM module.

            Args:
                node_name(string): The name of the node to add.

            Returns:
                True: The node is successfully added to NCM.
                False: The node is not successfully added to NCM.

        """

        try:
            results = self.swis.invoke('Cirrus.Nodes', 'AddNodeToNCM', self.get_node_id(node_name))
            self.logger.info("add_node_to_ncm - AddNodeToNCM invoke results: %s", results)

        except Exception as error:
            self.logger.info("add_node_to_ncm - AddNodeToNCM invoke error: %s", error)
            return False

        return True

    def ncm_download_nodes_running_config(self, node_name):
        """ Initiates an NCM download of a nodes running configuration.

            Args:
                node_name(string): A node name which should equal the caption used in SolarWinds for the node object.

            Returns:
                True: The configuration download is successfully initiated.
                False: The configuration download is not successfully initiated.

        """

        try:
            results = self.swis.query('SELECT NodeID FROM Cirrus.Nodes WHERE NodeCaption = @node_name',
                                      node_name=node_name)['results']
            self.logger.info("ncm_download_nodes_running_config - query results: %s", results)

        except Exception as error:
            self.logger.info("ncm_download_nodes_running_config - query error: %s", error)
            return False

        cirrus_node_id = results[0]['NodeID']

        try:
            self.swis.invoke('Cirrus.ConfigArchive', 'DownloadConfig', [cirrus_node_id], 'Running')
            self.logger.info("ncm_download_nodes_running_config - DownloadConfig invoke results: %s", results)

        except Exception as error:
            self.logger.info("ncm_download_nodes_running_config - DownloadConfig invoke error: %s", error)
            return False

        return True

    def ncm_run_compliance_report(self, report_name):
        """ Initiates an update of an NCM compliance report.

            Args:
                report_name(string): The name of the compliance report to update.

            Returns:
                True: The compliance report update is successfully initiated.
                False: The compliance report update is not successfully initiated.

        """

        try:
            results = self.swis.query('SELECT PolicyReportID FROM Cirrus.PolicyReports WHERE Name = @report_name',
                                      report_name=report_name)
            self.logger.info("ncm_run_compliance_report - query results: %s", results)

        except Exception as error:
            self.logger.info("ncm_run_compliance_report - query error: %s", error)
            return False

        report_id = results['results'][0]['PolicyReportID']

        try:
            results = self.swis.invoke('Cirrus.PolicyReports', 'StartCaching', [report_id])
            self.logger.info("ncm_run_compliance_report - StartCaching invoke results: %s", results)

        except Exception as error:
            self.logger.info("ncm_run_compliance_report - StartCaching invoke error: %s", error)
            return False

        return True

    ###################################################################################################################
    ##  User Device Tracker (UDT)                                                                                    ##
    ###################################################################################################################

    # def add_node_to_udt(self, node_name):
    #     udt_properties = {
    #         'NodeID': self.get_node_id(node_name),
    #         'Capability': '2',
    #         'Enabled': True
    #     }
    #
    #     results = self.swis.create('Orion.UDT.NodeCapability', **udt_properties)
    #     self.logger.info("add_node_to_udt - add node at l2 to udt create results: %s", results)
    #
    #     udt_properties = {
    #         'NodeID': self.get_node_id(node_name),
    #         'Capability': '3',
    #         'Enabled': True
    #     }
    #
    #     results = self.swis.create('Orion.UDT.NodeCapability', **udt_properties)
    #     self.logger.info("add_node_to_udt - add node at l3 to udt create results: %s", results)

    ###################################################################################################################
    ##  SolarWinds Voice & Network Quality Manager (VNQM)                                                            ##
    ###################################################################################################################

    # def add_icmp_echo_ip_sla_operation_to_node(self, node_name, ip_sla_operation_number, ip_sla_name):
    #     ip_sla_properties = {
    #         'NodeID': self.get_node_id(node_name),
    #         'OperationTypeID': 5,
    #         'OperationType': "ICMP Echo",
    #         'IsAutoConfigured': False,
    #         'Frequency': 10,
    #         'IpSlaOperationNumber': ip_sla_operation_number,
    #         'OperationName': ip_sla_name
    #     }
    #
    #     results = self.swis.create('Orion.IpSla.Operations', **ip_sla_properties)
    #     self.logger.info("add_icmp_echo_ip_sla_operation_to_node - add IP SLA operation to node create results: %s",
    #                      results)
    #
    # def add_node_to_ip_vnqm(self, node_name):
    #     vnqm_node_properties = {
    #         'NodeID': self.get_node_id(node_name),
    #         'Name': node_name,
    #         'IsHub': False,
    #         'IsAutoConfigured': True
    #     }
    #
    #     results = self.swis.create('Orion.IpSla.Sites', **vnqm_node_properties)
    #     self.logger.info("add_node_to_vnqm - add node to vnqm create results: %s", results)
