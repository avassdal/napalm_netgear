"""NAPALM driver for Netgear switches."""

import socket
from typing import Dict, List, Optional, Union

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionClosedException, ConnectionException
from napalm.base.helpers import mac
from napalm.base.netmiko_helpers import netmiko_args

from napalm_netgear.parser import (
    parse_fixed_width_table,
    parse_key_value_list,
    parse_interface_detail,
    parse_gs108tv3_mac_table,
    parse_gs108tv3_lldp_neighbors,
    parse_gs108tv3_system_info,
)

class NetgearDriver(NetworkDriver):
    """Netgear Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialize Netgear Driver."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args if optional_args else {}

    def _send_command(self, command: str) -> str:
        """Send command to device."""
        try:
            output = self.device.send_command(command)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionException(str(e))

    def get_interfaces(self) -> dict:
        """Get interface details.
        
        Returns:
            dict: Interface details keyed by interface name
        """
        interfaces = {}
        command = "show interface status"  # M4500 uses this command
        output = self._send_command(command)
        
        if not is_supported_command(output):  # Try M4250/M4350 command
            command = "show interfaces status all"
            output = self._send_command(command)
            
        if not is_supported_command(output):  # Try GS108Tv3 command
            command = "show interfaces GigabitEthernet 1-8"
            output = self._send_command(command)
            
        if not is_supported_command(output):
            raise ConnectionException("Unable to get interface status")
            
        # Parse interface status
        if "GigabitEthernet" in output:  # GS108Tv3 format
            current_interface = None
            current_data = {}
            
            for line in output.splitlines():
                line = line.strip()
                
                # New interface section
                if line.startswith("GigabitEthernet"):
                    # Save previous interface if exists
                    if current_interface and current_data:
                        interfaces[current_interface] = current_data
                        
                    # Start new interface
                    parts = line.split()
                    if len(parts) >= 2:
                        current_interface = normalize_interface_name(parts[0].replace("GigabitEthernet", ""))
                        current_data = {
                            "is_up": "up" in line.lower(),
                            "is_enabled": True,  # Assume enabled if present
                            "description": "",
                            "last_flapped": -1.0,
                            "speed": -1,  # Will be updated from Auto-speed line
                            "mtu": 1500,  # Standard MTU
                            "mac_address": "",
                        }
                        
                elif current_interface:
                    if "Auto-speed" in line:
                        current_data["speed"] = -1  # Auto-negotiation
                    elif "media type" in line.lower():
                        current_data["description"] = line.split(",")[-1].strip()
                        
            # Save last interface
            if current_interface and current_data:
                interfaces[current_interface] = current_data
                
        else:  # M4250/M4350/M4500 format
            fields = ["port", "name", "link", "physical", "physical_status", "media", "flow"]
            parsed = parse_fixed_width_table(fields, output.splitlines())
            
            for entry in parsed:
                interface = normalize_interface_name(entry["port"])
                if interface:
                    speed_str = entry.get("physical_status", "")
                    interfaces[interface] = {
                        "is_up": entry.get("link", "").lower() == "up",
                        "is_enabled": True,  # Assume enabled if shown
                        "description": entry.get("name", ""),
                        "last_flapped": -1.0,
                        "speed": MAP_INTERFACE_SPEED.get(speed_str, 0),
                        "mtu": 1500,  # Standard MTU
                        "mac_address": "",  # Not available in status output
                    }
                    
        # Get interface counters for GS108Tv3
        if "GigabitEthernet" in output:
            for interface in interfaces:
                command = f"show interfaces GigabitEthernet {interface.replace('g', '')}"
                counter_output = self._send_command(command)
                if is_supported_command(counter_output):
                    details = parse_interface_detail(interface, counter_output)
                    interfaces[interface].update(details)

        return interfaces

    def get_interfaces_counters(self) -> dict:
        """Get interface counters.
        
        Returns:
            dict: Interface counters keyed by interface name
        """
        counters = {}
        
        # Get list of interfaces first
        interfaces = self.get_interfaces()
        
        for interface in interfaces:
            command = f"show interface {interface}"
            output = self._send_command(command)
            
            # Parse counter values using key-value parser
            parsed = parse_key_value_list(output.splitlines())
            
            # Initialize counter dict with defaults
            counters[interface] = {
                'tx_errors': 0,
                'rx_errors': 0,
                'tx_discards': 0,
                'rx_discards': 0,
                'tx_octets': 0,
                'rx_octets': 0,
                'tx_unicast_packets': 0,
                'rx_unicast_packets': 0,
                'tx_multicast_packets': 0,
                'rx_multicast_packets': 0,
                'tx_broadcast_packets': 0,
                'rx_broadcast_packets': 0,
            }
            
            # Map parsed values to counter keys
            key_map = {
                'Total Transmit Errors': 'tx_errors',
                'Total Receive Errors': 'rx_errors',
                'Total Transmit Drops': 'tx_discards',
                'Total Receive Drops': 'rx_discards',
                'Bytes Transmitted': 'tx_octets',
                'Bytes Received': 'rx_octets',
                'Unicast Packets Transmitted': 'tx_unicast_packets',
                'Unicast Packets Received': 'rx_unicast_packets',
                'Multicast Packets Transmitted': 'tx_multicast_packets',
                'Multicast Packets Received': 'rx_multicast_packets',
                'Broadcast Packets Transmitted': 'tx_broadcast_packets',
                'Broadcast Packets Received': 'rx_broadcast_packets',
            }
            
            for key, counter_key in key_map.items():
                try:
                    value = int(parsed.get(key, "0"))
                    counters[interface][counter_key] = value
                except ValueError:
                    continue
                    
        return counters

    def get_facts(self) -> dict:
        """Returns a dictionary containing the following information:
         * uptime - Uptime of the device in seconds.
         * vendor - Manufacturer of the device.
         * model - Device model.
         * hostname - Hostname of the device
         * fqdn - Fqdn of the device
         * os_version - String with the OS version running on the device.
         * serial_number - Serial number of the device
         * interface_list - List of the interfaces of the device
        """
        facts = {
            'uptime': 0,
            'vendor': 'Netgear',
            'model': '',
            'hostname': '',
            'fqdn': '',
            'os_version': '',
            'serial_number': '',
            'interface_list': []
        }
        
        # Get system information from running config
        command = "show running-config"
        output = self._send_command(command)
        
        if "SYSTEM CONFIG FILE" in output:  # GS108Tv3 format
            info = parse_gs108tv3_system_info(output)
            facts.update(info)
            
            # Get interface list from config
            for line in output.splitlines():
                if line.startswith('interface g'):
                    port = line.split()[1]
                    if port not in facts['interface_list']:
                        facts['interface_list'].append(port)
                        
        else:  # M4250/M4350/M4500 format
            # Get system information
            command = "show version"
            output = self._send_command(command)
            parsed = parse_key_value_list(output.splitlines())
            
            facts.update({
                'model': parsed.get('Machine Model', ''),
                'os_version': parsed.get('Software Version', ''),
                'serial_number': parsed.get('Serial Number', ''),
            })
            
            # Get hostname
            command = "show hosts"
            output = self._send_command(command)
            parsed = parse_key_value_list(output.splitlines())
            facts['hostname'] = parsed.get('Host Name', '')
            facts['fqdn'] = facts['hostname']
            
            # Get uptime
            command = "show system"
            output = self._send_command(command)
            parsed = parse_key_value_list(output.splitlines())
            try:
                facts['uptime'] = int(parsed.get('System Up Time', '0').split()[0])
            except ValueError:
                facts['uptime'] = -1
                
            # Get interface list from status
            interfaces = self.get_interfaces()
            facts['interface_list'] = sorted(list(interfaces.keys()))
            
        return facts

    def get_mac_address_table(self) -> list:
        """Return LLDP neighbors details."""
        # Try GS108Tv3 command first
        command = "show mac address-table"
        output = self._send_command(command)
        
        if "MAC Address" in output and "Type" in output:  # GS108Tv3 format
            return parse_gs108tv3_mac_table(output)
            
        # Try M4250/M4350/M4500 format
        command = "show mac-addr-table"
        output = self._send_command(command)
        
        # Parse output using fixed width table parser
        fields = ["vlan", "mac", "type", "port"]
        parsed = parse_fixed_width_table(fields, output.splitlines())
        
        mac_entries = []
        for entry in parsed:
            try:
                vlan_id = int(entry["vlan"])
                mac_entries.append({
                    "mac": entry["mac"],
                    "interface": entry["port"],
                    "vlan": vlan_id,
                    "static": entry["type"].lower() != "dynamic",
                    "active": True,
                    "moves": 0,
                    "last_move": 0.0
                })
            except (ValueError, KeyError):
                continue
                
        return mac_entries

    def get_lldp_neighbors(self) -> dict:
        """Return LLDP neighbors details."""
        # Try GS108Tv3 command first
        command = "show lldp neighbor"
        output = self._send_command(command)
        
        if "Device ID" in output and "Port ID" in output:  # GS108Tv3 format
            return parse_gs108tv3_lldp_neighbors(output)
            
        # Try M4250/M4350/M4500 format
        command = "show lldp remote-device all"
        output = self._send_command(command)
        
        neighbors = {}
        # Skip header lines
        lines = output.splitlines()
        header_found = False
        
        for line in lines:
            if "Interface" in line and "Remote ID" in line:
                header_found = True
                continue
            
            if not header_found:
                continue
            
            # Skip separator lines
            if "-" * 5 in line:
                continue
            
            # Parse fields
            fields = line.split()
            if len(fields) < 3:
                continue
            
            try:
                local_port = fields[0]
                remote_id = fields[1]
                remote_port = fields[2]
            except IndexError:
                continue
            
            # Get remote system name
            command = f"show lldp remote-device detail {local_port}"
            detail_output = self._send_command(command)
            remote_name = ""
            
            for detail_line in detail_output.splitlines():
                if "System Name:" in detail_line:
                    remote_name = detail_line.split(":", 1)[1].strip()
                    break
            
            # Initialize interface if not present
            if local_port not in neighbors:
                neighbors[local_port] = []
            
            # Add neighbor
            neighbor = {
                "hostname": remote_name or remote_id,  # Use ID if name not found
                "port": remote_port
            }
            neighbors[local_port].append(neighbor)
            
        return neighbors

    def get_lldp_neighbors_detail(self) -> dict:
        """Return detailed view of the LLDP neighbors.
        
        Returns:
            dict: Detailed LLDP neighbors keyed by interface
        """
        neighbors = {}
        
        # Get LLDP neighbors
        command = "show lldp remote-device"
        output = self._send_command(command)
        
        # Parse output using key-value parser
        parsed = parse_key_value_list(output.splitlines())
        
        # Convert parsed data to LLDP neighbors format
        for key, value in parsed.items():
            if key.startswith("Interface"):
                interface = key.split(":")[1].strip()
                neighbors[interface] = {
                    'parent_interface': interface,
                    'remote_chassis_id': "",
                    'remote_port': "",
                    'remote_port_description': "",
                    'remote_system_name': "",
                    'remote_system_description': "",
                    'remote_system_capab': [],
                    'remote_system_enable_capab': []
                }
                
            elif key.startswith("Chassis ID"):
                neighbors[interface]['remote_chassis_id'] = value
                
            elif key.startswith("Port ID"):
                neighbors[interface]['remote_port'] = value
                
            elif key.startswith("System Name"):
                neighbors[interface]['remote_system_name'] = value
                
            elif key.startswith("Port Description"):
                neighbors[interface]['remote_port_description'] = value
                
            elif key.startswith("System Description"):
                neighbors[interface]['remote_system_description'] = value
                
            elif key.startswith("System Capabilities"):
                neighbors[interface]['remote_system_capab'] = value.split(",")
                
            elif key.startswith("Enabled Capabilities"):
                neighbors[interface]['remote_system_enable_capab'] = value.split(",")
                
        return neighbors

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> Dict[str, str]:
        """Return the configuration of a device.

        Args:
            retrieve: Which configuration type you want to populate, default is all of them.
                      The rest will be set to "".
            full: Retrieve all the configuration. For instance, on ios, "sh run all".
            sanitized: Remove secret data. Default: ``False``.
            format: The configuration format style to be retrieved.

        Returns:
          The object returned is a dictionary with a key for each configuration store:
            - running: Representation of the native running configuration
            - candidate: Representation of the native candidate configuration
            - startup: Representation of the native startup configuration
        """
        configs = {
            "startup": "",
            "running": "",
            "candidate": ""  # Netgear doesn't support candidate configuration
        }

        if retrieve in ("startup", "all"):
            command = "show startup-config"
            output = self._send_command(command)
            if sanitized:
                # Remove password/secret lines
                output = re.sub(r'^.*secret .*$', '', output, flags=re.M)
                output = re.sub(r'^.*password .*$', '', output, flags=re.M)
                # Remove SNMP community strings
                output = re.sub(r'^.*community .*$', '', output, flags=re.M)
            configs["startup"] = output.strip()

        if retrieve in ("running", "all"):
            command = "show running-config"
            output = self._send_command(command)
            if sanitized:
                # Remove password/secret lines
                output = re.sub(r'^.*secret .*$', '', output, flags=re.M)
                output = re.sub(r'^.*password .*$', '', output, flags=re.M)
                # Remove SNMP community strings
                output = re.sub(r'^.*community .*$', '', output, flags=re.M)
            configs["running"] = output.strip()

        return configs

    def load_replace_candidate(self, filename=None, config=None):
        """
        Populates the candidate configuration. You can populate it from a file or from a string.
        If you send both a filename and a string containing the configuration, the file takes
        precedence.
        If you use this method the existing configuration will be replaced entirely by the
        candidate configuration once you commit the changes. This method will not change the
        configuration by itself.
        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise ReplaceConfigException: If there is an error on the configuration sent.
        """
        if(filename is not None):
            with open(filename, 'r') as f:
                config = f.read()
        self.config = config

    def load_merge_candidate(self, filename=None, config=None):
        """
        Populates the candidate configuration. You can populate it from a file or from a string.
        If you send both a filename and a string containing the configuration, the file takes
        precedence.
        If you use this method the existing configuration will be merged with the candidate
        configuration once you commit the changes. This method will not change the configuration
        by itself.
        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise MergeConfigException: If there is an error on the configuration sent.
        """
        if(filename is not None):
            with open(filename, 'r') as f:
                config = f.read()
        self.config = config

    def compare_config(self):
        """
        :return: A string showing the difference between the running configuration and the \
        candidate configuration. The running_config is loaded automatically just before doing the \
        comparison so there is no need for you to do it.
        """
        return "some stuff might be different"

    def commit_config(self, message="", revert_in=None):
        """
        Commits the changes requested by the method load_replace_candidate or load_merge_candidate.
        NAPALM drivers that support 'commit confirm' should cause self.has_pending_commit
        to return True when a 'commit confirm' is in progress.
        Implementations should raise an exception if commit_config is called multiple times while a
        'commit confirm' is pending.
        :param message: Optional - configuration session commit message
        :type message: str
        :param revert_in: Optional - number of seconds before the configuration will be reverted
        :type revert_in: int|None
        """
        output = ""
        output = self.device.send_config_set(
            config_commands=self.config.splitlines(),
            enter_config_mode=False
        )
        output += self.device.save_config(confirm=True, confirm_response="")

    def open(self):
        """Open a connection to the device."""
        device_type = "netgear_prosafe"
        
        # Check if required fields are present
        if self.username == "":
            raise ConnectionException("username is required")
        if self.password == "":
            raise ConnectionException("password is required")
            
        try:
            self.device = self._netmiko_open(
                device_type, netmiko_optional_args=self.netmiko_optional_args
            )
            
            # Check if this is a GS108Tv3 by trying to get version info
            try:
                output = self._send_command("show running-config", expect_string=r"#|>")
                if "SYSTEM CONFIG FILE" in output and "GS108Tv3" in output:
                    # Enable mode for GS108Tv3 using the same password as login
                    self._enable_gs108tv3()
            except Exception:
                pass
                
        except ConnectionException as e:
            raise ConnectionException(f"Cannot connect to {self.hostname}: {str(e)}")
            
    def _enable_gs108tv3(self):
        """Enable privileged mode on GS108Tv3 using the same password as login."""
        try:
            # Send enable command and wait for password prompt
            output = self.device.send_command_timing(
                "enable",
                strip_prompt=False,
                strip_command=False
            )
            
            if "Password:" in output:
                # Send the same password used for login
                output = self.device.send_command_timing(
                    self.password,
                    strip_prompt=False,
                    strip_command=False
                )
                
                if "#" not in output:
                    raise ConnectionException("Failed to enter enable mode")
                    
        except Exception as e:
            raise ConnectionException(f"Error entering enable mode: {str(e)}")