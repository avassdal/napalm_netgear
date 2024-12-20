"""NAPALM driver for Netgear switches."""

import socket
from typing import Dict, List, Optional, Union
import time
import re

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

    def _send_command(self, command, read_timeout=None):
        """Send command with optional timeout."""
        try:
            print(f"Sending command: {command}")  # Debug output
            if read_timeout:
                print(f"Using read_timeout: {read_timeout}")  # Debug output
                output = self.device.send_command_timing(
                    command,
                    strip_prompt=False,
                    strip_command=False,
                    read_timeout=read_timeout,
                    cmd_verify=False  # Don't verify command echo
                )
            else:
                print("No read_timeout specified")  # Debug output
                output = self.device.send_command_timing(
                    command,
                    strip_prompt=False,
                    strip_command=False,
                    cmd_verify=False  # Don't verify command echo
                )
            print(f"Command output: {output[:100]}...")  # Debug output (first 100 chars)
            return output
        except Exception as e:
            print(f"Error sending command: {str(e)}")  # Debug output
            raise CommandErrorException(f"Failed to send command {command}: {str(e)}")

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
            
            # Get interface config for MTU
            config_output = self._send_command("show running-config")
            mtu_map = {}  # Map of interface to MTU
            current_if = None
            for line in config_output.splitlines():
                line = line.strip()
                if line.startswith("interface g"):
                    current_if = line.split()[1]
                elif current_if and line.startswith("mtu "):
                    try:
                        mtu_map[current_if] = int(line.split()[1])
                    except (IndexError, ValueError):
                        pass
            
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
                            "mtu": mtu_map.get(current_interface, 1500),  # Get MTU from config
                            "mac_address": "",
                        }
                        
                elif current_interface:
                    if "Auto-speed" in line:
                        current_data["speed"] = -1  # Auto-negotiation
                    elif "media type" in line.lower():
                        current_data["description"] = line.split(",")[-1].strip()
                    elif "MAC address is" in line:
                        mac = line.split("is", 1)[1].strip()
                        current_data["mac_address"] = mac
                        
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
                        "mtu": 1500,  # Will be updated from interface details
                        "mac_address": "",  # Will be updated from interface details
                    }
                    
                    # Get interface details for MTU and MAC
                    command = f"show interface {interface}"
                    detail_output = self._send_command(command)
                    if is_supported_command(detail_output):
                        details = parse_interface_detail(interface, detail_output)
                        interfaces[interface].update(details)
                        
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
                'Transmit Packet Errors': 'tx_errors',
                'Packets Received With Error': 'rx_errors',
                'Transmit Packets Discarded': 'tx_discards',
                'Receive Packets Discarded': 'rx_discards',
                'Bytes Transmitted': 'tx_octets',
                'Bytes Received': 'rx_octets',
                'Packets Transmitted Without Errors': 'tx_unicast_packets',
                'Packets Received Without Error': 'rx_unicast_packets',
                'Multicast Packets Transmitted': 'tx_multicast_packets',
                'Multicast Packets Received': 'rx_multicast_packets',
                'Broadcast Packets Transmitted': 'tx_broadcast_packets',
                'Broadcast Packets Received': 'rx_broadcast_packets',
                # GS108Tv3 format
                'Total Transmit Errors': 'tx_errors',
                'Total Receive Errors': 'rx_errors', 
                'Total Transmit Drops': 'tx_discards',
                'Total Receive Drops': 'rx_discards',
                'Total Bytes Transmitted': 'tx_octets',
                'Total Bytes Received': 'rx_octets',
                'Unicast Packets Transmitted': 'tx_unicast_packets',
                'Unicast Packets Received': 'rx_unicast_packets'
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

    def get_lldp_neighbors(self) -> Dict[str, List[Dict[str, str]]]:
        """Get LLDP neighbors."""
        
        # First try M4500 command
        try:
            output = self.device.send_command_timing(
                "show lldp remote-device all",
                strip_prompt=False,
                strip_command=False,
                read_timeout=30,  # Longer timeout
                cmd_verify=False
            )
            
            # Parse the output
            neighbors = {}
            
            # Skip header lines and empty lines
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            header_found = False
            
            for line in lines:
                if "Interface" in line and "RemID" in line:
                    header_found = True
                    continue
                    
                if header_found and line:
                    # Split line into columns
                    parts = line.split()
                    if len(parts) >= 3:  # At least interface, remote ID, and chassis ID
                        interface = parts[0]
                        hostname = parts[2]  # Chassis ID is typically the hostname
                        
                        if interface not in neighbors:
                            neighbors[interface] = []
                            
                        neighbors[interface].append({
                            "hostname": hostname,
                            "port": parts[0]  # Using local interface as port for now
                        })
            
            return neighbors
            
        except Exception as e:
            print(f"Error getting LLDP neighbors: {str(e)}")
            return {}
            
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
            netmiko_optional_args = {
                "port": self.optional_args.get("port", 22),
                "global_delay_factor": 1.0,  # Increased delay
                "secret": self.password,  # Use login password as enable secret
                "verbose": True,  # Enable verbose logging
                "session_log": "netmiko_session.log",  # Log all session output
                "fast_cli": False,  # Disable fast CLI mode for better reliability
                "session_timeout": 60,  # Longer timeout
                "auth_timeout": 30,  # Longer auth timeout
                "banner_timeout": 20,  # Longer banner timeout
                "conn_timeout": 30,  # Longer connection timeout
                "allow_auto_change": True,  # Allow automatic handling of password prompts
                "ssh_strict": False,  # Don't be strict about SSH key checking
                "use_keys": False,  # Don't use SSH keys
                "disabled_algorithms": {
                    "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]  # Disable newer algorithms
                },
            }
            
            print(f"Attempting connection with args: {netmiko_optional_args}")  # Debug output
            
            try:
                print("Starting _netmiko_open...")  # Debug output
                self.device = self._netmiko_open(
                    device_type, netmiko_optional_args=netmiko_optional_args
                )
                print("_netmiko_open completed successfully")  # Debug output
            except Exception as e:
                print(f"Connection attempt failed: {str(e)}")  # Debug output
                raise ConnectionException(f"Failed to connect: {str(e)}")
            
            print("Connection established, checking device type")  # Debug output
            
            # Give device time to settle
            time.sleep(2)  # Increased sleep time
            
            # Clear any pending output
            self.device.clear_buffer()
            
            # Disable paging
            print("Disabling paging...")  # Debug output
            self.device.send_command_timing(
                "no pager",
                strip_prompt=False,
                strip_command=False,
                read_timeout=10,  # Increased timeout
                cmd_verify=False
            )
            
            # Check device type and handle enable mode accordingly
            try:
                print("Sending show running-config command...")  # Debug output
                # Use send_command_timing instead of send_command
                output = self.device.send_command_timing(
                    "show running-config",
                    strip_prompt=False,
                    strip_command=False,
                    read_timeout=30,  # Increased timeout
                    cmd_verify=False
                )
                print(f"Running config output: {output[:100]}...")  # Debug output (first 100 chars)
                
                # Check if we're already in privileged mode
                if "#" in self.device.find_prompt():
                    print("Already in privileged mode, skipping enable")  # Debug output
                else:
                    # Determine device type and enable mode requirements
                    if "SYSTEM CONFIG FILE" in output and "GS108Tv3" in output:
                        print("Detected GS108Tv3, enabling privileged mode")  # Debug output
                        self._enable_mode()
                    elif any(model in output for model in ["M4250", "M4350"]):
                        print("Detected M4250/M4350, enabling privileged mode")  # Debug output
                        self._enable_mode()
                    elif "M4500" in output:
                        print("Detected M4500, already in privileged mode")  # Debug output
                    else:
                        print("Unknown device type, attempting enable mode")  # Debug output
                        self._enable_mode()
                    
            except Exception as e:
                print(f"Error checking device type: {str(e)}")  # Debug output
                # Don't raise here, try to proceed without enable mode
                pass
                
        except ConnectionException as e:
            print(f"Connection failed: {str(e)}")  # Debug output
            raise ConnectionException(f"Cannot connect to {self.hostname}: {str(e)}")

    def _enable_mode(self):
        """Enter privileged mode on supported devices."""
        try:
            print("Attempting to enter enable mode...")  # Debug output
            
            # First check if we're already in enable mode
            output = self.device.find_prompt()
            print(f"Current prompt: {output}")  # Debug output
            
            if "#" in output:
                print("Already in enable mode")  # Debug output
                return
                
            # Send enable command and wait for password prompt
            output = self.device.send_command_timing(
                "enable",
                strip_prompt=False,
                strip_command=False,
                read_timeout=5
            )
            print(f"Enable command output: {output}")  # Debug output
            
            # Look for various password prompts
            password_prompts = [
                "Password:",
                "password:",
                "Enter password:",
                "Enter enable password:",
                "Password: "
            ]
            
            if any(prompt in output for prompt in password_prompts):
                print("Password prompt detected, sending password...")  # Debug output
                # Send the same password used for login
                output = self.device.send_command_timing(
                    self.password,
                    strip_prompt=False,
                    strip_command=False,
                    read_timeout=5
                )
                print(f"Password response: {output}")  # Debug output
                
                if "#" not in output:
                    raise ConnectionException("Failed to enter enable mode - incorrect password or unexpected response")
            else:
                print(f"No password prompt found in output: {output}")  # Debug output
                raise ConnectionException("Failed to enter enable mode - no password prompt")
                    
        except Exception as e:
            print(f"Error in enable mode: {str(e)}")  # Debug output
            raise ConnectionException(f"Error entering enable mode: {str(e)}")