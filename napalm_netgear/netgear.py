"""NAPALM driver for Netgear switches."""

import socket
from typing import Dict, List, Optional, Any, Union, Tuple
import time
import re
from . import parser  # Use relative import

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionClosedException, ConnectionException, CommandErrorException
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

    def _is_supported_command(self, output: str) -> bool:
        """Check if command output indicates it's supported."""
        return not any(error in output for error in [
            "% Invalid input detected",
            "An invalid interface has been used",
            "Invalid command"
        ])

    def _parse_speed(self, speed_str):
        """Parse speed string into float (Mbps)."""
        if not speed_str or speed_str.lower() == 'auto' or speed_str.lower() == 'unknown':
            return 0.0
            
        # Handle special cases like "10G Full", "1000 Full"
        speed_str = speed_str.lower().replace('full', '').replace('half', '').strip()
        
        # Convert 10G to 10000
        if 'g' in speed_str:
            try:
                return float(speed_str.replace('g', '')) * 1000
            except ValueError:
                return 0.0
            
        try:
            return float(speed_str.split()[0])  # Take first number if multiple parts
        except (ValueError, IndexError):
            return 0.0  # Return 0 for non-numeric speeds

    def get_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Get interface details.

        Returns:
            dict: Interfaces in Napalm format:
                - is_up (bool)
                - is_enabled (bool)
                - description (str)
                - speed (int - Mbps)
                - mtu (int)
                - mac_address (str)
                - last_flapped (float)
        """
        interfaces = {}

        # Get interface status - single command for all interfaces
        cmd = "show interfaces status all"
        output = self._send_command(cmd)

        # Parse interface status table
        interface_status = parser.parse_interface_status(output)

        # Process each interface
        for status in interface_status:
            iface = status.get("port")
            if not iface:
                continue

            # Skip LAG/VLAN interfaces and invalid interface names
            if iface.startswith(('lag ', 'vlan ', '(')) or not re.match(r'\d+/\d+', iface):
                continue

            # Create basic interface info
            interface_info = {
                "is_up": status.get("state", "").lower() == "up",
                "is_enabled": True,  # Assume enabled if visible
                "description": status.get("name", ""),
                "mac_address": "",  # Not available in status table
                "last_flapped": -1.0,  # Not available in status table
                "mtu": 1500,  # Default MTU
            }

            # Get speed from Physical Status field
            speed_str = status.get("speed", "").lower()
            if speed_str:
                if "10g" in speed_str:
                    interface_info["speed"] = 10000
                elif "1000" in speed_str:
                    interface_info["speed"] = 1000
                elif "100" in speed_str:
                    interface_info["speed"] = 100
                elif "10" in speed_str:
                    interface_info["speed"] = 10
                else:
                    interface_info["speed"] = 0
            else:
                interface_info["speed"] = 0
            
            interfaces[iface] = interface_info

        return interfaces

    def _parse_interface_status(self, output):
        """Parse the output of 'show interfaces status all'."""
        interfaces = []
        header = None
        fields = None

        for line in output.splitlines():
            # Skip empty lines
            if not line.strip():
                continue

            # Check for M4250 format header
            if "Link    Physical    Physical    Media" in line:
                fields = ['port', 'name', 'link_state', 'physical_mode', 'physical_status', 'media_type', 'flow_control', 'vlan']
                continue
            # Check for M4500 format header
            elif "Port       Name                    Link" in line:
                fields = ['port', 'name', 'link', 'state', 'mode', 'speed', 'type', 'vlan']
                continue
            # Default format header
            elif "Port" in line and "Link" in line:
                fields = ['port', 'link', 'admin', 'speed', 'duplex', 'type', 'name']
                continue

            if not fields:
                continue

            # Skip separator line
            if '-' * 5 in line:
                continue

            # Parse values based on field mapping
            values = line.split()
            if not values:
                continue

            interface = {}
            for i, field in enumerate(fields):
                if i < len(values):
                    interface[field] = values[i]
                else:
                    interface[field] = ''

            # Skip invalid interfaces
            if not interface.get('port') or interface['port'].startswith('lag') or interface['port'].startswith('vlan'):
                continue

            interfaces.append(interface)

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

    def _clean_output_line(self, line: str, remove_dots: bool = True) -> str:
        """Clean up output line by removing dots and extra whitespace.
        
        Args:
            line: The line to clean
            remove_dots: If True, remove all dots from the line. If False, keep dots.
        """
        # First split on the field name
        if ":" in line:
            _, value = line.split(":", 1)
        else:
            for field in ["System Description", "System Name", "System Up Time", "Serial Number", "Default domain"]:
                if field in line:
                    _, value = line.split(field, 1)
                    break
            else:
                value = line
        
        # Remove dots if requested and clean whitespace
        if remove_dots:
            value = value.replace(".", "")
        value = value.strip()
        return value

    def _parse_version(self, desc: str) -> Tuple[str, str]:
        """Parse model and version from system description.
        
        Args:
            desc: System description line
            
        Returns:
            Tuple of (model, version)
        """
        try:
            # Remove dots from description but keep commas
            desc = desc.replace(".", "").strip()
            
            # Split by comma and get model and version
            parts = [p.strip() for p in desc.split(",")]
            if len(parts) >= 2:
                model = parts[0].split()[0]  # First word of first part
                version = parts[1].strip()  # Second part is version
                
                # Add dots back to version (format: XX.X.X.XX)
                if len(version) == 6:  # 130426 -> 13.0.4.26
                    version = f"{version[0:2]}.{version[2]}.{version[3]}.{version[4:6]}"
                return model, version
        except (IndexError, ValueError) as e:
            print(f"Error parsing version: {str(e)}")
        
        return "", ""

    def _format_uptime(self, seconds: int) -> str:
        """Convert uptime in seconds to days, hours, minutes, seconds format."""
        days = seconds // 86400
        seconds %= 86400
        hours = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        
        parts = []
        if days > 0:
            parts.append(f"{days} {'days' if days != 1 else 'day'}")
        if hours > 0:
            parts.append(f"{hours} {'hrs' if hours != 1 else 'hr'}")
        if minutes > 0:
            parts.append(f"{minutes} {'mins' if minutes != 1 else 'min'}")
        if seconds > 0 or not parts:  # Include seconds if non-zero or if all other parts are zero
            parts.append(f"{seconds} {'secs' if seconds != 1 else 'sec'}")
        
        return " ".join(parts)

    def get_facts(self) -> Dict[str, Any]:
        """Return a set of facts from the devices."""
        # Get system info
        cmd = "show sysinfo"
        output = self._send_command(cmd)
        print(f"Debug sysinfo output:\n{cmd}\n\n{output}")

        # Parse system description
        desc = ""
        uptime = ""
        hostname = ""
        for line in output.splitlines():
            if "System Description" in line:
                desc = line.split(".")[-1].strip()
            elif "System Up Time" in line:
                uptime = line.split(".")[-1].strip()
            elif "System Name" in line:
                hostname = line.split(".")[-1].strip()

        # Parse model and version from description
        model, version = self._parse_version(desc)

        # Get interface list from status command
        interfaces = []
        cmd = "show interfaces status all"
        output = self._send_command(cmd)
        print(f"Sending command: {cmd}")
        print(f"No read_timeout specified")
        print(f"Command output: {cmd}\n\n{output[:50]}...")

        # Parse interface list from status output
        for line in output.splitlines():
            if not line.strip():
                continue
            # Skip header lines
            if any(x in line for x in ["Link", "Port", "------"]):
                continue
            # Extract interface name
            parts = line.split()
            if not parts:
                continue
            iface = parts[0]
            # Skip LAG/VLAN interfaces
            if iface.startswith(("lag ", "vlan ", "(")):
                continue
            # Only add physical interfaces
            if re.match(r'\d+/\d+', iface):
                interfaces.append(iface)

        return {
            "uptime": uptime,
            "vendor": "Netgear",
            "model": model,
            "hostname": hostname,
            "fqdn": hostname,  # FQDN not available, use hostname
            "os_version": version,
            "serial_number": "",  # Serial number not available in sysinfo
            "interface_list": sorted(interfaces)
        }

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
            # Get basic neighbor info
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
                if "LLDP Remote Device Summary" in line:
                    continue
                    
                if "Interface" in line and "RemID" in line:
                    header_found = True
                    continue
                    
                if header_found and line:
                    # Skip separator lines
                    if "-" in line and not any(c.isalnum() for c in line):
                        continue
                        
                    # Split line into columns
                    parts = line.split()
                    if len(parts) >= 3:  # At least interface, remote ID, and chassis ID
                        interface = parts[0]
                        # Skip header rows that might appear in the middle
                        if interface == "Interface":
                            continue
                            
                        # Get remote chassis ID (MAC address)
                        chassis_id = parts[2]  # Usually MAC address
                        
                        # Only process if we have valid data
                        if chassis_id and any(c.isalnum() for c in chassis_id):
                            # Get detailed info for this interface
                            detail_output = self.device.send_command_timing(
                                f"show lldp remote-device detail {interface}",
                                strip_prompt=False,
                                strip_command=False,
                                read_timeout=10,
                                cmd_verify=False
                            )
                            
                            # Parse port ID from detail output
                            port_id = None
                            for detail_line in detail_output.splitlines():
                                if "Port ID: " in detail_line:
                                    port_id = detail_line.split("Port ID: ", 1)[1].strip()
                                    break
                            
                            if interface not in neighbors:
                                neighbors[interface] = []
                                
                            neighbors[interface].append({
                                "hostname": chassis_id,
                                "port": port_id or interface  # Use port ID if found, otherwise interface
                            })
            
            # Remove any empty interfaces
            neighbors = {k: v for k, v in neighbors.items() if v}
            
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
                read_timeout=10,
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
                    read_timeout=30,
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