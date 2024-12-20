"""NAPALM driver for Netgear switches."""

import socket
from typing import Dict, List, Optional, Any, Union, Tuple
import time
import re
from . import parser  # Use relative import

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)

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
    parse_interfaces_ip,
    parse_ipv6_interfaces,
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

    def _send_command(self, command: str, read_timeout: Optional[int] = None) -> str:
        """Send command with optional timeout.
        
        Args:
            command: Command to send
            read_timeout: Read timeout in seconds, defaults to 10
            
        Returns:
            Command output as string
        """
        if not read_timeout:
            read_timeout = 10  # Default timeout
            
        try:
            output = self.device.send_command_timing(
                command,
                strip_prompt=False,
                strip_command=False,
                read_timeout=read_timeout,
                cmd_verify=False  # Don't verify command echo
            )
            return output
        except Exception as e:
            raise CommandErrorException(f"Failed to send command '{command}': {str(e)}")

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
                # Extract model from first part
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
        """Return a set of facts from the devices.
        
        Returns:
            dict: Facts about the device:
                - uptime (str): System uptime
                - vendor (str): Always "Netgear"
                - model (str): Switch model (e.g. M4250-8G2XF-PoE+, M4350-24X4V, GS108Tv3)
                - hostname (str): Device hostname
                - fqdn (str): Fully qualified domain name
                - os_version (str): Operating system version (format: XX.X.X.XX)
                - serial_number (str): Device serial number
                - interface_list (list): List of interface names
        """
        # Get all info from sysinfo command
        sysinfo_output = self._send_command("show sysinfo")
        
        # Initialize variables
        uptime = "0 secs"
        model = ""
        hostname = ""
        os_version = ""
        serial_number = ""
        
        # Parse sysinfo output
        for line in sysinfo_output.splitlines():
            line = line.strip()
            
            if "System Description" in line:
                # Format: "System Description............................. M4250-8G2XF-PoE+ 8x1G PoE+ 220W and 2xSFP+ Managed Switch, 13.0.4.26, 1.0.0.11"
                # Or: "System Description............................. NETGEAR M4350-24X4V 24x10G Copper 4x25G Fiber Managed Switch, 14.0.2.26, B1.0.0.6"
                # Or: "System Description............................. GS108Tv3 8-Port Gigabit Smart Managed Pro Switch, 7.0.7.3"
                desc = self._clean_output_line(line)
                if desc:
                    parts = desc.split(",")
                    if len(parts) >= 2:
                        # Extract model from first part
                        model_part = parts[0]
                        for word in model_part.split():
                            if word.startswith(("M4", "GS")):
                                model = word
                                break
                            
                        # Extract version
                        version = parts[1].strip()  # Second part is version
                        # Format version if it's just digits (130426 -> 13.0.4.26)
                        if version.isdigit() and len(version) == 6:
                            os_version = f"{version[0:2]}.{version[2]}.{version[3]}.{version[4:6]}"
                        else:
                            os_version = version
                        
            elif "System Name" in line:
                hostname = self._clean_output_line(line)
                
            elif "System Up Time" in line:
                # Already formatted as "X days Y hrs Z mins W secs"
                uptime = self._clean_output_line(line)
                
            elif "Serial Number" in line:
                serial_number = self._clean_output_line(line)
                if serial_number:
                    serial_number = serial_number.split()[0]

        # If serial number not in sysinfo, try show version
        if not serial_number:
            version_output = self._send_command("show version")
            for line in version_output.splitlines():
                if "Serial Number" in line:
                    serial = self._clean_output_line(line)
                    if serial:
                        serial_number = serial.split()[0]
                    break

        # Get interfaces from status command
        output = self._send_command("show interfaces status all")
        interface_list = []
        
        # Parse interface list from status output
        for line in output.splitlines():
            # Skip headers and empty lines
            if not line.strip() or "Link" in line or "-" * 5 in line:
                continue
                
            # Split line into columns
            fields = line.split()
            if fields and "/" in fields[0]:  # Only physical interfaces
                if not fields[0].startswith(("lag", "vlan")):
                    interface_list.append(fields[0])
        
        # Sort interfaces naturally
        interface_list.sort(key=lambda x: tuple(int(n) for n in x.split('/')))

        # Build facts dictionary
        facts = {
            "uptime": uptime,
            "vendor": "Netgear",
            "model": model,
            "hostname": hostname,
            "fqdn": hostname,  # No domain support needed
            "os_version": os_version,
            "serial_number": serial_number,
            "interface_list": interface_list
        }
        
        return facts

    def get_interfaces_ip(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
        """Get interface IP addresses.
        
        Returns:
            dict: Interfaces and their IP addresses, formatted as:
                {
                    "interface": {
                        "ipv4": {
                            "address": {
                                "prefix_length": int
                            }
                        },
                        "ipv6": {
                            "address": {
                                "prefix_length": int
                            }
                        }
                    }
                }
        """
        # Get IPv4 addresses
        output = self._send_command("show ip interface brief")
        print(f"\nIPv4 command output:\n{output}")
        
        if not self._is_supported_command(output):
            print("IPv4 command not supported")
            return {}
            
        interfaces_ip = parser.parse_interfaces_ip(output)
        print(f"\nParsed IPv4 interfaces: {interfaces_ip}")
        
        # Get IPv6 addresses
        output = self._send_command("show ipv6 interface brief")
        print(f"\nIPv6 command output:\n{output}")
        
        if self._is_supported_command(output):
            ipv6_interfaces = parser.parse_ipv6_interfaces(output)
            print(f"\nParsed IPv6 interfaces: {ipv6_interfaces}")
            
            # Merge IPv6 addresses into result
            for interface, data in ipv6_interfaces.items():
                if interface not in interfaces_ip:
                    interfaces_ip[interface] = {"ipv4": {}, "ipv6": {}}
                interfaces_ip[interface]["ipv6"].update(data["ipv6"])
        
        print(f"\nFinal result: {interfaces_ip}")
        return interfaces_ip

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

    def open(self) -> None:
        """Open a connection to the device."""
        # Set connection defaults
        device_args = {
            "device_type": "netgear_prosafe",
            "host": self.hostname,
            "username": self.username,
            "password": self.password,
            "port": 22,  # SSH port
            "global_delay_factor": 1.0,
            "secret": self.password,  # Use same password for enable
            "verbose": False,  # Disable verbose logging
            "session_log": None,  # Disable session logging
            "fast_cli": True,  # Enable fast CLI mode
            "session_timeout": 60,
            "auth_timeout": 30,
            "banner_timeout": 20,
            "conn_timeout": 30,
            "allow_auto_change": True,
            "ssh_strict": False,
            "use_keys": False,
            "disabled_algorithms": {
                "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]
            }
        }

        # Update connection args from optional_args
        device_args.update(self.optional_args)

        try:
            self.device = ConnectHandler(**device_args)
            self._enable_mode()
        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            raise ConnectionException(str(e))

    def _enable_mode(self):
        """Enter privileged mode on supported devices."""
        try:
            self.device.enable(cmd_verify=False)
        except Exception:
            pass

    def close(self) -> None:
        """Close the connection to the device."""
        self.device.disconnect()