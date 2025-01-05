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

import logging

logger = logging.getLogger(__name__)

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
        self.log = logger

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
        """Get interface details."""
        interfaces = {}

        # Get interface status
        output = self._send_command("show interfaces status all")
        
        # Skip header lines
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        data_lines = False
        
        for line in lines:
            # Skip until we find the separator line
            if '-' * 5 in line:
                data_lines = True
                continue
                
            if not data_lines:
                continue
                
            # Split line into fields
            fields = line.split()
            if len(fields) < 4:  # Need at least port, type, admin, status
                continue
                
            interface = fields[0]
            if not interface or interface.startswith(('lag', 'vlan', '(')):
                continue
                
            # Parse interface state
            admin_state = fields[2] if len(fields) > 2 else ""
            phys_state = fields[3] if len(fields) > 3 else ""
            
            interfaces[interface] = {
                "is_up": phys_state.lower() == "up",
                "is_enabled": admin_state.lower() == "enable",
                "description": "",  # Not available in status output
                "mac_address": "",  # Not available in status output
                "last_flapped": -1.0,  # Not available
                "mtu": 1500,  # Default MTU
                "speed": 0  # Will be updated if available
            }
            
            # Try to parse speed if available
            if len(fields) > 4:
                speed_str = fields[4].lower()
                if "10g" in speed_str:
                    interfaces[interface]["speed"] = 10000
                elif "1000" in speed_str:
                    interfaces[interface]["speed"] = 1000
                elif "100" in speed_str:
                    interfaces[interface]["speed"] = 100
                elif "10" in speed_str:
                    interfaces[interface]["speed"] = 10
        
        return interfaces

    def get_interfaces_counters(self) -> dict:
        """Get interface counters.
        
        Returns:
            dict: Interface counters keyed by interface name:
                {
                    "interface": {
                        "tx_errors": int,
                        "rx_errors": int,
                        "tx_discards": int,
                        "rx_discards": int,
                        "tx_octets": int,
                        "rx_octets": int,
                        "tx_unicast_packets": int,
                        "rx_unicast_packets": int,
                        "tx_multicast_packets": int,
                        "rx_multicast_packets": int,
                        "tx_broadcast_packets": int,
                        "rx_broadcast_packets": int
                    }
                }
                
        Example M4250:
            >>> {
            ...     "0/1": {
            ...         "tx_errors": 0,
            ...         "rx_errors": 0,
            ...         "tx_discards": 0,
            ...         "rx_discards": 0,
            ...         "tx_octets": 0,
            ...         "rx_octets": 1234567,
            ...         "tx_unicast_packets": 0,
            ...         "rx_unicast_packets": 1234,
            ...         "tx_multicast_packets": 0,
            ...         "rx_multicast_packets": 12,
            ...         "tx_broadcast_packets": 0,
            ...         "rx_broadcast_packets": 7
            ...     }
            ... }
            
        Example M4350:
            >>> {
            ...     "1/0/1": {
            ...         "tx_errors": 0,
            ...         "rx_errors": 0,
            ...         "tx_discards": 0,
            ...         "rx_discards": 0,
            ...         "tx_octets": 0,
            ...         "rx_octets": 1234567,
            ...         "tx_unicast_packets": 0,
            ...         "rx_unicast_packets": 1234,
            ...         "tx_multicast_packets": 0,
            ...         "rx_multicast_packets": 12,
            ...         "tx_broadcast_packets": 0,
            ...         "rx_broadcast_packets": 7
            ...     }
            ... }
        """
        counters = {}
        
        # Get interface counters
        output = self._send_command("show interface counters")
        if not self._is_supported_command(output):
            return {}
            
        # Parse counter values
        try:
            # Skip empty lines and prompts
            lines = [line.strip() for line in output.splitlines() 
                    if line.strip() and not line.startswith("(M4250")]
            
            # Find header line
            header_line = None
            for i, line in enumerate(lines):
                if "Port" in line and "InOctets" in line:
                    header_line = line
                    data_start = i + 2  # Skip separator line
                    break
                    
            if not header_line:
                return {}
                
            # Parse each interface line
            for line in lines[data_start:]:
                if not line or line.startswith("CPU"):
                    break
                    
                fields = line.split()
                if len(fields) < 8:  # Need at least port and basic counters
                    continue
                    
                # Get interface name
                interface = fields[0]
                if interface.startswith("ch"):
                    continue  # Skip channel interfaces
                    
                # Initialize counter dict with defaults
                counters[interface] = {
                    'tx_errors': 0,
                    'rx_errors': int(fields[7]) if len(fields) > 7 else 0,  # Rx Error
                    'tx_discards': 0,
                    'rx_discards': int(fields[5]) if len(fields) > 5 else 0,  # InDropPkts
                    'tx_octets': 0,
                    'rx_octets': int(fields[1]) if len(fields) > 1 else 0,  # InOctets
                    'tx_unicast_packets': 0,
                    'rx_unicast_packets': int(fields[2]) if len(fields) > 2 else 0,  # InUcastPkts
                    'tx_multicast_packets': 0,
                    'rx_multicast_packets': int(fields[3]) if len(fields) > 3 else 0,  # InMcastPkts
                    'tx_broadcast_packets': 0,
                    'rx_broadcast_packets': int(fields[4]) if len(fields) > 4 else 0,  # InBcastPkts
                }
                
        except Exception:
            return {}
            
        return counters

    def get_interface_counters(self) -> dict:
        """Alias for get_interfaces_counters to match NAPALM CLI."""
        return self.get_interfaces_counters()
        
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
                - uptime (int): System uptime in seconds
                - vendor (str): Always "Netgear"
                - model (str): Switch model (e.g. M4250-8G2XF-PoE+, M4350-24X4V, GS108Tv3)
                - hostname (str): Device hostname
                - fqdn (str): Fully qualified domain name
                - os_version (str): Operating system version (format: XX.X.X.XX)
                - serial_number (str): Device serial number
                - interface_list (list): List of interface names
        """
        # Initialize variables
        uptime = 0
        model = ""
        hostname = ""
        os_version = ""
        serial_number = ""
        interface_list = []
        
        # Get all info from sysinfo command
        sysinfo_output = self._send_command("show sysinfo")
        
        # Parse sysinfo output
        for line in sysinfo_output.splitlines():
            line = line.strip()
            
            if "System Description" in line:
                desc = self._clean_output_line(line)
                if desc:
                    # For GS108Tv3, model is first word before "ProSAFE"
                    if "ProSAFE" in desc:
                        model = desc.split("ProSAFE")[0].strip().split()[0]
                    else:
                        # For other models, look for M4xxx or GSxxx pattern
                        for word in desc.split():
                            if word.startswith(("M4", "GS")):
                                model = word
                                break
                    
                    # Extract version if present
                    parts = desc.split(",")
                    if len(parts) >= 2:
                        version = parts[1].strip()
                        if version.isdigit() and len(version) == 6:
                            os_version = f"{version[0:2]}.{version[2]}.{version[3]}.{version[4:6]}"
                        else:
                            os_version = version
                        
            elif "System Name" in line:
                hostname = self._clean_output_line(line)
                
            elif "System Up Time" in line:
                try:
                    uptime_str = self._clean_output_line(line)
                    if uptime_str:
                        parts = uptime_str.replace(",", "").split()
                        days = int(parts[parts.index("days")-1]) if "days" in parts else 0
                        hours = int(parts[parts.index("hrs")-1]) if "hrs" in parts else 0
                        mins = int(parts[parts.index("mins")-1]) if "mins" in parts else 0
                        secs = int(parts[parts.index("secs")-1]) if "secs" in parts else 0
                        uptime = ((days * 24 + hours) * 60 + mins) * 60 + secs
                except (ValueError, IndexError):
                    uptime = 0
                    
            elif "Serial Number" in line:
                serial = self._clean_output_line(line)
                if serial:
                    serial_number = serial.split()[0]
                    
        # If serial number not found in sysinfo, try show version
        if not serial_number:
            version_output = self._send_command("show version")
            for line in version_output.splitlines():
                line = line.strip()
                if "Serial Number" in line:
                    serial = self._clean_output_line(line)
                    if serial:
                        serial_number = serial.split()[0]
                        break

        # Get interface list from status command
        output = self._send_command("show interfaces status all")
        header_seen = False
        
        for line in output.splitlines():
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Mark when we see the header separator
            if "-" * 5 in line:
                header_seen = True
                continue
                
            # Skip lines until we've seen the header separator
            if not header_seen:
                continue
                
            # Split line into fields and get interface name
            fields = line.split()
            if fields and len(fields) >= 1:
                interface = fields[0]
                # Only add if it's a valid interface name (e.g., "1/0/1")
                if interface and "/" in interface and not interface.startswith(("lag", "vlan", "(")):
                    interface_list.append(interface)

        # Sort interfaces naturally
        interface_list.sort(key=lambda x: [int(n) for n in x.split('/') if n.isdigit()])

        # Build facts dictionary
        facts = {
            "uptime": uptime,  # Now returning integer seconds
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
        if not self._is_supported_command(output):
            return {}
            
        interfaces_ip = parser.parse_interfaces_ip(output)
        
        # Get IPv6 addresses
        output = self._send_command("show ipv6 interface brief")
        if self._is_supported_command(output):
            ipv6_interfaces = parser.parse_ipv6_interfaces(output)
            
            # Merge IPv6 addresses into result
            for interface, data in ipv6_interfaces.items():
                if interface not in interfaces_ip:
                    interfaces_ip[interface] = {"ipv4": {}, "ipv6": {}}
                interfaces_ip[interface]["ipv6"].update(data["ipv6"])
        
        return interfaces_ip

    def get_mac_address_table(self) -> List[Dict[str, Any]]:
        """Return the MAC address table."""
        mac_entries = []
        
        # Get MAC address table
        output = self._send_command("show mac-addr-table")
        
        # Skip header lines
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        data_lines = False
        
        for line in lines:
            # Skip until we find the separator line
            if '-' * 5 in line:
                data_lines = True
                continue
                
            if not data_lines:
                continue
                
            # Split line into fields
            fields = line.split()
            if len(fields) < 4:  # Need VLAN, MAC, Port, Type
                continue
                
            try:
                vlan_id = int(fields[0])
                mac_addr = fields[1]
                interface = fields[2]
                entry_type = fields[3].lower()
                
                mac_entries.append({
                    'mac': mac_addr,
                    'interface': interface,
                    'vlan': vlan_id,
                    'static': entry_type == 'static',
                    'active': True,
                    'moves': 0,
                    'last_move': 0.0
                })
            except (ValueError, IndexError):
                continue
        
        return mac_entries

    def get_lldp_neighbors(self) -> Dict[str, List[Dict[str, str]]]:
        """Get LLDP neighbors."""
        neighbors = {}
        
        # Get LLDP neighbors
        output = self._send_command("show lldp remote-device all")
        
        # Skip header lines
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        data_lines = False
        
        for line in lines:
            if "Remote Device" in line or "-" * 5 in line:
                data_lines = True
                continue
                
            if not data_lines:
                continue
                
            # Split line into fields
            fields = line.split("|")
            if len(fields) < 4:  # Need local port, remote ID, remote port, system name
                continue
                
            local_port = fields[0].strip()
            if not local_port or local_port.startswith(('lag', 'vlan')):
                continue
                
            remote_port = fields[2].strip() if len(fields) > 2 else ""
            remote_name = fields[3].strip() if len(fields) > 3 else ""
            
            neighbors[local_port] = [{
                "hostname": remote_name,
                "port": remote_port
            }]
        
        return neighbors

    def is_alive(self) -> Dict[str, bool]:
        """Return connection status."""
        return {
            "is_alive": self.device is not None
        }

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

        # Try port 1234 first (M4500 series)
        try:
            self.device = ConnectHandler(
                **device_args,
                port=1234
            )
            self._enable_mode()
            return
        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            # If connection fails, try standard port 22
            try:
                self.device = ConnectHandler(
                    **device_args,
                    port=22
                )
                self._enable_mode()
            except (NetMikoTimeoutException, NetMikoAuthenticationException) as e2:
                raise ConnectionException(f"Failed to connect on both ports 1234 and 22: {str(e2)}")

    def _enable_mode(self):
        """Enter privileged mode on supported devices."""
        try:
            self.device.enable()
        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            raise ConnectionException(str(e))

    def close(self) -> None:
        """Close the connection to the device."""
        self.device.disconnect()

    def get_environment(self) -> Dict[str, Dict]:
        """Get environment information from device.
        
        Returns:
            dict: Environment information including fans, temperature, power, CPU, and memory.
            
            Example::
            
                {
                    "fans": {
                        "fan1": {
                            "status": true
                        }
                    },
                    "temperature": {
                        "sensor1": {
                            "temperature": 43.0,
                            "is_alert": false,
                            "is_critical": false
                        }
                    },
                    "power": {
                        "PSU1": {
                            "status": true,
                            "capacity": -1.0,
                            "output": -1.0
                        }
                    },
                    "cpu": {
                        0: {
                            "%usage": 5.0
                        }
                    },
                    "memory": {
                        "available_ram": -1,
                        "used_ram": -1,
                        "free_ram": -1
                    }
                }
        """
        environment = {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {}
        }

        # Try unified environment command first (M4350)
        command = "show environment"
        output = self._send_command(command)
        
        if not "Command not found" in output and not "Invalid input" in output:
            # Parse temperature sensors
            in_temp_section = False
            for line in output.splitlines():
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Check for temperature section
                if "Temperature Sensors:" in line:
                    in_temp_section = True
                    continue
                # Check for fan section
                elif "Fans:" in line:
                    in_temp_section = False
                    continue
                    
                if in_temp_section and line and not "Unit" in line and not "----" in line:
                    # Parse temperature sensor line
                    fields = line.split()
                    if len(fields) >= 4:
                        try:
                            sensor_name = fields[2].lower()
                            temp = float(fields[3])
                            state = fields[4].lower()
                            environment["temperature"][sensor_name] = {
                                "temperature": temp,
                                "is_alert": state != "normal",
                                "is_critical": state == "critical"
                            }
                        except (ValueError, IndexError):
                            continue

            # Parse fans
            in_fan_section = False
            for line in output.splitlines():
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Check for fan section
                if "Fans:" in line:
                    in_fan_section = True
                    continue
                # Check for power section
                elif "Power Modules:" in line:
                    in_fan_section = False
                    continue
                    
                if in_fan_section and line and not "Unit Fan" in line and not "----" in line:
                    # Parse fan line
                    fields = line.split()
                    if len(fields) >= 7:
                        try:
                            fan_name = fields[2].lower()
                            status = fields[6].lower()
                            # Consider fan operational unless explicitly marked as failed
                            environment["fans"][fan_name] = {
                                "status": status != "failed"
                            }
                        except (ValueError, IndexError):
                            continue

            # Parse power supplies
            in_power_section = False
            for line in output.splitlines():
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Check for power section
                if "Power Modules:" in line:
                    in_power_section = True
                    continue
                # Check for end of section
                elif line == "":
                    in_power_section = False
                    continue
                    
                if in_power_section and line and not "Unit" in line and not "----" in line:
                    # Parse power supply line
                    fields = line.split()
                    if len(fields) >= 5:
                        try:
                            psu_num = fields[1]
                            status = fields[4].lower()
                            environment["power"][f"PSU{psu_num}"] = {
                                "status": status == "operational",
                                "capacity": -1.0,  # Not available
                                "output": -1.0     # Not available
                            }
                        except (ValueError, IndexError):
                            continue

        # Get CPU utilization and memory stats (common to both models)
        command = "show process cpu"
        output = self._send_command(command)
        
        if not "Command not found" in output and not "Invalid input" in output:
            # Log the raw output for debugging
            self.log.debug(f"CPU/Memory command output:\n{output}")
            
            # Parse memory information
            in_memory_section = False
            free_kb = None
            alloc_kb = None
            
            for line in output.splitlines():
                # Memory section starts with "Memory Utilization Report"
                if "Memory Utilization Report" in line:
                    in_memory_section = True
                    continue
                # Memory section ends when we hit CPU Utilization
                elif "CPU Utilization:" in line:
                    in_memory_section = False
                    continue
                
                if in_memory_section and line:
                    self.log.debug(f"Processing memory line: {line}")
                    fields = line.split()
                    if len(fields) >= 2:
                        try:
                            if "free" in fields[0].lower():
                                free_kb = int(fields[1])
                                self.log.debug(f"Found free memory: {free_kb} KB")
                            elif "alloc" in fields[0].lower():
                                alloc_kb = int(fields[1])
                                self.log.debug(f"Found allocated memory: {alloc_kb} KB")
                        except (ValueError, IndexError):
                            pass

            # Set memory values if we found them
            if free_kb is not None and alloc_kb is not None:
                total_kb = free_kb + alloc_kb
                environment["memory"] = {
                    "available_ram": total_kb * 1024,  # Convert to bytes
                    "used_ram": alloc_kb * 1024,      # Convert to bytes
                    "free_ram": free_kb * 1024        # Convert to bytes
                }
                self.log.debug(f"Set memory values - total: {total_kb}KB, used: {alloc_kb}KB, free: {free_kb}KB")
            else:
                self.log.debug(f"Failed to find both memory values - free: {free_kb}, alloc: {alloc_kb}")
                environment["memory"] = {
                    "available_ram": -1,
                    "used_ram": -1,
                    "free_ram": -1
                }

            # Parse CPU information
            for line in output.splitlines():
                # M4350 format: "CPU Utilization: 5%"
                if "CPU Utilization:" in line and "%" in line:
                    try:
                        cpu_util = float(line.split(':')[1].strip().rstrip('%'))
                        environment["cpu"][0] = {
                            "%usage": cpu_util
                        }
                        break
                    except (ValueError, IndexError):
                        environment["cpu"][0] = {
                            "%usage": 0.0
                        }
                # M4250 format: "Total CPU Utilization           13.03%   17.95%   21.11%"
                elif "Total CPU Utilization" in line and "%" in line:
                    try:
                        # Use 5 seconds utilization
                        fields = line.split()
                        cpu_util = float(fields[-3].rstrip('%'))
                        environment["cpu"][0] = {
                            "%usage": cpu_util
                        }
                        break
                    except (ValueError, IndexError):
                        environment["cpu"][0] = {
                            "%usage": 0.0
                        }

        return environment

    def _disable_paging(self):
        """Disable paging on the device."""
        self._send_command("no pager")