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
                try:
                    uptime_str = line.split(":", 1)[1].strip()
                    parts = uptime_str.replace(",", "").split()
                    days = int(parts[0]) if "days" in parts else 0
                    hours = int(parts[parts.index("hrs")-1]) if "hrs" in parts else 0
                    mins = int(parts[parts.index("mins")-1]) if "mins" in parts else 0
                    secs = int(parts[parts.index("secs")-1]) if "secs" in parts else 0
                    uptime_secs = ((days * 24 + hours) * 60 + mins) * 60 + secs
                    uptime = self._format_uptime(uptime_secs)
                except (ValueError, IndexError):
                    uptime = "0 secs"
                    
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

    def get_mac_address_table(self) -> list:
        """Return LLDP neighbors details."""
        # Try GS108Tv3 command first
        command = "show mac address-table"
        output = self._send_command(command)
        
        if "MAC Address" in output and "Type" in output:  # GS108Tv3 format
            return parse_gs108tv3_mac_table(output)
            
        # Try M4250/M4350 format
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
        """Get LLDP neighbors.
        
        Example M4350:
            >>> {
            ...     "1/0/2": [
            ...         {
            ...             "hostname": "SWITCH-1",  # System name if available
            ...             "port": "0/10"
            ...         }
            ...     ]
            ... }
            
        Example M4250:
            >>> {
            ...     "0/3": [
            ...         {
            ...             "hostname": "AP-1",  # System name if available
            ...             "port": "00:11:22:33:44:55"
            ...         }
            ...     ],
            ...     "0/10": [
            ...         {
            ...             "hostname": "SWITCH-2",
            ...             "port": "1/0/2"
            ...         }
            ...     ]
            ... }
        """
        neighbors = {}
        
        # Try M4250/M4350 command first
        try:
            # Disable paging first
            self._send_command("no pager")
            
            command = "show lldp remote-device all"
            self.log.debug(f"Sending command: {command}")
            output = self._send_command(command)
            self.log.debug(f"Initial LLDP command output:\n{output}")
            
            if not output:
                self.log.debug("No response from device for initial command")
            elif "An invalid interface has been used for this command" in output:
                self.log.debug("Initial command not supported, trying alternative")
                # Switch to M4500 command if 'all' not supported
                command = "show lldp remote-device"
                self.log.debug(f"Sending alternative command: {command}")
                output = self._send_command(command)
                self.log.debug(f"Alternative LLDP command output:\n{output}")
                
                if not output:
                    self.log.debug("No response from device for alternative command")
                    return {}
            
            if not output:
                self.log.debug("No LLDP output received")
                return {}
                
        except Exception as e:
            self.log.debug(f"Error with first LLDP command, trying alternative: {str(e)}")
            try:
                # Disable paging first
                self._send_command("no pager")
                
                command = "show lldp remote-device"
                self.log.debug(f"Sending alternative command after error: {command}")
                output = self._send_command(command)
                self.log.debug(f"Alternative LLDP command output after error:\n{output}")
                
                if not output:
                    self.log.debug("No response from device for alternative command after error")
                    return {}
                    
            except Exception as e:
                self.log.error(f"Failed to get LLDP neighbors: {str(e)}")
                return {}
            
        self.log.debug(f"Final LLDP output to parse:\n{output}")
        
        # Parse output to get interfaces with neighbors
        lines = output.splitlines()
        interfaces = []
        
        # Skip header lines until we find the interface listing
        header_found = False
        data_section = False
        
        self.log.debug("Starting interface discovery from LLDP output...")
        
        for line in lines:
            line = line.strip()
            self.log.debug(f"Processing line: '{line}'")
            
            # Handle both M4500 and M4250/M4350 header formats
            if not header_found:
                if any(header in line for header in [
                    "LLDP Remote Device Summary",
                    "Local Interface",
                    "Interface  RemID"
                ]):
                    self.log.debug(f"Found header line: '{line}'")
                    header_found = True
                    continue
                else:
                    self.log.debug("Not a header line, skipping")
                    continue
                
            if header_found and "-----" in line:  # Found separator after header
                self.log.debug("Found separator line, starting data section")
                data_section = True
                continue
                
            if not data_section:
                self.log.debug("Not in data section yet")
                continue
                
            if not line:
                self.log.debug("Skipping empty line")
                continue
                
            # Split line and get interface if it has a RemID
            parts = line.split()
            self.log.debug(f"Line parts: {parts}")
            
            if len(parts) >= 1:
                potential_interface = parts[0].strip()
                self.log.debug(f"Checking potential interface: '{potential_interface}'")
                
                if self._is_valid_interface(potential_interface):
                    self.log.debug(f"Found valid interface: {potential_interface}")
                    if potential_interface not in interfaces:  # Avoid duplicates
                        self.log.debug(f"Adding new interface: {potential_interface}")
                        interfaces.append(potential_interface)
                    else:
                        self.log.debug(f"Interface already found: {potential_interface}")
                else:
                    self.log.debug(f"Invalid interface format: {potential_interface}")
            else:
                self.log.debug("Line has no parts")
        
        self.log.debug(f"Found interfaces with neighbors: {interfaces}")
        
        # Get detailed info for each interface with neighbors
        for interface in interfaces:
            # Disable paging first
            self._send_command("no pager")
            
            command = f"show lldp remote-device detail {interface}"
            try:
                output = self._send_command(command)
                if not output:
                    self.log.debug(f"No LLDP detail output for interface {interface}")
                    continue
            except Exception as e:
                self.log.error(f"Failed to get LLDP detail for interface {interface}: {str(e)}")
                continue
                
            self.log.debug(f"\nLLDP detail for {interface}:\n{output}")
            
            # Parse detailed output
            neighbor = {
                "parent_interface": interface,
                "remote_chassis_id": "",
                "remote_port": "",
                "remote_port_description": "",
                "remote_system_name": "",
                "remote_system_description": "",
                "remote_system_capab": [],
                "remote_system_enable_capab": [],
                "remote_management_address": ""
            }
            
            lines = output.splitlines()
            current_section = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                self.log.debug(f"Processing detail line: {line}")
                
                # Skip header lines
                if any(header in line for header in [
                    "LLDP Remote Device Detail",
                    "Local Interface:",
                    "Remote Identifier:",
                    "Chassis ID Subtype:",
                    "Port ID Subtype:"
                ]):
                    continue
                    
                # Handle main fields
                if "Chassis ID:" in line:
                    neighbor["remote_chassis_id"] = line.split(":", 1)[1].strip()
                elif "Port ID:" in line:
                    neighbor["remote_port"] = line.split(":", 1)[1].strip()
                elif "System Name:" in line:
                    neighbor["remote_system_name"] = line.split(":", 1)[1].strip()
                elif "System Description:" in line:
                    neighbor["remote_system_description"] = line.split(":", 1)[1].strip()
                elif "Port Description:" in line:
                    neighbor["remote_port_description"] = line.split(":", 1)[1].strip()
                elif "System Capabilities Supported:" in line:
                    caps = line.split(":", 1)[1].strip()
                    neighbor["remote_system_capab"] = self._parse_capabilities(caps)
                elif "System Capabilities Enabled:" in line:
                    caps = line.split(":", 1)[1].strip()
                    neighbor["remote_system_enable_capab"] = self._parse_capabilities(caps)
                elif "Management Address:" in line:
                    current_section = "management"
                elif current_section == "management" and "Type:" in line:
                    continue  # Skip the type line
                elif current_section == "management" and "Address:" in line:
                    neighbor["remote_management_address"] = line.split(":", 1)[1].strip()
                    current_section = None
                elif "Time to Live:" in line:
                    current_section = None
                    
            # Only add if we have valid data
            if any(val for val in neighbor.values() if val and val != interface):
                self.log.debug(f"Parsed neighbor for {interface}: {neighbor}")
                neighbors[interface] = [neighbor]
            else:
                self.log.debug(f"No valid neighbor data found for {interface}")
        
        self.log.debug(f"Final neighbors dict: {neighbors}")
        return neighbors

    def get_lldp_neighbors_detail(self, interface=""):
        """Get LLDP neighbor information detail.

        Args:
            interface (str, optional): Interface to get neighbor information for. Defaults to "".

        Returns:
            dict: Detailed LLDP neighbor information.
                {interface: [{
                    'parent_interface'          : u'ethernet2',
                    'remote_port'              : u'Gi1/0/22',
                    'remote_port_description'  : u'',
                    'remote_chassis_id'        : u'2c:b0:5d:b9:50:4e',
                    'remote_system_name'       : u'1.1.1.1',
                    'remote_system_description': u'Cisco IOS Software...',
                    'remote_system_capab'      : ['bridge', 'repeater'],
                    'remote_system_enable_capab': ['bridge']
                }], }
        """
        print("DEBUG: Starting get_lldp_neighbors_detail")
        self.log.debug("Getting LLDP neighbor details...")
        
        # Initialize neighbors dictionary
        neighbors = {}
        
        # Disable paging first
        print("DEBUG: Sending no pager command")
        output = self._send_command("no pager")
        print(f"DEBUG: no pager output: {output}")
        
        # Try M4250/M4350 command first
        try:
            command = "show lldp remote-device all"
            print(f"DEBUG: Sending command: {command}")
            output = self._send_command(command)
            print(f"DEBUG: Initial LLDP command output:\n{output}")
            self.log.debug(f"Initial LLDP command output:\n{output}")
            
            if not output:
                print("DEBUG: No response from device for initial command")
                self.log.debug("No response from device for initial command")
            elif "An invalid interface has been used for this command" in output:
                print("DEBUG: Initial command not supported, trying alternative")
                self.log.debug("Initial command not supported, trying alternative")
                # Switch to M4500 command if 'all' not supported
                command = "show lldp remote-device"
                print(f"DEBUG: Sending alternative command: {command}")
                output = self._send_command(command)
                print(f"DEBUG: Alternative LLDP command output:\n{output}")
                self.log.debug(f"Alternative LLDP command output:\n{output}")
                
                if not output:
                    print("DEBUG: No response from device for alternative command")
                    self.log.debug("No response from device for alternative command")
                    return {}
            
            if not output:
                print("DEBUG: No LLDP output received")
                self.log.debug("No LLDP output received")
                return {}
                
        except Exception as e:
            print(f"DEBUG: Error with first LLDP command: {str(e)}")
            self.log.debug(f"Error with first LLDP command, trying alternative: {str(e)}")
            try:
                # Disable paging first
                print("DEBUG: Sending no pager command after error")
                self._send_command("no pager")
                
                command = "show lldp remote-device"
                print(f"DEBUG: Sending alternative command after error: {command}")
                output = self._send_command(command)
                print(f"DEBUG: Alternative LLDP command output after error:\n{output}")
                self.log.debug(f"Alternative LLDP command output after error:\n{output}")
                
                if not output:
                    print("DEBUG: No response from device for alternative command after error")
                    self.log.debug("No response from device for alternative command after error")
                    return {}
                    
            except Exception as e:
                print(f"DEBUG: Failed to get LLDP neighbors: {str(e)}")
                self.log.error(f"Failed to get LLDP neighbors: {str(e)}")
                return {}
            
        print(f"DEBUG: Final LLDP output to parse:\n{output}")
        self.log.debug(f"Final LLDP output to parse:\n{output}")
        
        # Parse output to get interfaces with neighbors
        lines = output.splitlines()
        interfaces = []
        
        # Skip header lines until we find the interface listing
        header_found = False
        data_section = False
        
        self.log.debug("Starting interface discovery from LLDP output...")
        
        for line in lines:
            line = line.strip()
            self.log.debug(f"Processing line: '{line}'")
            
            # Handle both M4500 and M4250/M4350 header formats
            if not header_found:
                if any(header in line for header in [
                    "LLDP Remote Device Summary",
                    "Local Interface",
                    "Interface  RemID"
                ]):
                    self.log.debug(f"Found header line: '{line}'")
                    header_found = True
                    continue
                else:
                    self.log.debug("Not a header line, skipping")
                    continue
                
            if header_found and "-----" in line:  # Found separator after header
                self.log.debug("Found separator line, starting data section")
                data_section = True
                continue
                
            if not data_section:
                self.log.debug("Not in data section yet")
                continue
                
            if not line:
                self.log.debug("Skipping empty line")
                continue
                
            # Split line and get interface if it has a RemID
            parts = line.split()
            self.log.debug(f"Line parts: {parts}")
            
            if len(parts) >= 1:
                potential_interface = parts[0].strip()
                self.log.debug(f"Checking potential interface: '{potential_interface}'")
                
                if self._is_valid_interface(potential_interface):
                    self.log.debug(f"Found valid interface: {potential_interface}")
                    if potential_interface not in interfaces:  # Avoid duplicates
                        self.log.debug(f"Adding new interface: {potential_interface}")
                        interfaces.append(potential_interface)
                    else:
                        self.log.debug(f"Interface already found: {potential_interface}")
                else:
                    self.log.debug(f"Invalid interface format: {potential_interface}")
            else:
                self.log.debug("Line has no parts")
        
        self.log.debug(f"Found interfaces with neighbors: {interfaces}")
        
        # Get detailed info for each interface with neighbors
        for interface in interfaces:
            # Disable paging first
            self._send_command("no pager")
            
            command = f"show lldp remote-device detail {interface}"
            try:
                output = self._send_command(command)
                if not output:
                    self.log.debug(f"No LLDP detail output for interface {interface}")
                    continue
            except Exception as e:
                self.log.error(f"Failed to get LLDP detail for interface {interface}: {str(e)}")
                continue
                
            self.log.debug(f"\nLLDP detail for {interface}:\n{output}")
            
            # Parse detailed output
            neighbor = {
                "parent_interface": interface,
                "remote_chassis_id": "",
                "remote_port": "",
                "remote_port_description": "",
                "remote_system_name": "",
                "remote_system_description": "",
                "remote_system_capab": [],
                "remote_system_enable_capab": [],
                "remote_management_address": ""
            }
            
            lines = output.splitlines()
            current_section = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                self.log.debug(f"Processing detail line: {line}")
                
                # Skip header lines
                if any(header in line for header in [
                    "LLDP Remote Device Detail",
                    "Local Interface:",
                    "Remote Identifier:",
                    "Chassis ID Subtype:",
                    "Port ID Subtype:"
                ]):
                    continue
                    
                # Handle main fields
                if "Chassis ID:" in line:
                    neighbor["remote_chassis_id"] = line.split(":", 1)[1].strip()
                elif "Port ID:" in line:
                    neighbor["remote_port"] = line.split(":", 1)[1].strip()
                elif "System Name:" in line:
                    neighbor["remote_system_name"] = line.split(":", 1)[1].strip()
                elif "System Description:" in line:
                    neighbor["remote_system_description"] = line.split(":", 1)[1].strip()
                elif "Port Description:" in line:
                    neighbor["remote_port_description"] = line.split(":", 1)[1].strip()
                elif "System Capabilities Supported:" in line:
                    caps = line.split(":", 1)[1].strip()
                    neighbor["remote_system_capab"] = self._parse_capabilities(caps)
                elif "System Capabilities Enabled:" in line:
                    caps = line.split(":", 1)[1].strip()
                    neighbor["remote_system_enable_capab"] = self._parse_capabilities(caps)
                elif "Management Address:" in line:
                    current_section = "management"
                elif current_section == "management" and "Type:" in line:
                    continue  # Skip the type line
                elif current_section == "management" and "Address:" in line:
                    neighbor["remote_management_address"] = line.split(":", 1)[1].strip()
                    current_section = None
                elif "Time to Live:" in line:
                    current_section = None
                    
            # Only add if we have valid data
            if any(val for val in neighbor.values() if val and val != interface):
                self.log.debug(f"Parsed neighbor for {interface}: {neighbor}")
                neighbors[interface] = [neighbor]
            else:
                self.log.debug(f"No valid neighbor data found for {interface}")
        
        self.log.debug(f"Final neighbors dict: {neighbors}")
        return neighbors

    def _is_valid_interface(self, interface: str) -> bool:
        """Check if interface name is valid.
        
        Valid formats:
        - 0/1
        - 1/0/1
        - 2/0/1
        etc.
        """
        return bool(re.match(r'^\d+/\d+(/\d+)?$', interface))

    def _normalize_capability(self, capability: str) -> str:
        """Normalize capability name.
        
        Handles special cases:
        - "access point" -> "access-point"
        - Removes extra spaces
        - Converts to lowercase
        """
        capability = capability.lower().strip()
        if "access point" in capability:
            capability = capability.replace("access point", "access-point")
        return capability

    def _parse_capabilities(self, caps_str: str) -> List[str]:
        """Parse capabilities string into list.
        
        Args:
            caps_str: Comma-separated list of capabilities
            
        Returns:
            List of normalized capability strings
        """
        if not caps_str:
            return []
        return [self._normalize_capability(cap) for cap in caps_str.split(",")]

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
                line = line.strip()
                
                if "Temperature Sensors:" in line:
                    in_temp_section = True
                    continue
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
                line = line.strip()
                
                if "Fans:" in line:
                    in_fan_section = True
                    continue
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
                line = line.strip()
                
                if "Power Modules:" in line:
                    in_power_section = True
                    continue
                elif line == "":  # End of section
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