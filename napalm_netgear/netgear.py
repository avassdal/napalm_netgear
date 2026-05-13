"""NAPALM driver for Netgear switches."""

from typing import Dict, List, Optional, Any, Tuple
import difflib
import re

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException, CommandErrorException

from napalm_netgear.parser import (
    parse_interface_status,
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
        self.platform = "netgear"
        self._platform_type = "unknown"  # "m_series" or "gs_series"
        self._gs_port_count = 0
        self._gs_tech_support = None  # Cached show tech-support output
        self.config = ""
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
            # Handle --More-- pagination (GS series doesn't support 'no pager')
            max_pages = 100
            pages = 0
            while '--More--' in output and pages < max_pages:
                output = output.replace('--More--', '')
                more = self.device.send_command_timing(
                    ' ', strip_prompt=False, strip_command=False,
                    read_timeout=read_timeout, cmd_verify=False
                )
                output += more
                pages += 1
            # Clean ANSI escape sequences from output
            output = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output)
            output = output.replace('\r', '')
            return output
        except Exception as e:
            raise CommandErrorException(f"Failed to send command '{command}': {str(e)}")

    def _is_supported_command(self, output: str) -> bool:
        """Check if command output indicates it's supported."""
        return not any(error in output for error in [
            "% Invalid input detected",
            "An invalid interface has been used",
            "Invalid command",
            "Unknown command",
            "Incomplete command"
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
        if self._platform_type == "gs_series":
            return self._get_interfaces_gs()

        interfaces = {}

        # Get interface status
        output = self._send_command("show interfaces status all")

        if self._is_supported_command(output):
            # Use position-based parser for fixed-width column output
            parsed = parse_interface_status(output)

            for entry in parsed:
                interface = entry.get("port", "")
                if not interface or interface.startswith(("lag", "vlan", "(")):
                    continue

                link_state = entry.get("state", "").lower()
                speed_str = entry.get("speed", "")

                interfaces[interface] = {
                    "is_up": link_state == "up",
                    "is_enabled": True,
                    "description": entry.get("name", ""),
                    "mac_address": "",
                    "last_flapped": -1.0,
                    "mtu": 1500,
                    "speed": self._parse_speed(speed_str),
                }
        else:
            # Fallback: M4500 uses 'show interface status' (no 's' on interface, no 'all')
            status_output = self._send_command("show interface status")
            for line in status_output.splitlines():
                fields = line.split()
                if not fields or "/" not in fields[0]:
                    continue
                iface = fields[0]
                if iface.startswith(("lag", "vlan")):
                    continue
                # Format: Intf Type AdminMode PhyMode PhyStat LinkStat ...
                link_stat = ""
                admin_mode = ""
                phy_stat = ""
                if len(fields) >= 6:
                    # Fields shift depending on whether Type column has value
                    # Find "Up" or "Down" in the fields for link state
                    for i, f in enumerate(fields[1:], 1):
                        if f in ("Up", "Down"):
                            link_stat = f
                            break
                    admin_mode = fields[2] if len(fields) > 2 else ""
                    # Speed is the PhyStat field (e.g. "25GF", "10GF")
                    phy_stat = fields[4] if len(fields) > 4 else ""

                interfaces[iface] = {
                    "is_up": link_stat == "Up",
                    "is_enabled": admin_mode == "Enable",
                    "description": "",
                    "mac_address": "",
                    "last_flapped": -1.0,
                    "mtu": 1500,
                    "speed": self._parse_speed(phy_stat),
                }

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
        if self._platform_type == "gs_series":
            return self._get_interfaces_counters_gs()

        counters = {}
        
        # Get interface counters
        output = self._send_command("show interface counters")
        if not self._is_supported_command(output):
            return {}
            
        # Parse counter values
        try:
            # Skip empty lines and prompts
            lines = [line.strip() for line in output.splitlines() 
                    if line.strip() and not line.startswith("(")]
            
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
        except (IndexError, ValueError):
            pass
        
        return "", ""

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

        # GS-series: use show info + show version + show running-config
        if self._platform_type == "gs_series":
            return self._get_facts_gs()

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
                        # Extract model from first part
                        model = parts[0].split()[0]  # First word of first part
                        version = parts[1].strip()  # Second part is version
                        
                        # Add dots back to version (format: XX.X.X.XX)
                        if len(version) == 6:  # 130426 -> 13.0.4.26
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

        # Get interface list from status command with header filtering
        output = self._send_command('show interfaces status all | exclude "Port|Name|Link|Type|Speed|Duplex|Mode|Status|VLAN"')
        if self._is_supported_command(output):
            for line in output.splitlines():
                line = line.strip()
                if not line or "-" * 5 in line:
                    continue
                fields = line.split()
                if not fields:
                    continue
                interface = fields[0]
                if interface and "/" in interface and not interface.startswith(("lag", "vlan")):
                    interface_list.append(interface)
        else:
            # Fallback: M4500 uses 'show interface status' (no 's' on interface, no 'all')
            status_output = self._send_command("show interface status")
            for line in status_output.splitlines():
                fields = line.split()
                if not fields or "/" not in fields[0]:
                    continue
                iface = fields[0]
                if not iface.startswith(("lag", "vlan")):
                    interface_list.append(iface)

        # Sort interfaces naturally by their numeric components
        interface_list.sort(key=lambda x: [int(n) for n in x.split('/') if n.isdigit()])

        # Build facts dictionary
        facts = {
            "uptime": float(uptime),
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
        if self._platform_type == "gs_series":
            return self._get_interfaces_ip_gs()

        # Get IPv4 addresses
        output = self._send_command("show ip interface brief")
        if not self._is_supported_command(output):
            return {}
            
        interfaces_ip = parse_interfaces_ip(output)
        
        # Get IPv6 addresses
        output = self._send_command("show ipv6 interface brief")
        if self._is_supported_command(output):
            ipv6_interfaces = parse_ipv6_interfaces(output)
            
            # Merge IPv6 addresses into result
            for interface, data in ipv6_interfaces.items():
                if interface not in interfaces_ip:
                    interfaces_ip[interface] = {"ipv4": {}, "ipv6": {}}
                interfaces_ip[interface]["ipv6"].update(data["ipv6"])
        
        return interfaces_ip

    def get_mac_address_table(self) -> List[Dict[str, Any]]:
        """Return the MAC address table.

        GS-series uses pipe-delimited format from 'show mac address-table'.

        Real device format (M4250/M4350/M4500):
            VLAN ID  MAC Address         Interface              IfIndex  Status
            -------  ------------------  ---------------------  -------  ------------
            1        0C:C4:7A:73:68:1A   0/10                   10       Learned
            50       54:07:7D:0C:39:DD   vlan 50                420      Management
            1        54:07:7D:0C:46:26   ch1                    354      MLAG Static
        """
        if self._platform_type == "gs_series":
            return self._get_mac_address_table_gs()

        mac_entries = []

        # Get MAC address table
        output = self._send_command("show mac-addr-table")

        lines = output.splitlines()

        # Find separator line to determine column positions
        separator_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('-------'):
                separator_idx = i
                break

        if separator_idx < 0:
            return []

        # Find column boundaries from separator dashes
        sep_line = lines[separator_idx]
        cols = []
        in_dash = False
        start = 0
        for i, ch in enumerate(sep_line):
            if ch == '-' and not in_dash:
                start = i
                in_dash = True
            elif ch != '-' and in_dash:
                cols.append((start, i))
                in_dash = False
        if in_dash:
            cols.append((start, len(sep_line)))

        if len(cols) < 5:
            return []

        # Parse data lines using column positions
        for line in lines[separator_idx + 1:]:
            if not line.strip() or '--More--' in line or line.strip().startswith('('):
                continue

            try:
                vlan_str = line[cols[0][0]:cols[0][1]].strip()
                mac_addr = line[cols[1][0]:cols[1][1]].strip()
                interface = line[cols[2][0]:cols[2][1]].strip()
                # cols[3] is IfIndex, skip it
                status = line[cols[4][0]:].strip()

                if not vlan_str or not mac_addr:
                    continue

                vlan_id = int(vlan_str)
                is_static = 'static' in status.lower() or 'management' in status.lower()

                mac_entries.append({
                    'mac': mac_addr,
                    'interface': interface,
                    'vlan': vlan_id,
                    'static': is_static,
                    'active': True,
                    'moves': 0,
                    'last_move': 0.0
                })
            except (ValueError, IndexError):
                continue

        return mac_entries

    def _parse_lldp_summary(self, output: str):
        """Parse the fixed-width LLDP summary table.
        
        Returns:
            list of dicts with keys: local_port, chassis_id, port_id, system_name
        """
        results = []
        lines = output.splitlines()
        
        # Find the separator line to determine column positions
        sep_idx = None
        for i, line in enumerate(lines):
            if '-' * 5 in line:
                sep_idx = i
                break
        
        if sep_idx is None or sep_idx < 1:
            return results
        
        # Column headers: Interface, RemID, Chassis ID, Port ID, System Name, OUI, OUI Subtype
        # Find start positions by looking at the separator dashes
        sep_line = lines[sep_idx]
        col_starts = []
        in_dash = False
        for j, ch in enumerate(sep_line):
            if ch == '-' and not in_dash:
                col_starts.append(j)
                in_dash = True
            elif ch != '-':
                in_dash = False
        
        # We expect at least 5 columns: Interface, RemID, Chassis ID, Port ID, System Name
        if len(col_starts) < 5:
            return results
        
        # Parse data lines after separator
        for line in lines[sep_idx + 1:]:
            if not line.strip():
                continue
                
            # Extract local port from first column
            local_port = line[col_starts[0]:col_starts[1]].strip() if len(col_starts) > 1 else line[col_starts[0]:].strip()
            if not local_port:
                continue  # Continuation line (capabilities etc.)
            if local_port.startswith(('lag', 'vlan', '(')):
                continue
            
            # Extract fields using column positions
            chassis_id = line[col_starts[2]:col_starts[3]].strip() if len(col_starts) > 3 else ""
            port_id = line[col_starts[3]:col_starts[4]].strip() if len(col_starts) > 4 else ""
            # System name goes from col 4 to col 5 (or end if fewer columns)
            if len(col_starts) > 5:
                system_name = line[col_starts[4]:col_starts[5]].strip()
            else:
                system_name = line[col_starts[4]:].strip()
            
            # Skip lines that only have a port but no neighbor data
            if not chassis_id and not port_id:
                continue
            
            results.append({
                "local_port": local_port,
                "chassis_id": chassis_id,
                "port_id": port_id,
                "system_name": system_name,
            })
        
        return results

    def get_lldp_neighbors(self) -> Dict[str, List[Dict[str, str]]]:
        """Get LLDP neighbors.

        Returns:
            dict: Interfaces and their LLDP neighbors:
                {
                    "local_port": [{
                        "hostname": "string",
                        "port": "string",
                    }],
                }
        """
        if self._platform_type == "gs_series":
            return self._get_lldp_neighbors_gs()

        neighbors = {}
        
        # Get LLDP neighbors (M4500 uses 'show lldp remote-device' without 'all')
        output = self._send_command("show lldp remote-device all")
        if not self._is_supported_command(output):
            output = self._send_command("show lldp remote-device")
        
        for entry in self._parse_lldp_summary(output):
            local_port = entry["local_port"]
            chassis_id = entry["chassis_id"]
            port_id = entry["port_id"]
            system_name = entry["system_name"]
            
            if local_port not in neighbors:
                neighbors[local_port] = []
            
            neighbors[local_port].append({
                "hostname": system_name or chassis_id,
                "port": port_id if not port_id.startswith("0x") else chassis_id
            })
        
        return neighbors

    def get_lldp_neighbors_detail(self, interface: str = "") -> Dict[str, List[Dict[str, Any]]]:
        """Get detailed information about LLDP neighbors.

        Returns:
            dict: Detailed information about LLDP neighbors keyed by interface:
                {
                    "local_port": [{
                        "parent_interface": "string",
                        "remote_chassis_id": "string",
                        "remote_port": "string",
                        "remote_port_description": "string",
                        "remote_system_name": "string",
                        "remote_system_description": "string",
                        "remote_system_capab": ["string"],
                        "remote_system_enable_capab": ["string"]
                    }]
                }
        """
        # GS-series: no per-port LLDP detail command; build from tech-support LLDP section
        if self._platform_type == "gs_series":
            return self._get_lldp_neighbors_detail_gs()

        neighbors = {}
        
        # Get list of interfaces with neighbors from summary table (1 command)
        # M4500 uses 'show lldp remote-device' without 'all'
        output = self._send_command("show lldp remote-device all")
        if not self._is_supported_command(output):
            output = self._send_command("show lldp remote-device")
        interfaces = list({e["local_port"] for e in self._parse_lldp_summary(output)})
        
        # Fetch detail per interface that has a neighbor
        for interface in interfaces:
            detail_output = self._send_command(f"show lldp remote-device detail {interface}")
            
            neighbor = {
                "parent_interface": interface,
                "remote_chassis_id": "",
                "remote_port": "",
                "remote_port_description": "",
                "remote_system_name": "",
                "remote_system_description": "",
                "remote_system_capab": [],
                "remote_system_enable_capab": []
            }
            
            for line in detail_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                if line.startswith("Chassis ID:"):
                    value = line.split(":", 1)[1].strip()
                    neighbor["remote_chassis_id"] = value
                elif line.startswith("Port ID:"):
                    value = line.split(":", 1)[1].strip()
                    neighbor["remote_port"] = value
                elif line.startswith("System Name:"):
                    value = line.split(":", 1)[1].strip()
                    neighbor["remote_system_name"] = value
                elif line.startswith("System Description:"):
                    value = line.split(":", 1)[1].strip()
                    neighbor["remote_system_description"] = value
                elif line.startswith("Port Description:"):
                    value = line.split(":", 1)[1].strip()
                    neighbor["remote_port_description"] = value
                elif line.startswith("System Capabilities Supported:"):
                    value = line.split(":", 1)[1].strip()
                    neighbor["remote_system_capab"] = [cap.strip() for cap in value.split(",") if cap.strip()]
                elif line.startswith("System Capabilities Enabled:"):
                    value = line.split(":", 1)[1].strip()
                    neighbor["remote_system_enable_capab"] = [cap.strip() for cap in value.split(",") if cap.strip()]
            
            # Only add if we have valid data
            if neighbor["remote_chassis_id"] or neighbor["remote_port"]:
                if interface not in neighbors:
                    neighbors[interface] = []
                neighbors[interface].append(neighbor)
        
        return neighbors

    # ---- GS-series getter implementations (powered by show tech-support) ----

    def _get_facts_gs(self) -> Dict[str, Any]:
        """Get facts for GS-series switches from tech-support."""
        uptime = 0
        model = ""
        hostname = ""
        os_version = ""
        serial_number = ""
        interface_list = []

        # Parse System Information section
        sysinfo = self._get_gs_section("System Information")
        for line in sysinfo.splitlines():
            line = line.strip()
            if line.startswith("System Name"):
                hostname = line.split(":", 1)[1].strip()
            elif line.startswith("Board Name"):
                # "GS108Tv3 (BID:1)" -> "GS108Tv3"
                raw = line.split(":", 1)[1].strip()
                model = raw.split("(")[0].strip()
            elif line.startswith("Firmware Version"):
                os_version = line.split(":", 1)[1].strip()
            elif line.startswith("System Up Time"):
                try:
                    uptime_str = line.split(":", 1)[1].strip()
                    parts = uptime_str.replace(",", "").split()
                    days = int(parts[parts.index("days") - 1]) if "days" in parts else 0
                    hours = int(parts[parts.index("hours") - 1]) if "hours" in parts else 0
                    mins = int(parts[parts.index("mins") - 1]) if "mins" in parts else 0
                    secs = int(parts[parts.index("secs") - 1]) if "secs" in parts else 0
                    uptime = ((days * 24 + hours) * 60 + mins) * 60 + secs
                except (ValueError, IndexError):
                    uptime = 0

        # Get serial from Running-config header (has "! Serial Number:")
        running = self._get_gs_section("Running-config")
        for line in running.splitlines():
            line = line.strip()
            if line.startswith("! Serial Number:"):
                serial_number = line.split(":", 1)[1].strip()
            elif line.startswith("interface g"):
                iface = line.split()[1]
                if iface not in interface_list:
                    interface_list.append(iface)

        interface_list.sort(key=lambda x: int(re.sub(r'[^0-9]', '', x) or 0))

        return {
            "uptime": float(uptime),
            "vendor": "Netgear",
            "model": model,
            "hostname": hostname,
            "fqdn": hostname,
            "os_version": os_version,
            "serial_number": serial_number,
            "interface_list": interface_list,
        }

    def _get_interfaces_gs(self) -> Dict[str, Dict[str, Any]]:
        """Get interfaces for GS-series from tech-support STP section."""
        interfaces = {}
        n = self._get_gs_port_count()

        # Use Snapping-Tree section to determine port state (Frw = up, Dsbl = down)
        stp = self._get_gs_section("Snapping-Tree")
        port_states = {}  # port_num -> "up"/"down"
        # Parse "msti 0 port 0 state Frw (Frw)" lines (msti 0 is the base instance)
        for line in stp.splitlines():
            m = re.match(r'msti\s+0\s+port\s+(\d+)\s+state\s+(\w+)', line)
            if m:
                port_num = int(m.group(1))
                state = m.group(2)
                if port_num < n:  # Only physical ports (0-indexed)
                    port_states[port_num] = state in ("Frw",)

        for i in range(n):
            iface = f"g{i + 1}"
            interfaces[iface] = {
                "is_up": port_states.get(i, False),
                "is_enabled": True,
                "description": "",
                "mac_address": "",
                "last_flapped": -1.0,
                "mtu": 1500,
                "speed": 1000.0 if port_states.get(i, False) else 0.0,
            }

        return interfaces

    def _get_interfaces_counters_gs(self) -> dict:
        """Get interface counters for GS-series (one port at a time to avoid pagination)."""
        counters = {}
        n = self._get_gs_port_count()

        for port in range(1, n + 1):
            iface = f"g{port}"
            c = {
                'tx_errors': 0, 'rx_errors': 0,
                'tx_discards': 0, 'rx_discards': 0,
                'tx_octets': 0, 'rx_octets': 0,
                'tx_unicast_packets': 0, 'rx_unicast_packets': 0,
                'tx_multicast_packets': 0, 'rx_multicast_packets': 0,
                'tx_broadcast_packets': 0, 'rx_broadcast_packets': 0,
            }
            output = self._send_command(f"show interfaces GigabitEthernet {port}")

            for line in output.splitlines():
                line = line.strip()

                m = re.match(r'(\d+)\s+packets\s+input,\s*(\d+)\s+bytes', line)
                if m:
                    c['rx_unicast_packets'] = int(m.group(1))
                    c['rx_octets'] = int(m.group(2))
                    continue

                m = re.match(r'Received\s+(\d+)\s+broadcasts\s+\((\d+)\s+multicasts\)', line)
                if m:
                    c['rx_broadcast_packets'] = int(m.group(1))
                    c['rx_multicast_packets'] = int(m.group(2))
                    continue

                m = re.match(r'(\d+)\s+input\s+errors', line)
                if m:
                    c['rx_errors'] = int(m.group(1))
                    continue

                m = re.match(r'(\d+)\s+packets\s+output,\s*(\d+)\s+bytes', line)
                if m:
                    c['tx_unicast_packets'] = int(m.group(1))
                    c['tx_octets'] = int(m.group(2))
                    continue

                m = re.match(r'(\d+)\s+output\s+errors', line)
                if m:
                    c['tx_errors'] = int(m.group(1))
                    continue

            counters[iface] = c

        return counters

    def _get_mac_address_table_gs(self) -> List[Dict[str, Any]]:
        """Get MAC address table from tech-support 'MAC Address Table' section."""
        mac_entries = []
        section = self._get_gs_section("MAC Address Table")

        in_table = False
        for line in section.splitlines():
            stripped = line.strip()
            if stripped.startswith("------+"):
                in_table = True
                continue
            if not in_table or not stripped or "Total number" in stripped:
                continue

            parts = [p.strip() for p in stripped.split("|")]
            if len(parts) < 4:
                continue
            try:
                vlan_id = int(parts[0])
                mac_addr = parts[1]
                # Validate it looks like a MAC address (contains colons + hex)
                if not re.match(r'^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$', mac_addr):
                    continue
                mac_type = parts[2]
                interface = parts[3]
                mac_entries.append({
                    'mac': mac_addr,
                    'interface': interface,
                    'vlan': vlan_id,
                    'static': 'dynamic' not in mac_type.lower(),
                    'active': True,
                    'moves': 0,
                    'last_move': 0.0,
                })
            except (ValueError, IndexError):
                continue

        return mac_entries

    def _get_lldp_neighbors_detail_gs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get LLDP neighbor detail for GS-series from tech-support LLDP section."""
        neighbors = {}
        lldp_section = self._get_gs_section("LLDP")

        in_table = False
        for line in lldp_section.splitlines():
            line = line.strip()
            if re.match(r'^-+\s*\+', line):
                in_table = True
                continue
            if not in_table or not line:
                continue

            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 6:
                continue

            local_port = parts[0]
            device_id = parts[1]
            port_id = parts[2]
            sys_name = parts[3]
            capabilities = parts[4]

            if not local_port:
                continue

            neighbor = {
                "parent_interface": local_port,
                "remote_chassis_id": device_id,
                "remote_port": port_id,
                "remote_port_description": "",
                "remote_system_name": sys_name,
                "remote_system_description": "",
                "remote_system_capab": [c.strip() for c in capabilities.split(",") if c.strip()],
                "remote_system_enable_capab": [c.strip() for c in capabilities.split(",") if c.strip()],
            }

            if local_port not in neighbors:
                neighbors[local_port] = []
            neighbors[local_port].append(neighbor)

        return neighbors

    def _get_lldp_neighbors_gs(self) -> Dict[str, List[Dict[str, str]]]:
        """Get LLDP neighbors for GS-series from tech-support LLDP section."""
        neighbors = {}
        lldp_section = self._get_gs_section("LLDP")

        in_table = False
        for line in lldp_section.splitlines():
            line = line.strip()
            if re.match(r'^-+\s*\+', line):
                in_table = True
                continue
            if not in_table or not line:
                continue

            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                continue

            local_port = parts[0]
            device_id = parts[1]
            port_id = parts[2]
            sys_name = parts[3] if len(parts) > 3 else ""

            if not local_port:
                continue

            if local_port not in neighbors:
                neighbors[local_port] = []
            neighbors[local_port].append({
                "hostname": sys_name or device_id,
                "port": port_id or device_id,
            })

        return neighbors

    def _get_environment_gs(self) -> Dict[str, Dict]:
        """Get environment from tech-support CPU section."""
        environment = {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {"available_ram": -1, "used_ram": -1},
        }

        cpu_section = self._get_gs_section("CPU")
        if not cpu_section:
            return environment

        in_memory = False
        free_kb = None
        alloc_kb = None

        for line in cpu_section.splitlines():
            if "Memory Utilization Report" in line:
                in_memory = True
                continue
            elif "CPU Utilization:" in line and "%" not in line:
                in_memory = False
                continue

            if in_memory:
                fields = line.split()
                if len(fields) >= 2:
                    try:
                        if "free" in fields[0].lower():
                            free_kb = int(fields[1])
                        elif "alloc" in fields[0].lower():
                            alloc_kb = int(fields[1])
                    except (ValueError, IndexError):
                        pass

            if "Total CPU Utilization" in line and "%" in line:
                try:
                    fields = line.split()
                    cpu_util = float(fields[-3].rstrip('%'))
                    environment["cpu"]["0"] = {"%usage": cpu_util}
                except (ValueError, IndexError):
                    environment["cpu"]["0"] = {"%usage": 0.0}

        if free_kb is not None and alloc_kb is not None:
            total_kb = free_kb + alloc_kb
            environment["memory"] = {
                "available_ram": total_kb * 1024,
                "used_ram": alloc_kb * 1024,
            }

        return environment

    def _get_interfaces_ip_gs(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
        """Get interface IPs from tech-support IP Configuration section."""
        interfaces_ip = {}
        section = self._get_gs_section("IP Configuration")

        # Parse "inet x.x.x.x/prefix" from the linux-style output
        for line in section.splitlines():
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+.*scope\s+global', line)
            if m:
                ip_addr = m.group(1)
                prefix = int(m.group(2))
                interfaces_ip["vlan1"] = {
                    "ipv4": {ip_addr: {"prefix_length": prefix}},
                    "ipv6": {},
                }
                break

        return interfaces_ip

    # ---- End GS-series getter implementations ----

    def get_optics(self) -> Dict[str, dict]:
        """Get optics/transceiver information."""
        optics = {}

        output = self._send_command("show fiber-ports optics all")
        if not self._is_supported_command(output):
            return optics

        current_port = None
        for line in output.splitlines():
            line = line.strip()
            if not line or "----" in line or "Port" in line and "Lane" in line:
                continue

            fields = line.split()
            if not fields:
                continue

            # Lines starting with a port number (e.g. 0/1) define a new port
            # Continuation lines (lanes) start with the lane identifier
            if "/" in fields[0] and "-Lane" not in fields[0]:
                current_port = fields[0]
                lane_field = fields[1] if len(fields) > 1 else ""
            else:
                lane_field = fields[0] if fields else ""

            if not current_port or "-Lane" not in lane_field:
                continue

            # Extract lane index from "0/1-Lane1" -> 0
            try:
                lane_idx = int(lane_field.split("-Lane")[1]) - 1
            except (ValueError, IndexError):
                lane_idx = 0

            # Parse values: Temp Voltage Current OutputPower InputPower
            def parse_float(val):
                try:
                    if val == "N/A":
                        return 0.0
                    return float(val)
                except (ValueError, IndexError):
                    return 0.0

            # Fields after the lane identifier
            rest = fields[2:] if "/" in fields[0] and "-Lane" not in fields[0] else fields[1:]
            output_power = parse_float(rest[3]) if len(rest) > 3 else 0.0
            input_power = parse_float(rest[4]) if len(rest) > 4 else 0.0
            laser_bias = parse_float(rest[2]) if len(rest) > 2 else 0.0

            channel = {
                "index": lane_idx,
                "state": {
                    "input_power": {
                        "instant": input_power,
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "output_power": {
                        "instant": output_power,
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "laser_bias_current": {
                        "instant": laser_bias,
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                },
            }

            if current_port not in optics:
                optics[current_port] = {"physical_channels": {"channel": []}}
            optics[current_port]["physical_channels"]["channel"].append(channel)

        return optics

    def get_arp_table(self, vrf: str = "") -> List[Dict[str, Any]]:
        """Get ARP table entries."""
        arp_table = []

        output = self._send_command("show ip arp")
        if not self._is_supported_command(output):
            return arp_table

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            fields = line.split()
            if len(fields) < 4:
                continue

            ip_addr = fields[0]
            # Validate IP address format
            if not re.match(r"\d+\.\d+\.\d+\.\d+", ip_addr):
                continue

            mac_addr = fields[1]
            # Interface is "vlan N" -> combine into "vlan N"
            iface = f"{fields[2]} {fields[3]}" if len(fields) > 3 else fields[2]
            # Parse age: "0h 13m 33s" or "n/a"
            age = 0.0
            age_parts = " ".join(fields[5:]) if len(fields) > 5 else ""
            if age_parts and age_parts != "n/a":
                try:
                    hours = 0
                    minutes = 0
                    seconds = 0
                    for part in age_parts.split():
                        if part.endswith("h"):
                            hours = int(part[:-1])
                        elif part.endswith("m"):
                            minutes = int(part[:-1])
                        elif part.endswith("s"):
                            seconds = int(part[:-1])
                    age = float(hours * 3600 + minutes * 60 + seconds)
                except (ValueError, IndexError):
                    age = 0.0

            arp_table.append({
                "interface": iface,
                "mac": mac_addr,
                "ip": ip_addr,
                "age": age,
            })

        return arp_table

    def get_vlans(self) -> Dict[int, dict]:
        """Get VLAN information."""
        vlans: Dict[int, dict] = {}

        output = self._send_command("show vlan")
        if not self._is_supported_command(output):
            return vlans

        # Parse VLAN table - entries can span multiple lines for interfaces
        current_vlan_id = None
        current_interfaces: List[str] = []

        for line in output.splitlines():
            # Skip header/separator/stats lines
            if not line.strip() or "----" in line or "VLAN ID" in line:
                continue
            if "Maximum VLAN" in line or "VLAN Entries" in line:
                continue

            fields = line.split()
            if not fields:
                continue

            # Check if this line starts a new VLAN entry (starts with numeric VLAN ID)
            try:
                vlan_id = int(fields[0])
                # Save previous VLAN if any
                if current_vlan_id is not None:
                    vlans[current_vlan_id]["interfaces"] = current_interfaces

                # Find VLAN name and type - name can contain spaces
                # Format: VLAN_ID VLAN_NAME VLAN_TYPE INTERFACES
                # Find the type field (Default/Static) to split name from type
                vlan_type_idx = None
                for i, f in enumerate(fields[1:], 1):
                    if f in ("Default", "Static", "Dynamic"):
                        vlan_type_idx = i
                        break

                if vlan_type_idx:
                    vlan_name = " ".join(fields[1:vlan_type_idx])
                    # Interfaces are after the type field, comma-separated
                    iface_str = " ".join(fields[vlan_type_idx + 1:])
                else:
                    vlan_name = fields[1] if len(fields) > 1 else ""
                    iface_str = ""

                current_vlan_id = vlan_id
                current_interfaces = []
                if iface_str:
                    current_interfaces = [i.strip() for i in iface_str.split(",") if i.strip()]

                vlans[current_vlan_id] = {
                    "name": vlan_name,
                    "interfaces": current_interfaces,
                }

            except ValueError:
                # Continuation line with more interfaces
                if current_vlan_id is not None:
                    iface_str = line.strip()
                    new_ifaces = [i.strip() for i in iface_str.split(",") if i.strip()]
                    current_interfaces.extend(new_ifaces)
                    vlans[current_vlan_id]["interfaces"] = current_interfaces

        return vlans

    def get_users(self) -> Dict[str, dict]:
        """Get configured users."""
        users: Dict[str, dict] = {}

        output = self._send_command("show users")
        if not self._is_supported_command(output):
            return users

        past_separator = False
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if "----" in line:
                past_separator = True
                continue
            if not past_separator:
                continue

            fields = line.split()
            if len(fields) < 2:
                continue

            username = fields[0]
            access_mode = fields[1]

            # Parse privilege level from "Privilege-15" format
            level = 0
            if "Privilege-" in access_mode:
                try:
                    level = int(access_mode.split("-")[1])
                except (ValueError, IndexError):
                    level = 0

            users[username] = {
                "level": level,
                "password": "",
                "sshkeys": [],
            }

        return users

    def get_snmp_information(self) -> Dict[str, Any]:
        """Get SNMP configuration."""
        snmp_info: Dict[str, Any] = {
            "chassis_id": "",
            "community": {},
            "contact": "",
            "location": "",
        }

        output = self._send_command("show snmp")
        if not self._is_supported_command(output):
            return snmp_info

        for line in output.splitlines():
            line_stripped = line.strip()

            if line_stripped.startswith("System Contact:"):
                snmp_info["contact"] = line_stripped.replace("System Contact:", "").strip()
            elif line_stripped.startswith("System Location:"):
                snmp_info["location"] = line_stripped.replace("System Location:", "").strip()

        # Parse community strings from the first table
        in_community_table = False
        for line in output.splitlines():
            if "Community-String" in line and "Community-Access" in line:
                in_community_table = True
                continue
            if "----" in line:
                continue
            if not line.strip():
                if in_community_table:
                    in_community_table = False
                continue

            if in_community_table:
                fields = line.split()
                if len(fields) >= 2:
                    community = fields[0]
                    access = fields[1].lower()
                    mode = "rw" if "write" in access else "ro"
                    snmp_info["community"][community] = {
                        "acl": "N/A",
                        "mode": mode,
                    }

        return snmp_info

    def get_route_to(
        self, destination: str = "", protocol: str = "", longer: bool = False
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get routes to a destination."""
        routes: Dict[str, List[Dict[str, Any]]] = {}

        output = self._send_command("show ip route")
        if not self._is_supported_command(output):
            return routes

        # Protocol code mapping
        proto_map = {
            "S": "static",
            "C": "connected",
            "R": "RIP",
            "O": "OSPF",
            "B": "BGP",
            "IA": "OSPF",
            "E1": "OSPF",
            "E2": "OSPF",
            "K": "kernel",
            "L": "leaked",
        }

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            fields = line.split()
            if len(fields) < 2:
                continue

            # Route lines start with a protocol code followed by network/mask
            proto_code = fields[0]
            if proto_code not in proto_map:
                continue

            network = fields[1]
            if "/" not in network:
                continue

            # Parse [preference/metric]
            preference = 0
            for f in fields:
                if f.startswith("[") and "/" in f:
                    try:
                        pref_met = f.strip("[]").split("/")
                        preference = int(pref_met[0])
                    except (ValueError, IndexError):
                        pass

            # Parse next hop
            next_hop = ""
            for i, f in enumerate(fields):
                if f == "via":
                    next_hop = fields[i + 1].rstrip(",") if i + 1 < len(fields) else ""
                    break

            # Filter by destination if specified
            if destination and not network.startswith(destination.split("/")[0]):
                continue

            # Filter by protocol if specified (case-insensitive)
            if protocol and proto_map.get(proto_code, "").lower() != protocol.lower():
                continue

            route_entry = {
                "protocol": proto_map.get(proto_code, proto_code),
                "current_active": True,
                "last_active": True,
                "age": -1,
                "next_hop": next_hop,
                "outgoing_interface": "",
                "selected_next_hop": True,
                "preference": preference,
                "inactive_reason": "",
                "routing_table": "default",
                "protocol_attributes": {},
            }

            if network not in routes:
                routes[network] = []
            routes[network].append(route_entry)

        return routes

    def is_alive(self) -> Dict[str, bool]:
        """Return connection status."""
        return {
            "is_alive": self.device is not None
        }

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

        # GS-series: extract configs from tech-support (no pagination)
        if self._platform_type == "gs_series":
            if retrieve in ("startup", "all"):
                output = self._get_gs_section("Startup-config")
                if sanitized:
                    output = re.sub(r'^.*secret .*$', '', output, flags=re.M)
                    output = re.sub(r'^.*password .*$', '', output, flags=re.M)
                    output = re.sub(r'^.*community .*$', '', output, flags=re.M)
                configs["startup"] = output.strip()
            if retrieve in ("running", "all"):
                output = self._get_gs_section("Running-config")
                if sanitized:
                    output = re.sub(r'^.*secret .*$', '', output, flags=re.M)
                    output = re.sub(r'^.*password .*$', '', output, flags=re.M)
                    output = re.sub(r'^.*community .*$', '', output, flags=re.M)
                configs["running"] = output.strip()
            return configs

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
        if not self.config:
            return ""
        running = self.get_config(retrieve="running")["running"]
        diff = difflib.unified_diff(
            running.splitlines(keepends=True),
            self.config.splitlines(keepends=True),
            fromfile="running",
            tofile="candidate",
        )
        return "".join(diff)

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

        # If port is explicitly specified, use it directly
        if "port" in self.optional_args:
            try:
                self.device = ConnectHandler(**device_args)
                self._enable_mode()
                return
            except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
                raise ConnectionException(f"Failed to connect on port {self.optional_args['port']}: {str(e)}")

        # Otherwise try port 1234 first (M4500 series), then fall back to 22
        try:
            self.device = ConnectHandler(**device_args, port=1234)
            self._enable_mode()
            return
        except (NetMikoTimeoutException, NetMikoAuthenticationException):
            try:
                self.device = ConnectHandler(**device_args, port=22)
                self._enable_mode()
            except (NetMikoTimeoutException, NetMikoAuthenticationException) as e2:
                raise ConnectionException(f"Failed to connect on both ports 1234 and 22: {str(e2)}")

    def _enable_mode(self):
        """Enter privileged mode and detect platform type."""
        try:
            self.device.enable()
            # Disable pagination for this session (only valid for current access line)
            self.device.send_command_timing("no pager", read_timeout=5, cmd_verify=False)
            # Detect platform type
            self._detect_platform()
        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            raise ConnectionException(str(e))

    def _detect_platform(self):
        """Detect whether this is an M-series or GS-series switch."""
        # Quick check: show sysinfo works on M-series, returns "Unknown command" on GS
        output = self.device.send_command_timing(
            "show sysinfo", strip_prompt=False, strip_command=False,
            read_timeout=5, cmd_verify=False
        )
        if "Unknown command" in output:
            self._platform_type = "gs_series"
            self.log.info("Detected GS-series platform")
        else:
            self._platform_type = "m_series"
            self.log.info("Detected M-series platform")

    def _get_gs_tech_support(self) -> Dict[str, str]:
        """Fetch, parse, and cache 'show tech-support' sections (no pagination on GS).

        Returns:
            Dict mapping section names to their content.
        """
        if self._gs_tech_support is None:
            raw = self._send_command("show tech-support", read_timeout=30)
            sections = {}
            current_name = None
            current_lines = []
            # Section headers: "--------- Section Name ---------" (name starts with a letter)
            header_re = re.compile(r'^-{10,}\s+([A-Za-z][\w\s/()-]+?)\s+-{10,}\s*$')
            for line in raw.splitlines():
                m = header_re.match(line)
                if m:
                    if current_name is not None:
                        sections[current_name] = '\n'.join(current_lines)
                    current_name = m.group(1).strip()
                    current_lines = []
                elif current_name is not None:
                    current_lines.append(line)
            if current_name is not None:
                sections[current_name] = '\n'.join(current_lines)
            self._gs_tech_support = sections
        return self._gs_tech_support

    def _get_gs_section(self, section_name: str) -> str:
        """Get a named section from cached tech-support."""
        return self._get_gs_tech_support().get(section_name, "")

    def _get_gs_port_count(self) -> int:
        """Detect and cache GS-series port count from tech-support."""
        if self._gs_port_count > 0:
            return self._gs_port_count
        section = self._get_gs_section("System Information")
        for line in section.splitlines():
            if "Board Name" in line:
                model = line.split(":", 1)[1].strip()
                m = re.search(r'GS\d?(\d{2})', model)
                if m:
                    self._gs_port_count = int(m.group(1))
                break
        if self._gs_port_count == 0:
            self._gs_port_count = 8  # Default fallback
        return self._gs_port_count

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

        if self._platform_type == "gs_series":
            return self._get_environment_gs()

        # Try unified environment command first (M4350)
        command = "show environment"
        output = self._send_command(command)
        
        if "Command not found" not in output and "Invalid input" not in output:
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
                elif "Fans:" in line:
                    in_temp_section = False
                    continue
                    
                if in_temp_section and line and "Unit" not in line and "----" not in line:
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
                elif "Power Modules:" in line:
                    in_fan_section = False
                    continue
                    
                if in_fan_section and line and "Unit Fan" not in line and "----" not in line:
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
                elif line == "":  # End of section
                    in_power_section = False
                    continue
                    
                if in_power_section and line and "Unit" not in line and "----" not in line:
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
        
        if "Command not found" not in output and "Invalid input" not in output:
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
                }
                self.log.debug(f"Set memory values - total: {total_kb}KB, used: {alloc_kb}KB, free: {free_kb}KB")
            else:
                self.log.debug(f"Failed to find both memory values - free: {free_kb}, alloc: {alloc_kb}")
                environment["memory"] = {
                    "available_ram": -1,
                    "used_ram": -1,
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