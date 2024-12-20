"""NAPALM Netgear ProSafe Handler."""
import re
import socket
from typing import Dict, List
from napalm.base import models

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionClosedException
)
from napalm.base.helpers import (
    generate_regex_or
)
from napalm.base.netmiko_helpers import netmiko_args

from .parser import parseFixedLenght, parseList

MAP_INTERFACE_SPEED = {
    "10 Half": 10,
    "10 Full": 10,
    "100 Half": 100,
    "100 Full": 100,
    "1000 Full": 1000,
    "10G Full": 10000,
    "25G Full": 25000,  # Add support for 25G interfaces
}

MAP_SUBNETMASK_PREFIXLENGTH = {
    "0.0.0.0":	        0,
    "128.0.0.0":	    1,
    "192.0.0.0":	    2,
    "224.0.0.0":	    3,
    "240.0.0.0":	    4,
    "248.0.0.0":	    5,
    "252.0.0.0":	    6,
    "254.0.0.0":	    7,
    "255.0.0.0":	    8,
    "255.128.0.0":	    9,
    "255.192.0.0":      10,
    "255.224.0.0":	    11,
    "255.240.0.0":	    12,
    "255.248.0.0":	    13,
    "255.252.0.0":	    14,
    "255.254.0.0":	    15,
    "255.255.0.0":	    16,
    "255.255.128.0":	17,
    "255.255.192.0":	18,
    "255.255.224.0":	19,
    "255.255.240.0":	20,
    "255.255.248.0":	21,
    "255.255.252.0":	22,
    "255.255.254.0":	23,
    "255.255.255.0":	24,
    "255.255.255.128":	25,
    "255.255.255.192":	26,
    "255.255.255.224":	27,
    "255.255.255.240":	28,
    "255.255.255.248":	29,
    "255.255.255.252":	30,
    "255.255.255.254":	31,
    "255.255.255.255":	32
}

class NetgearDriver(NetworkDriver):
    """NAPALM Netgear ProSafe Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Netgear ProSafe Handler."""
        if optional_args is None:
            optional_args = {}
        self.config = ""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.transport = optional_args.get("transport", "ssh")

        self.netmiko_optional_args = netmiko_args(optional_args)

        self.device = None

        self.platform = "netgear_prosafe"

    def open(self):
        """Open a connection to the device."""
        self.device = self._netmiko_open(
            self.platform, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""
        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    @staticmethod
    def _send_command_postprocess(output):
        """
        Cleanup actions on send_command() for NAPALM getters.
        """
        return output.strip()

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        if self.device is None:
            return {"is_alive": False}
        # SSH
        try:
            # Try sending ASCII null byte to maintain the connection alive
            self.device.write_channel(null)
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {"is_alive": False}

    def get_interfaces(self):
        """
        Get interface details.

        last_flapped is not implemented

        Example Output:

        {   u'Vlan1': {   'description': u'N/A',
                      'is_enabled': True,
                      'is_up': True,
                      'last_flapped': -1.0,
                      'mac_address': u'a493.4cc1.67a7',
                      'speed': 100},
        u'Vlan100': {   'description': u'Data Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100},
        u'Vlan200': {   'description': u'Voice Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100}}
        """
        interfaces = {}
        command = "show interfaces status all"
        output = self._send_command(command)

        # Skip header lines and parse
        lines = output.splitlines()[3:]  # Skip first 3 lines (headers)
        
        for line in lines:
            if not line.strip():
                continue

            # Split line into fields, preserving whitespace for empty fields
            fields = line.split(None, 6)  # Split into max 7 fields
            if len(fields) < 2:  # Need at least port and name
                continue

            port = fields[0].strip()
            
            # Skip LAG interfaces as they're handled separately
            if port.startswith("lag "):
                continue
                
            # Get interface name (may be blank)
            name = fields[1].strip() if len(fields) > 1 else ""
            
            # Get link state
            state = fields[2].strip().lower() if len(fields) > 2 else ""
            is_enabled = state != "down"  # Interface is enabled if not "down"
            is_up = state == "up"
            
            # Get speed from Physical Status field
            speed = 0
            if len(fields) > 4:
                phys_status = fields[4].strip()
                if phys_status in MAP_INTERFACE_SPEED:
                    speed = MAP_INTERFACE_SPEED[phys_status]

            # Create interface entry
            interfaces[port] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": name,
                "last_flapped": -1.0,  # Not available
                "speed": speed,
                "mac_address": "",  # Will be populated from "show interfaces"
            }

        # Get MAC addresses from detailed interface info
        for interface in interfaces:
            command = f"show interface {interface}"
            output = self._send_command(command)
            
            for line in output.splitlines():
                if "Burned In MAC Address:" in line:
                    mac = line.split(":")[-1].strip()
                    interfaces[interface]["mac_address"] = mac
                    break

        return interfaces

    def get_interfaces_counters(self):
        """Return interface counters and errors."""
        interface_counters = {}

        # Get list of interfaces first
        command = "show interfaces status all"
        output = self._send_command(command)
        
        # Parse interface names from status output
        lines = output.splitlines()[3:]  # Skip headers
        interfaces = []
        for line in lines:
            if not line.strip():
                continue
            fields = line.split(None, 1)  # Split into max 2 fields
            if len(fields) >= 1:
                port = fields[0].strip()
                if not port.startswith(("lag ", "vlan ")):  # Skip LAG and VLAN interfaces
                    interfaces.append(port)

        # Get counters for each interface
        for interface in interfaces:
            command = f"show interface {interface}"
            output = self._send_command(command)

            # Initialize counters
            counters = {
                'tx_errors': 0,
                'rx_errors': 0,
                'tx_discards': 0,
                'rx_discards': 0,
                'tx_octets': 0,  # Not available in M4350
                'rx_octets': 0,  # Not available in M4350
                'tx_unicast_packets': 0,
                'rx_unicast_packets': 0,
                'tx_multicast_packets': 0,  # Not available in M4350
                'rx_multicast_packets': 0,  # Not available in M4350
                'tx_broadcast_packets': 0,  # Not available in M4350
                'rx_broadcast_packets': 0
            }

            # Parse counter values
            for line in output.splitlines():
                line = line.strip()
                
                # Map M4350 counter names to NAPALM counter names
                if "Packets Received Without Error" in line:
                    counters['rx_unicast_packets'] = int(line.split('.')[-1].strip())
                elif "Packets Received With Error" in line:
                    counters['rx_errors'] = int(line.split('.')[-1].strip())
                elif "Broadcast Packets Received" in line:
                    counters['rx_broadcast_packets'] = int(line.split('.')[-1].strip())
                elif "Receive Packets Discarded" in line:
                    counters['rx_discards'] = int(line.split('.')[-1].strip())
                elif "Packets Transmitted Without Errors" in line:
                    counters['tx_unicast_packets'] = int(line.split('.')[-1].strip())
                elif "Transmit Packets Discarded" in line:
                    counters['tx_discards'] = int(line.split('.')[-1].strip())
                elif "Transmit Packet Errors" in line:
                    counters['tx_errors'] = int(line.split('.')[-1].strip())

            interface_counters[interface] = counters

        return interface_counters

    def get_mac_address_table(self):
        """Return the MAC address table."""
        mac_table = []

        command = "show mac-addr-table"
        output = self._send_command(command)

        # Skip header lines and parse
        lines = output.splitlines()
        header_found = False
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and the "Address Entries" line
            if not line or "Address Entries Currently in Use" in line:
                continue
                
            # Look for the header line
            if "VLAN ID  MAC Address" in line:
                header_found = True
                continue
                
            # Skip the separator line after header
            if header_found and "-------" in line:
                continue
                
            if header_found:
                # Split the line into fields
                fields = line.split()
                if len(fields) >= 5:  # Must have VLAN, MAC, Interface, IfIndex, Status
                    vlan_id = fields[0]
                    mac_address = fields[1].replace(':', '')  # Remove colons
                    interface = fields[2]
                    
                    # Map status to NAPALM format
                    status = fields[4].lower()
                    if status == "learned":
                        status = "dynamic"
                    elif status == "management":
                        status = "static"
                    else:
                        status = "other"
                        
                    # Skip CPU interfaces as they're internal
                    if "CPU Interface" in interface:
                        continue
                        
                    mac_entry = {
                        'mac': mac_address,
                        'interface': interface,
                        'vlan': int(vlan_id),
                        'static': status == "static",
                        'active': True,  # Always active on Netgear
                        'moves': -1,  # Not available
                        'last_move': -1.0  # Not available
                    }
                    
                    mac_table.append(mac_entry)

        return mac_table

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return the configuration of a device.

        Args:
            retrieve(string): Which configuration type you want to populate, default is all of them.
                              The rest will be set to "".
            full(bool): Retrieve all the configuration. For instance, on ios, "sh run all".
            sanitized(bool): Remove secret data. Default: ``False``.
            format(string): The configuration format style to be retrieved.

        Returns:
          The object returned is a dictionary with a key for each configuration store:

            - running(string) - Representation of the native running configuration
            - candidate(string) - Representation of the native candidate configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
            - startup(string) - Representation of the native startup configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
        """
        # The output of get_config should be directly usable by load_replace_candidate()
        # IOS adds some extra, unneeded lines that should be filtered.
        filter_strings = [
            r"^!System Up Time .*$",
            r"^!Current SNTP Synchronized Time:.*$",
        ]
        filter_pattern = generate_regex_or(filter_strings)

        configs: models.ConfigDict = {
            "startup": "",
            "running": "",
            "candidate": ""  # Netgear doesn't support candidate configuration
        }

        # Netgear only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve in ("startup", "all"):
            command = "show startup-config"
            output = self._send_command(command)
            output = re.sub(filter_pattern, "", output, flags=re.M)
            if sanitized:
                # Remove password lines
                output = re.sub(r"^.*password.*$", "", output, flags=re.M)
                # Remove SNMP community strings
                output = re.sub(r"^.*community.*$", "", output, flags=re.M)
            configs["startup"] = output.strip()

        if retrieve in ("running", "all"):
            command = f"show running-config{run_full}"
            output = self._send_command(command)
            output = re.sub(filter_pattern, "", output, flags=re.M)
            if sanitized:
                # Remove password lines
                output = re.sub(r"^.*password.*$", "", output, flags=re.M)
                # Remove SNMP community strings
                output = re.sub(r"^.*community.*$", "", output, flags=re.M)
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

    def get_facts(self):
        """
        Returns a dictionary containing the following information:
         * uptime - Uptime of the device in seconds.
         * vendor - Manufacturer of the device.
         * model - Device model.
         * hostname - Hostname of the device
         * fqdn - Fqdn of the device
         * os_version - String with the OS version running on the device.
         * serial_number - Serial number of the device
         * interface_list - List of the interfaces of the device
        Example::
            {
            'uptime': 151005.57332897186,
            'vendor': u'Arista',
            'os_version': u'4.14.3-2329074.gaatlantarel',
            'serial_number': u'SN0123A34AS',
            'model': u'vEOS',
            'hostname': u'eos-router',
            'fqdn': u'eos-router',
            'interface_list': [u'Ethernet2', u'Management1', u'Ethernet1', u'Ethernet3']
            }
        """
        # Get version info
        command = "show version"
        output = self._send_command(command)
        ver_fields = parseList(output.splitlines())

        # Get system info
        command = "show sysinfo"
        output = self._send_command(command)
        sys_fields = parseList(output.splitlines())

        # Get hostname and domain info
        command = "show hosts"
        output = self._send_command(command)
        host_fields = parseList(output.splitlines())
        
        hostname = host_fields.get("Host name", "")
        domain = host_fields.get("Default domain", "")
        if domain and "not configured" not in domain.lower():
            fqdn = f"{hostname}.{domain}"
        else:
            fqdn = hostname

        # Parse uptime from "System Up Time: X days Y hrs Z mins W secs"
        uptime = 0.0
        if "System Up Time" in sys_fields:
            parts = sys_fields["System Up Time"].split()
            try:
                days = int(parts[0])
                hours = int(parts[2])
                minutes = int(parts[4])
                seconds = int(parts[6])
                uptime = float(days * 86400 + hours * 3600 + minutes * 60 + seconds)
            except (ValueError, IndexError):
                pass

        # Get interface list
        command = "show interfaces status all"
        output = self._send_command(command)
        interfaces = []
        header_found = False
        
        for line in output.splitlines():
            # Skip empty lines
            if not line.strip():
                continue
                
            # Look for header line
            if "Port" in line and "Name" in line and "Link" in line:
                header_found = True
                continue
                
            # Skip separator line
            if "---------" in line:
                continue
                
            # Only process lines after header
            if header_found:
                parts = line.split()
                if not parts:
                    continue
                    
                # Get interface name (first column)
                interface = parts[0].strip()
                
                # Skip LAG and VLAN interfaces
                if interface.startswith(("lag", "vlan")):
                    continue
                    
                # Add interface if it's a valid port
                if interface and "/" in interface:  # Physical ports have format X/Y
                    interfaces.append(interface)

        return {
            'uptime': uptime,
            'vendor': 'Netgear',
            'os_version': ver_fields.get("Software Version", ""),
            'serial_number': ver_fields.get("Serial Number", ""),
            'model': ver_fields.get("Machine Model", ""),
            'hostname': hostname,
            'fqdn': fqdn,
            'interface_list': interfaces
        }
    
    def get_interfaces_ip(self):
        """
        Get interface ip details.

        Returns a dict of dicts

        Example Output:

        {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
            u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                'ipv6': {   u'1::1': {   'prefix_length': 64},
                                            u'2001:DB8:1::1': {   'prefix_length': 64},
                                            u'2::': {   'prefix_length': 64},
                                            u'FE80::3': {   'prefix_length': 10}}},
            u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
            u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
            u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                        u'10.41.0.1': {   'prefix_length': 24},
                                        u'10.65.0.1': {   'prefix_length': 24}}},
            u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
        """
        command = "show ip interface brief"
        output = self._send_command(command)
        interface_list = parseFixedLenght(["Interface","State","IP Address","IP Mask","TYPE", "Method"], output.splitlines())
        interfaces = {}
        for a in interface_list:
            if(a["Interface"]== ""):
                break
            if(a["Interface"] not in interfaces):
                interfaces[a["Interface"]] = {
                    "ipv4": {}
                }
            interfaces[a["Interface"]]["ipv4"][a["IP Address"]] = {
                "prefix_length": MAP_SUBNETMASK_PREFIXLENGTH[a["IP Mask"]]
            }
        return interfaces

    def _normalize_interface_name(self, interface):
        """Normalize interface names between M4250 and M4350."""
        if interface is None:
            return None
            
        # Handle different interface naming schemes
        # M4250: 0/1
        # M4350: 1/0/1
        if interface.startswith('0/'):
            return interface  # M4250 format
        elif '/' in interface and not interface.startswith(('lag ', 'vlan ')):
            parts = interface.split('/')
            if len(parts) == 3:  # M4350 format (1/0/1)
                return interface
            elif len(parts) == 2:  # M4250 format (0/1)
                return interface
                
        return interface  # Return as-is for LAG/VLAN interfaces

    def _is_supported_command(self, command_output):
        """Check if a command is supported on this model."""
        error_messages = [
            "Command not found",
            "Invalid input",
            "Unavailable command",
            "Unknown command",
            "Error: Command not found"
        ]
        return not any(msg.lower() in command_output.lower() for msg in error_messages)

    def get_environment(self):
        """
        Get environment information from device.
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
        
        if self._is_supported_command(output):
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
                            environment["fans"][fan_name] = {
                                "status": status == "operational"
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

        # Get CPU utilization (common to both models)
        command = "show process cpu"
        output = self._send_command(command)
        
        if self._is_supported_command(output):
            for line in output.splitlines():
                if "CPU Utilization" in line:
                    try:
                        cpu_util = float(line.split(':')[1].strip().rstrip('%'))
                        environment["cpu"][0] = {
                            "%usage": cpu_util
                        }
                    except (ValueError, IndexError):
                        environment["cpu"][0] = {
                            "%usage": 0.0
                        }
                    break

        # Get memory stats (common to both models)
        command = "show memory stats"
        output = self._send_command(command)
        
        if self._is_supported_command(output):
            for line in output.splitlines():
                if "Memory Utilization" in line:
                    try:
                        mem_util = float(line.split(':')[1].strip().rstrip('%'))
                        environment["memory"] = {
                            "available_ram": -1,  # Not available
                            "used_ram": -1,      # Not available
                            "free_ram": -1       # Not available
                        }
                    except (ValueError, IndexError):
                        pass

        return environment

    def get_lldp_neighbors(self) -> Dict[str, List[models.LLDPNeighborDict]]:
        """
        Returns a dictionary where the keys are local ports and the value is a list of \
        dictionaries with the following information:
            * hostname
            * port

        Example::

            {
            u'Ethernet2':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'520',
                    }
                ],
            u'Ethernet3':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'522',
                    }
                ],
            u'Ethernet1':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'519',
                    },
                    {
                    'hostname': u'ios-xrv-unittest',
                    'port': u'Gi0/0/0/0',
                    }
                ],
            u'Management1':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'508',
                    }
                ]
            }
        """
        lldp: Dict[str, List[models.LLDPNeighborDict]] = {}
        command = "show lldp remote-device all"
        output = self._send_command(command)
        
        # Parse the fixed-length table output
        fields = parseFixedLenght(
            ["local_port", "remote_id", "chassis_id", "port_id", "system_name", "oui", "oui_subtype"],
            output.splitlines()
        )
        
        # Initialize all ports with empty lists
        for entry in fields:
            if entry["local_port"] and not entry["local_port"].isspace() and entry["local_port"] != "Interface":
                lldp[entry["local_port"]] = []
        
        current_port = None
        for entry in fields:
            # Skip header rows and empty entries
            if not entry["local_port"] or entry["local_port"] == "Interface":
                continue
                
            # If we have a port number, this is the main entry
            if not entry["local_port"].isspace():
                current_port = entry["local_port"]
                # Only add neighbors if we have remote info
                if entry["remote_id"]:
                    neighbor: models.LLDPNeighborDict = {
                        "hostname": entry["system_name"].strip() or entry["chassis_id"].strip(),
                        "port": entry["port_id"].strip()
                    }
                    lldp[current_port].append(neighbor)
        
        return lldp

    def get_lldp_neighbors_detail(
        self, interface: str = ""
    ) -> models.LLDPNeighborsDetailDict:
        """
        Returns a detailed view of the LLDP neighbors as a dictionary
        containing lists of dictionaries for each interface.

        Empty entries are returned as an empty string (e.g. '') or list where applicable.

        Inner dictionaries contain fields:

            * parent_interface (string)
            * remote_port (string)
            * remote_port_description (string)
            * remote_chassis_id (string)
            * remote_system_name (string)
            * remote_system_description (string)
            * remote_system_capab (list) with any of these values
                * other
                * repeater
                * bridge
                * wlan-access-point
                * router
                * telephone
                * docsis-cable-device
                * station
            * remote_system_enabled_capab (list)

        Example::

            {
                'TenGigE0/0/0/8': [
                    {
                        'parent_interface': u'Bundle-Ether8',
                        'remote_chassis_id': u'8c60.4f69.e96c',
                        'remote_system_name': u'switch',
                        'remote_port': u'Eth2/2/1',
                        'remote_port_description': u'Ethernet2/2/1',
                        'remote_system_description': u'''Cisco Nexus Operating System (NX-OS)
                              Software 7.1(0)N1(1a)
                              TAC support: http://www.cisco.com/tac
                              Copyright (c) 2002-2015, Cisco Systems, Inc. All rights reserved.''',
                        'remote_system_capab': ['bridge', 'repeater'],
                        'remote_system_enable_capab': ['bridge']
                    }
                ]
            }
        """
        lldp = {}

        # First get list of interfaces with LLDP neighbors
        command = "show lldp remote-device all"
        output = self._send_command(command)
        
        # Skip header lines and parse
        lines = output.splitlines()[4:]
        interfaces_with_neighbors = []
        
        for line in lines:
            if not line.strip():
                continue

            # Split line into fields, preserving whitespace for empty fields
            fields = line.split(None, 6)  # Split into max 7 fields
            if len(fields) < 2:  # Need at least port and name
                continue

            port = fields[0].strip()
            
            # Skip LAG interfaces as they're handled separately
            if port.startswith("lag "):
                continue
                
            # Get interface name (may be blank)
            name = fields[1].strip() if len(fields) > 1 else ""
            
            # Get link state
            state = fields[2].strip().lower() if len(fields) > 2 else ""
            is_enabled = state != "down"  # Interface is enabled if not "down"
            is_up = state == "up"
            
            # Get speed from Physical Status field
            speed = 0
            if len(fields) > 4:
                phys_status = fields[4].strip()
                if phys_status in MAP_INTERFACE_SPEED:
                    speed = MAP_INTERFACE_SPEED[phys_status]

            # Create interface entry
            interfaces[port] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": name,
                "last_flapped": -1.0,  # Not available
                "speed": speed,
                "mac_address": "",  # Will be populated from "show interfaces"
            }

        # Get MAC addresses from detailed interface info
        for interface in interfaces:
            command = f"show interface {interface}"
            output = self._send_command(command)
            
            for line in output.splitlines():
                if "Burned In MAC Address:" in line:
                    mac = line.split(":")[-1].strip()
                    interfaces[interface]["mac_address"] = mac
                    break

        return interfaces