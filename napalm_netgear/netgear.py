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
    "10G Full": 10*1000,
    "1000 Full": 1000,
    "100 Full": 100,
    "100 Half": 100,
    "10 Full": 10,
    "10 Half": 10,
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
        # default values.
        last_flapped = -1.0

        command = "show interfaces status all"
        output = self._send_command(command)
        fields = parseFixedLenght(["name", "label", "state", "", "speed"], output.splitlines())

        interface_dict = {}
        for item in fields:
            if(item["name"].startswith("lag")):
                continue
            try:
                speed = MAP_INTERFACE_SPEED[item["speed"]]
            except KeyError:
                speed = 1000
            interface_dict[item["name"]] = {
                "is_enabled": True,
                "is_up": (item["state"] == "Up"),
                "description": item["label"],
                "mac_address": "",
                "last_flapped": last_flapped,
                "mtu": 1500,
                "speed": speed
            }

        return interface_dict

    def get_interfaces_counters(self):
        """
        Return interface counters and errors.

        'tx_errors': int,
        'rx_errors': int,
        'tx_discards': int,
        'rx_discards': int,
        'tx_octets': int,
        'rx_octets': int,
        'tx_unicast_packets': int,
        'rx_unicast_packets': int,
        'tx_multicast_packets': int,
        'rx_multicast_packets': int,
        'tx_broadcast_packets': int,
        'rx_broadcast_packets': int,

        Currently doesn't determine output broadcasts, multicasts
        """
        res = {}
        command = "show interfaces status all"
        output = self._send_command(command)
        interfaces = parseFixedLenght(["name"], output.splitlines())
        for a in interfaces:
            name = a["name"]
            if(name.startswith("lag")):
                break
            command = "show interface %s" % name
            output = self._send_command(command)
            stats = parseList(output.splitlines())
            res[name] = {
                'tx_errors': int(stats['Transmit Packet Errors']),
                'rx_errors': int(stats['Packets Received With Error']),
                'tx_discards': int(stats['Transmit Packets Discarded']),
                'rx_discards': int(stats['Receive Packets Discarded']),
                'tx_octets': -1,
                'rx_octets': -1,
                'tx_unicast_packets': int(stats['Packets Transmitted Without Errors']),
                'rx_unicast_packets': int(stats['Packets Received Without Error']),
                'tx_multicast_packets': -1,
                'rx_multicast_packets': -1,
                'tx_broadcast_packets': -1,
                'rx_broadcast_packets': int(stats['Broadcast Packets Received']),
            }
        return res

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)
        """
        res = []
        command = "show mac-addr-table"
        output = self._send_command(command)
        fields = parseFixedLenght(["vlan", "mac", "interface", "", "status"], output.splitlines())
        for item in fields:
            res.append({
                "mac": item["mac"],
                "interface": item["interface"],
                "vlan": int(item["vlan"]),
                "active": True,
                "static": (item["status"] == "Learned"),
                "moves": -1,
                "last_move": -1.0
            })
        return res

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
        for line in output.splitlines():
            # Skip header and empty lines
            if not line or "-----" in line or "Port" in line:
                continue
            # First word in line is interface name
            interface = line.split()[0]
            if interface and not interface.startswith("lag"):
                interfaces.append(interface)

        return {
            'uptime': uptime,
            'vendor': 'Netgear',
            'os_version': ver_fields.get("Software Version", ""),  # More accurate from show version
            'serial_number': ver_fields.get("Serial Number", ""),
            'model': ver_fields.get("Machine Model", ""),  # More accurate from show version
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

    def get_environment(self):
        """
        Returns a dictionary with the environment information of the device.
        
        Example:
            {
                "fans": {
                    "Fan1": {
                        "status": True
                    }
                },
                "temperature": {
                    "CPU": {
                        "is_alert": False,
                        "is_critical": False,
                        "temperature": 45.0
                    }
                },
                "power": {
                    "PSU1": {
                        "capacity": 50.0,
                        "output": 8.3,
                        "status": True
                    }
                },
                "cpu": {
                    "0": {
                        "%usage": 25.32
                    }
                },
                "memory": {
                    "available_ram": 1437136,
                    "used_ram": 613596
                }
            }
        """
        environment = {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {
                "available_ram": 0,
                "used_ram": 0
            }
        }

        # Get memory information
        command = "show process memory"
        output = self._send_command(command)
        
        # Parse memory information from the detailed output
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Total:"):
                # Skip this as we want free/allocated
                continue
            elif line.startswith("Allocated:"):
                try:
                    used_mem = int(line.split()[1])
                    environment["memory"]["used_ram"] = used_mem
                except (ValueError, IndexError):
                    pass
            elif line.startswith("Free:"):
                try:
                    free_mem = int(line.split()[1])
                    environment["memory"]["available_ram"] = free_mem
                except (ValueError, IndexError):
                    pass

        # Get CPU information
        command = "show process cpu"
        output = self._send_command(command)
        
        # Parse CPU information
        for line in output.splitlines():
            if "Total CPU Utilization" in line:
                try:
                    parts = line.split()
                    # Use 5 seconds CPU utilization
                    cpu_usage = float(parts[-3].strip("%"))
                    environment["cpu"]["0"] = {
                        "%usage": cpu_usage
                    }
                except (ValueError, IndexError):
                    environment["cpu"]["0"] = {
                        "%usage": -1.0
                    }

        # Get environment information
        command = "show environment"
        output = self._send_command(command)
        
        # Parse the output sections
        sections = {}
        current_section = None
        current_lines = []
        
        for line in output.splitlines():
            line = line.strip()
            
            # Check for main temperature
            if line.startswith("Temp (C)"):
                try:
                    temp = float(line.split(".")[-1].strip())
                    environment["temperature"]["System"] = {
                        "temperature": temp,
                        "is_alert": False,
                        "is_critical": False
                    }
                except (ValueError, IndexError):
                    pass
                continue
                
            # Identify sections
            if "Temperature Sensors:" in line:
                if current_section and current_lines:
                    sections[current_section] = current_lines
                current_section = "temperature_sensors"
                current_lines = []
            elif "Fans:" in line:
                if current_section and current_lines:
                    sections[current_section] = current_lines
                current_section = "fans"
                current_lines = []
            elif "Power Modules:" in line:
                if current_section and current_lines:
                    sections[current_section] = current_lines
                current_section = "power"
                current_lines = []
            elif current_section:
                current_lines.append(line)
        
        # Add the last section
        if current_section and current_lines:
            sections[current_section] = current_lines
            
        # Parse temperature sensors
        if "temperature_sensors" in sections:
            headers = None
            for line in sections["temperature_sensors"]:
                if "----" in line:
                    continue
                if headers is None:
                    headers = [h.lower() for h in line.split()]
                    continue
                    
                parts = line.split()
                if len(parts) >= 6:  # Ensure we have enough parts
                    sensor_name = parts[2]  # sensor-System1, sensor-MAC, etc.
                    try:
                        temp = float(parts[3])
                        state = parts[4].lower()
                        max_temp = float(parts[5])
                        
                        environment["temperature"][sensor_name] = {
                            "temperature": temp,
                            "is_alert": state != "normal",
                            "is_critical": state == "critical",
                        }
                    except (ValueError, IndexError):
                        continue

        # Parse fans
        if "fans" in sections:
            headers = None
            for line in sections["fans"]:
                if "----" in line:
                    continue
                if headers is None:
                    headers = [h.lower() for h in line.split()]
                    continue
                    
                parts = line.split()
                if len(parts) >= 7:  # Ensure we have enough parts
                    fan_name = f"Fan{parts[1]}"  # FAN-1 becomes Fan1
                    state = parts[6].lower()
                    
                    environment["fans"][fan_name] = {
                        "status": state != "failed"
                    }

        # Parse power supplies
        if "power" in sections:
            headers = None
            for line in sections["power"]:
                if "----" in line:
                    continue
                if headers is None:
                    headers = [h.lower() for h in line.split()]
                    continue
                    
                parts = line.split()
                if len(parts) >= 5:  # Ensure we have enough parts
                    psu_name = f"PSU{parts[1]}"  # PS-1 becomes PSU1
                    state = parts[4].lower()
                    
                    environment["power"][psu_name] = {
                        "status": state == "operational",
                        "capacity": -1.0,  # Power capacity not available
                        "output": -1.0     # Power output not available
                    }

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
        lldp: models.LLDPNeighborsDetailDict = {}
        
        # Get list of ports with LLDP neighbors
        neighbors = self.get_lldp_neighbors()
        
        # If interface is specified, only get details for that interface
        if interface:
            if interface in neighbors:
                ports_to_query = [interface]
            else:
                return {}
        else:
            ports_to_query = list(neighbors.keys())
        
        # For each port with a neighbor, get the details
        for local_port in ports_to_query:
            command = f"show lldp remote-device detail {local_port}"
            output = self._send_command(command)
            
            # Initialize the port entry with an empty list
            lldp[local_port] = []
            
            # Skip if no LLDP data
            if "No LLDP data has been received" in output:
                continue
            
            # Create a neighbor entry
            neighbor = {
                'parent_interface': local_port,
                'remote_port': '',
                'remote_port_description': '',
                'remote_chassis_id': '',
                'remote_system_name': '',
                'remote_system_description': '',
                'remote_system_capab': [],
                'remote_system_enable_capab': []
            }
            
            # Parse the detailed output
            capabilities_map = {
                'Other': 'other',
                'Repeater': 'repeater',
                'Bridge': 'bridge',
                'WLAN Access Point': 'wlan-access-point',
                'Router': 'router',
                'Telephone': 'telephone',
                'DOCSIS Cable Device': 'docsis-cable-device',
                'Station Only': 'station'
            }
            
            for line in output.splitlines():
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or line.startswith("LLDP Remote Device Detail") or line == "Local Interface: " + local_port:
                    continue
                
                # Parse each field
                if line.startswith("Remote Identifier:"):
                    remote_id = line.split(":")[1].strip()
                elif line.startswith("Chassis ID:"):
                    neighbor['remote_chassis_id'] = line.split(":")[1].strip()
                elif line.startswith("Port ID:"):
                    neighbor['remote_port'] = line.split(":")[1].strip()
                elif line.startswith("System Name:"):
                    neighbor['remote_system_name'] = line.split(":")[1].strip()
                elif line.startswith("System Description:"):
                    neighbor['remote_system_description'] = line.split(":")[1].strip()
                elif line.startswith("Port Description:"):
                    neighbor['remote_port_description'] = line.split(":")[1].strip()
                elif line.startswith("System Capabilities Supported:"):
                    caps = line.split(":")[1].strip()
                    if caps:
                        raw_caps = [cap.strip() for cap in caps.split(",")]
                        neighbor['remote_system_capab'] = [
                            capabilities_map[cap] for cap in raw_caps 
                            if cap in capabilities_map
                        ]
                elif line.startswith("System Capabilities Enabled:"):
                    caps = line.split(":")[1].strip()
                    if caps:
                        raw_caps = [cap.strip() for cap in caps.split(",")]
                        neighbor['remote_system_enable_capab'] = [
                            capabilities_map[cap] for cap in raw_caps 
                            if cap in capabilities_map
                        ]
            
            # Add the neighbor to the port's list
            lldp[local_port].append(neighbor)
            
        return lldp