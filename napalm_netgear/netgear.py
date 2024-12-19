"""NAPALM Netgear ProSafe Handler."""
import re
import socket

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

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """Implementation of get_config for Netgear Prosafe.

        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since IOS does not support candidate configuration.
        """

        # The output of get_config should be directly usable by load_replace_candidate()
        # IOS adds some extra, unneeded lines that should be filtered.
        filter_strings = [
            r"^!System Up Time .*$",
            r"^!Current SNTP Synchronized Time:.*$",
        ]
        filter_pattern = generate_regex_or(filter_strings)

        configs = {"startup": "", "running": "", "candidate": ""}
        # Netgear only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve in ("startup", "all"):
            command = "show startup-config"
            output = self._send_command(command)
            output = re.sub(filter_pattern, "", output, flags=re.M)
            configs["startup"] = output.strip()

        if retrieve in ("running", "all"):
            command = f"show running-config{run_full}"
            output = self._send_command(command)
            output = re.sub(filter_pattern, "", output, flags=re.M)
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

        command = "show ver"
        output = self._send_command(command)
        fields = parseList(output.splitlines())

        return {
            'uptime': 0.0,
            'vendor': 'Netgear',
            'os_version': fields["Software Version"],
            'serial_number': fields["Serial Number"],
            'model': fields["Machine Model"],
            'hostname': '',
            'fqdn': '',
            'interface_list': []
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
            if not line:
                continue
                
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

    def get_lldp_neighbors(self):
        """
        Returns a dictionary where the keys are local ports and the value is a list of dictionaries
        with the following information:
            * hostname
            * port

        Example:
            {
                '0/1': [
                    {
                        'hostname': 'switch2.company.com',
                        'port': 'Ethernet1'
                    }
                ]
            }
        """
        lldp = {}
        command = "show lldp remote-device all"
        output = self._send_command(command)
        
        # Parse the fixed-length table output
        fields = parseFixedLenght(
            ["local_port", "remote_id", "chassis_id", "port_id", "system_name", "oui", "oui_subtype"],
            output.splitlines()
        )
        
        current_port = None
        for entry in fields:
            # Skip header rows and empty entries
            if not entry["local_port"] or entry["local_port"] == "Interface":
                continue
                
            # If we have a port number, this is the main entry
            if not entry["local_port"].isspace():
                current_port = entry["local_port"]
                # Only add ports that have neighbors
                if entry["remote_id"]:
                    if current_port not in lldp:
                        lldp[current_port] = []
                    lldp[current_port].append({
                        "hostname": entry["system_name"].strip() or entry["chassis_id"].strip(),
                        "port": entry["port_id"].strip()
                    })
        
        return lldp

    def get_lldp_neighbors_detail(self):
        """
        Returns a detailed view of the LLDP neighbors as a dictionary.

        Example:
            {
                'local_port': {
                    'parent_interface': 'string',
                    'remote_port': 'string',
                    'remote_port_description': 'string',
                    'remote_chassis_id': 'string',
                    'remote_system_name': 'string',
                    'remote_system_description': 'string',
                    'remote_system_capab': ['capabilities'],
                    'remote_system_enable_capab': ['enabled_capabilities']
                }
            }
        """
        lldp = {}
        
        # First get list of ports with LLDP neighbors
        neighbors = self.get_lldp_neighbors()
        
        # For each port with a neighbor, get the details
        for local_port in neighbors:
            command = f"show lldp remote-device detail {local_port}"
            output = self._send_command(command)
            
            # Initialize the port entry
            lldp[local_port] = {}
            
            # Parse the detailed output
            current_section = None
            capabilities = []
            enabled_capabilities = []
            
            for line in output.splitlines():
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or line.startswith("LLDP Remote Device Detail") or line == "Local Interface: " + local_port:
                    continue
                
                # Parse each field
                if line.startswith("Remote Identifier:"):
                    remote_id = line.split(":")[1].strip()
                elif line.startswith("Chassis ID:"):
                    lldp[local_port]['remote_chassis_id'] = line.split(":")[1].strip()
                elif line.startswith("Port ID:"):
                    lldp[local_port]['remote_port'] = line.split(":")[1].strip()
                elif line.startswith("System Name:"):
                    lldp[local_port]['remote_system_name'] = line.split(":")[1].strip()
                elif line.startswith("System Description:"):
                    lldp[local_port]['remote_system_description'] = line.split(":")[1].strip()
                elif line.startswith("Port Description:"):
                    lldp[local_port]['remote_port_description'] = line.split(":")[1].strip()
                elif line.startswith("System Capabilities Supported:"):
                    capabilities = [cap.strip() for cap in line.split(":")[1].strip().split(",")]
                    lldp[local_port]['remote_system_capab'] = capabilities
                elif line.startswith("System Capabilities Enabled:"):
                    enabled_capabilities = [cap.strip() for cap in line.split(":")[1].strip().split(",")]
                    lldp[local_port]['remote_system_enable_capab'] = enabled_capabilities
                elif line.startswith("Management Address:"):
                    current_section = "mgmt_addr"
                    lldp[local_port]['remote_management_address'] = {}
                elif current_section == "mgmt_addr" and line.startswith("    Address:"):
                    addr = line.split(":")[1].strip()
                    if addr:
                        lldp[local_port]['remote_management_address'] = addr
                
            # Set parent interface to the physical port
            lldp[local_port]['parent_interface'] = local_port
            
        return lldp