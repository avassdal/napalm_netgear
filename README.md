# napalm_netgear

[![Tests](https://github.com/avassdal/napalm_netgear/actions/workflows/test.yml/badge.svg)](https://github.com/avassdal/napalm_netgear/actions/workflows/test.yml)

NAPALM driver for Netgear ProSafe switches. Uses Netmiko's netgear_prosafe driver for SSH connectivity. Tested with M4250, M4350, M4500 series switches and GS108Tv3.

## Features

- Configuration management (get, merge, replace, commit, diff)
- Interface information (status, counters, IP addresses)
- LLDP neighbor discovery (basic and detailed)
- MAC address table management
- System information (facts, environment, SNMP, users, VLANs, optics)
- Multi-platform: M4250, M4350, M4500 and GS108Tv3

## Supported Getters

### Connection

- `open` - Open a connection to the device
- `close` - Close the connection to the device
- `is_alive` - Check if the connection to the device is active

### Configuration Management

- `get_config` - Get startup, running, or all configurations with sanitization options
- `load_merge_candidate` - Load configuration to be merged
- `load_replace_candidate` - Load configuration to be replaced
- `commit_config` - Commit the loaded configuration
- `compare_config` - Diff candidate against live running config (unified diff)

### Network Information

- `get_interfaces` - Get interface details (status, speed, description, MAC, MTU)
- `get_interfaces_ip` - Get interface IP addresses and prefixes (IPv4 + IPv6)
- `get_interfaces_counters` - Get interface traffic statistics
- `get_lldp_neighbors` - Get basic LLDP neighbor information
- `get_lldp_neighbors_detail` - Get detailed LLDP neighbor information
- `get_mac_address_table` - Get MAC address table entries
- `get_arp_table` - Get ARP table entries
- `get_route_to` - Get routes to a destination
- `get_vlans` - Get VLAN information

### System Information

- `get_facts` - Device facts (model, vendor, version, serial, hostname, uptime, interfaces)
- `get_environment` - CPU, memory, temperature, fans, power supplies
- `get_snmp_information` - SNMP community strings and system info
- `get_users` - Local user accounts and privilege levels
- `get_optics` - Optical transceiver diagnostics

## Installation

```bash
pip install napalm-netgear
```

## Usage

```python
from napalm import get_network_driver

# Initialize driver
driver = get_network_driver("netgear")
device = driver(
    hostname="192.168.1.1",
    username="admin",
    password="password"
)

# Open connection
device.open()

# Get device facts
facts = device.get_facts()
print(facts)

# Get configuration with sanitization (removes passwords and SNMP community strings)
config = device.get_config(sanitized=True)
print(config)

# Close connection
device.close()
```

## Supported Devices

- Netgear M4250 series
- Netgear M4350 series
- Netgear M4500 series
- Netgear GS108Tv3

Other Netgear ProSafe switches may work but have not been tested.

## Known Limitations

- `compare_config`: implemented via Python `difflib` (no native diff on device)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Public Domain - see the [LICENSE](LICENSE) file for details.
