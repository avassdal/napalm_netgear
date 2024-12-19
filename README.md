# napalm_netgear

NAPALM driver for Netgear ProSafe switches. Uses Netmiko's netgear_prosafe driver for SSH connectivity. Tested with M4300 and M4250 series switches.

## Features
- Configuration management (get, merge, replace, commit)
- Interface information (status, counters, IP addresses)
- LLDP neighbor discovery (basic and detailed)
- MAC address table management
- System information (facts, environment)

## Implemented APIs

### Core Methods
- `open` - Open a connection to the device
- `close` - Close the connection to the device
- `is_alive` - Check if the connection to the device is active

### Configuration Management
- `get_config` - Get startup, running, or all configurations with sanitization options
- `load_merge_candidate` - Load configuration to be merged
- `load_replace_candidate` - Load configuration to be replaced
- `commit_config` - Commit the loaded configuration
- `compare_config` - Compare running config with candidate

**Note**: `compare_config` is not yet fully implemented

### Network Information
- `get_interfaces` - Get interface details (status, speed, description)
- `get_interfaces_ip` - Get interface IP addresses and prefixes
- `get_interfaces_counters` - Get interface traffic statistics
- `get_lldp_neighbors` - Get basic LLDP neighbor information
- `get_lldp_neighbors_detail` - Get detailed LLDP neighbor information
- `get_mac_address_table` - Get MAC address table entries

### System Information
- `get_facts` - Get device facts:
  - Model (from Machine Model)
  - Vendor (Netgear)
  - Software version
  - Serial number
  - Hostname and FQDN (from show hosts)
  - System uptime in seconds
  - List of physical interfaces (0/X format)
- `get_environment` - Get environmental information:
  - CPU usage
  - Memory utilization
  - Temperature sensors
  - Fan status
  - Power supply status

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

- Netgear M4300 series
- Netgear M4250 series

Other Netgear ProSafe switches may work but have not been tested.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Public Domain - see the [LICENSE](LICENSE) file for details.
