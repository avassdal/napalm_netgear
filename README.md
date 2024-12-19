# napalm_netgear
NAPALM module for Netgear switches

Uses netmiko netgear prosafe driver. Tested with M4300 and M4250.

## Features
- Configuration management (get, merge, replace)
- Interface information and statistics
- LLDP neighbor discovery
- Environment monitoring (CPU, memory, temperature, fans, power)
- MAC address table management

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

### Network Information
- `get_interfaces` - Get interface details including status and speed
- `get_interfaces_ip` - Get interface IP addresses and prefixes
- `get_interfaces_counters` - Get basic interface traffic statistics
- `get_lldp_neighbors` - Get basic LLDP neighbor information
- `get_lldp_neighbors_detail` - Get detailed LLDP neighbor information
- `get_mac_address_table` - Get MAC address table entries

### System Information
- `get_facts` - Get device facts:
  - Model and vendor information
  - Software version and serial number
  - Hostname and FQDN (if domain configured)
  - System uptime in seconds
  - List of physical interfaces (excluding LAG/VLAN)
- `get_environment` - Get environmental information (CPU, memory, temperature, fans, power)

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

# Get device facts with accurate model and version
facts = device.get_facts()
print(facts)

# Get configuration with sanitization
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
