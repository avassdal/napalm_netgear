from napalm import get_network_driver
import json

def print_json(data):
    print(json.dumps(data, indent=2))

# Initialize driver
driver = get_network_driver('netgear')
device = driver(
    hostname='10.10.10.3',
    username='admin',
    password='LjSnS2wWMt5Ljn',
    optional_args={'port': 1223}
)

# Connect and get data
print("Connecting to device...")
device.open()

print("\nGetting facts...")
facts = device.get_facts()
print_json(facts)

print("\nGetting interfaces...")
interfaces = device.get_interfaces()
print_json(interfaces)

print("\nGetting interface counters...")
counters = device.get_interfaces_counters()
print_json(counters)

print("\nGetting MAC address table...")
mac_table = device.get_mac_address_table()
print_json(mac_table)

print("\nGetting LLDP neighbors...")
lldp = device.get_lldp_neighbors()
print_json(lldp)

# Close connection
device.close()
print("\nConnection closed.")
