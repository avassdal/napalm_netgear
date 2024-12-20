"""Utility functions for parsing Netgear switch command output."""

import re
from typing import Dict, List, Optional, Union, Any

# Interface speed mapping
MAP_INTERFACE_SPEED = {
    "10": 10,
    "100": 100,
    "1000": 1000,
    "2.5G": 2500,
    "10G": 10000,
    "10 Half": 10,
    "10 Full": 10,
    "100 Half": 100,
    "100 Full": 100,
    "1000 Full": 1000,
    "2.5G Full": 2500,
    "10G Full": 10000,
    # GS108Tv3 specific formats
    "1G": 1000,
    "1G Full": 1000,
    "Auto": -1,  # Auto-negotiation
    "10 HDX": 10,
    "10 FDX": 10,
    "100 HDX": 100,
    "100 FDX": 100,
    "1000 FDX": 1000
}

def normalize_interface_name(interface: Optional[str]) -> Optional[str]:
    """Normalize interface names between M4250/M4350/M4500/GS108Tv3.
    
    Args:
        interface: Interface name to normalize
        
    Returns:
        Normalized interface name or None if input is None
        
    Examples:
        >>> normalize_interface_name("0/1")  # M4250/M4500
        "0/1"
        >>> normalize_interface_name("1/0/1")  # M4350
        "1/0/1"
        >>> normalize_interface_name("ch1")  # M4500 port channel
        "ch1"
        >>> normalize_interface_name("g1")  # GS108Tv3
        "g1"
        >>> normalize_interface_name("1")  # GS108Tv3 (alternate format)
        "g1"
    """
    if interface is None:
        return None
        
    # Handle different interface naming schemes
    # M4250: 0/1
    # M4350: 1/0/1
    # M4500: 0/1, ch1 (port channels)
    # GS108Tv3: g1 or 1 (gigabit ports)
    if interface.startswith('ch'):
        return interface  # M4500 port channel
    elif interface.startswith('g'):
        return interface  # GS108Tv3 format
    elif interface.isdigit():  # Convert plain number to GS108Tv3 format
        return f"g{interface}"
    elif interface.startswith('0/'):
        return interface  # M4250/M4500 format
    elif interface.startswith('1/'):
        return interface  # M4350 format
    elif '/' in interface and not interface.startswith(('lag ', 'vlan ')):
        parts = interface.split('/')
        if len(parts) == 3:  # M4350 format (1/0/1)
            return interface
        elif len(parts) == 2:  # M4250/M4500 format (0/1)
            return interface
            
    return interface  # Return as-is for VLAN interfaces

def is_supported_command(command_output: str) -> bool:
    """Check if a command is supported on this model.
    
    Args:
        command_output: Output from command execution
        
    Returns:
        True if command is supported, False otherwise
        
    Example:
        >>> is_supported_command("% Command not found")
        False
        >>> is_supported_command("Interface 0/1 is up")
        True
    """
    error_messages = [
        "Command not found",
        "Invalid command",
        "Incomplete command",
        "Unrecognized command",
    ]
    return not any(msg.lower() in command_output.lower() for msg in error_messages)

def parse_interface_detail(interface: str, output: str) -> Dict[str, Union[str, int, bool, float]]:
    """Parse the output of 'show interface <interface>'.
    
    Args:
        interface: Interface name
        output: Command output to parse
        
    Returns:
        Dictionary containing interface details:
            - mac_address: MAC address string
            - description: Interface description
            - is_enabled: Admin state (bool)
            - is_up: Link state (bool)
            - speed: Interface speed in Mbps (int)
            - mtu: MTU size (int)
            - last_flapped: Time since last state change (float)
    """
    details = {
        "mac_address": "",
        "description": "",
        "is_enabled": True,
        "is_up": False,
        "speed": 0,
        "mtu": 1500,
        "last_flapped": -1.0
    }
    
    # Parse output lines
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        
        # GS108Tv3 format
        if line.startswith("GigabitEthernet"):
            details["is_up"] = "is up" in line.lower()
        elif "Hardware is" in line:
            if "MAC address is" in line:
                mac = line.split("MAC address is")[-1].strip()
                details["mac_address"] = mac
            details["description"] = line
        elif "Auto-speed" in line:
            details["speed"] = -1  # Auto-negotiation
        elif "media type" in line:
            if not details["description"]:
                details["description"] = line
        elif line.startswith("MTU "):
            try:
                details["mtu"] = int(line.split()[1])
            except (IndexError, ValueError):
                pass
                
        # M4250/M4350/M4500 format
        elif "Hardware Address" in line:
            mac = line.split(".")[-1].strip()
            details["mac_address"] = mac
        elif "Link Status" in line:
            details["is_up"] = "Up" in line
        elif "Physical Status" in line:
            mode = line.split(".")[-1].strip()
            details["speed"] = MAP_INTERFACE_SPEED.get(mode, 0)
        elif "Description" in line:
            details["description"] = line.split(".")[-1].strip()
        elif "Maximum Frame Size" in line or "MTU Size" in line:
            try:
                mtu = int(line.split(".")[-1].strip())
                if mtu > 0:
                    details["mtu"] = mtu
            except (IndexError, ValueError):
                pass
            
    return details

def parse_fixed_width_table(fields: List[str], data: List[str]) -> List[Dict[str, str]]:
    """Parse fixed-width table output from Netgear switches.
    
    Args:
        fields: List of field names corresponding to table columns
        data: Raw command output lines
        
    Returns:
        List of dictionaries with field names as keys and values from table
        
    Example:
        >>> data = [
        ...     "Port       Name         State",
        ...     "---------- ------------ -----",
        ...     "0/1                     Up   ",
        ...     "0/2        Server1      Down "
        ... ]
        >>> fields = ["port", "name", "state"]
        >>> parse_fixed_width_table(fields, data)
        [
            {"port": "0/1", "name": "", "state": "Up"},
            {"port": "0/2", "name": "Server1", "state": "Down"}
        ]
    """
    cell_start = []  # Start positions of columns
    cell_end = []    # End positions of columns
    results = []
    
    for line in data:
        # Parse separator line to find column boundaries
        if line.startswith("-"):
            if cell_start:  # Already found boundaries
                break
                
            in_cell = False
            for i, char in enumerate(line):
                if char == "-" and not in_cell:
                    cell_start.append(i)
                    in_cell = True
                elif char == " " and in_cell:
                    cell_end.append(i)
                    in_cell = False
                    
            if in_cell:  # Handle last column
                cell_end.append(len(line))
            continue
            
        if not cell_start:  # Skip until we find column boundaries
            continue
            
        # Parse data line into fields
        item = {}
        for i, field in enumerate(fields):
            if not field:  # Skip empty field names
                continue
            item[field] = line[cell_start[i]:cell_end[i]].strip()
        results.append(item)
        
    return results

def parse_key_value_list(data: List[str]) -> Dict[str, str]:
    """Parse key-value pairs separated by dots.
    
    Args:
        data: List of lines containing key-value pairs
        
    Returns:
        Dictionary of key-value pairs
        
    Example:
        >>> data = [
        ...     "Description.............. Core Switch",
        ...     "MAC Address.............. 00:11:22:33:44:55",
        ... ]
        >>> parse_key_value_list(data)
        {
            "Description": "Core Switch",
            "MAC Address": "00:11:22:33:44:55"
        }
    """
    pattern = r"^([^.]+)\.+ (.*)$"
    results = {}
    
    for line in data:
        match = re.search(pattern, line)
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()
            results[key] = value
            
    return results

def parse_pipe_separated_table(output: str, skip_patterns: List[str] = None) -> List[Dict[str, str]]:
    """Parse a pipe-separated table output into a list of dictionaries.
    
    Args:
        output: String containing the table output
        skip_patterns: List of patterns to skip lines (e.g. separators)
        
    Returns:
        List of dictionaries with field names as keys
    """
    if skip_patterns is None:
        skip_patterns = []
        
    results = []
    headers = []
    
    for line in output.splitlines():
        # Skip empty lines and lines matching skip patterns
        if not line.strip() or any(pattern in line for pattern in skip_patterns):
            continue
            
        # Split line by pipe and strip whitespace
        fields = [f.strip() for f in line.split("|") if f.strip()]
        
        # First non-skipped line contains headers
        if not headers:
            headers = fields
            continue
            
        # Create dictionary from fields
        if len(fields) == len(headers):
            entry = dict(zip(headers, fields))
            results.append(entry)
            
    return results

def parse_gs108tv3_mac_table(output: str) -> List[Dict[str, Any]]:
    """Parse GS108Tv3 MAC address table output.
    
    Args:
        output: Output from 'show mac address-table'
        
    Returns:
        List of dictionaries containing MAC table entries
    """
    mac_entries = []
    skip_patterns = ["---", "VID", "Total number"]
    
    parsed = parse_pipe_separated_table(output, skip_patterns)
    
    for entry in parsed:
        try:
            vlan_id = int(entry.get("VID", "0"))
            mac_entries.append({
                "mac": entry.get("MAC Address", ""),
                "interface": entry.get("Ports", ""),
                "vlan": vlan_id,
                "static": entry.get("Type", "").lower() != "dynamic",
                "active": True,
                "moves": 0,
                "last_move": 0.0
            })
        except ValueError:
            continue
            
    return mac_entries

def parse_gs108tv3_lldp_neighbors(output: str) -> Dict[str, List[Dict[str, str]]]:
    """Parse GS108Tv3 LLDP neighbors output.
    
    Args:
        output: Output from 'show lldp neighbor'
        
    Returns:
        Dictionary of interfaces and their LLDP neighbors
    """
    neighbors = {}
    skip_patterns = ["---", "Port |", "TTL"]
    
    parsed = parse_pipe_separated_table(output, skip_patterns)
    
    for entry in parsed:
        local_port = entry.get("Port", "")
        if not local_port:
            continue
            
        if local_port not in neighbors:
            neighbors[local_port] = []
            
        neighbors[local_port].append({
            "hostname": entry.get("SysName", ""),
            "port": entry.get("Port ID", "")
        })
        
    return neighbors

def parse_gs108tv3_system_info(output: str) -> Dict[str, str]:
    """Parse GS108Tv3 system information from running config.
    
    Args:
        output: Output from 'show running-config'
        
    Returns:
        Dictionary containing system information
    """
    info = {
        "model": "",
        "os_version": "",
        "serial_number": "",
        "hostname": "",
        "uptime": 0
    }
    
    for line in output.splitlines():
        line = line.strip()
        
        if line.startswith("! Model:"):
            info["model"] = line.split(":", 1)[1].strip()
        elif line.startswith("! Firmware Version:"):
            info["os_version"] = line.split(":", 1)[1].split()[0].strip()
        elif line.startswith("! Serial Number:"):
            info["serial_number"] = line.split(":", 1)[1].strip()
        elif line.startswith("! System Up Time:"):
            uptime_str = line.split(":", 1)[1].strip()
            try:
                parts = uptime_str.replace(",", "").split()
                days = int(parts[0]) if "days" in parts else 0
                hours = int(parts[parts.index("hours")-1]) if "hours" in parts else 0
                mins = int(parts[parts.index("mins")-1]) if "mins" in parts else 0
                secs = int(parts[parts.index("secs")-1]) if "secs" in parts else 0
                info["uptime"] = ((days * 24 + hours) * 60 + mins) * 60 + secs
            except (ValueError, IndexError):
                info["uptime"] = -1
        elif line.startswith("system name"):
            info["hostname"] = line.split('"')[1]
            
    return info

def parse_interface_status(output: str) -> List[Dict[str, str]]:
    """Parse the output of 'show interfaces status all'.
    
    Args:
        output: Command output to parse
        
    Returns:
        List of dictionaries containing interface status:
            - port: Interface name (0/1, 0/2)
            - name: Interface description
            - state: Link State (Up/Down)
            - mode: Physical Mode (Auto)
            - speed: Physical Status (1000 Full, 10G Full)
            - type: Media Type (Copper, 10GBase-SR)
            - flow_control: Flow Control state (Inactive)
            - vlan: VLAN membership (1, 50, Trunk)
            
    Example:
        >>> output = '''
        ...                                    Link    Physical    Physical    Media       Flow
        ... Port       Name                    State   Mode        Status      Type        Control     VLAN
        ... ---------  ----------------------  ------  ----------  ----------  ----------  ----------  ----------
        ... 0/1                                Down    Auto                                Inactive    50
        ... 0/2                                Up      Auto        1000 Full   Copper      Inactive    1
        ... '''
        >>> parse_interface_status(output)
        [
            {'port': '0/1', 'name': '', 'state': 'Down',
             'mode': 'Auto', 'speed': '', 'type': '', 'flow_control': 'Inactive', 'vlan': '50'},
            {'port': '0/2', 'name': '', 'state': 'Up',
             'mode': 'Auto', 'speed': '1000 Full', 'type': 'Copper', 'flow_control': 'Inactive', 'vlan': '1'}
        ]
    """
    # Skip empty lines
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 3:
        return []

    # Find the header lines
    header_index = -1
    for i, line in enumerate(lines):
        if "Link    Physical    Physical    Media" in line:
            header_index = i
            break
    
    if header_index == -1:
        return []

    # Get the column headers and separator line
    header1 = lines[header_index]
    header2 = lines[header_index + 1]
    separator = lines[header_index + 2]

    # Define field names based on M4250 format
    # Map to the actual columns in the output:
    # Port, Name, Link State, Physical Mode, Physical Status, Media Type, Flow Control, VLAN
    fields = ["port", "name", "state", "mode", "speed", "type", "flow_control", "vlan"]

    # Find column positions from separator line
    positions = []
    in_column = False
    for i, char in enumerate(separator):
        if char == "-" and not in_column:
            positions.append(i)
            in_column = True
        elif char != "-" and in_column:
            in_column = False
    positions.append(len(separator))

    # Parse each data line
    results = []
    for line in lines[header_index + 3:]:
        if not line or line.startswith(("--More--", "(M4250", "(")):
            continue

        # Skip LAG and VLAN interfaces
        if line.strip().startswith(("lag ", "vlan ")):
            continue

        # Extract values based on column positions
        values = {}
        for i, field in enumerate(fields):
            if i < len(positions) - 1:
                start = positions[i]
                end = positions[i + 1]
                value = line[start:end].strip() if start < len(line) else ""
                values[field] = value

        if values.get("port") and "/" in values["port"]:  # Only add if we have a valid port number
            results.append(values)

    return results

if __name__ == '__main__':
    data="""(M4250-26G4XF-PoE+)#show interfaces status all

                                   Link    Physical    Physical    Media       Flow
Port       Name                    State   Mode        Status      Type        Control     VLAN
---------  ----------------------  ------  ----------  ----------  ----------  ----------  ----------
0/1                                Down    Auto                                Inactive    50
0/2                                Up      Auto        1000 Full   Copper      Inactive    1
0/3                                Down    Auto                                Inactive    50
0/4                                Down    Auto                                Inactive    50
0/5                                Down    Auto                                Inactive    50
0/6                                Down    Auto                                Inactive    50
0/7                                Down    Auto                                Inactive    50
0/8                                Down    Auto                                Inactive    50
0/9                                Down    Auto                                Inactive    50
0/10                               Down    Auto                                Inactive    50
0/11                               Down    Auto                                Inactive    50
0/12                               Down    Auto                                Inactive    50
0/13                               Down    Auto                                Inactive    50
0/14                               Down    Auto                                Inactive    50
0/15                               Down    Auto                                Inactive    50
0/16                               Down    Auto                                Inactive    50
0/17                               Down    Auto                                Inactive    50
0/18                               Down    Auto                                Inactive    50
0/19                               Down    Auto                                Inactive    50
0/20                               Down    Auto                                Inactive    50
0/21                               Down    Auto                                Inactive    50
0/22                               Down    Auto                                Inactive    50
0/23                               Down    Auto                                Inactive    50
0/24                               Down    Auto                                Inactive    50
0/25                               Down    Auto                                Inactive    50
0/26                               Down    Auto                                Inactive    50
0/27                               Down    10G Full                                    Inactive    50
0/28                               Down    10G Full                                    Inactive    50
0/29                               Down    10G Full                                    Inactive    50
0/30                               Up      10G Full    10G Full    10GBase-LR          Inactive    50
lag 1                              Down                                                             1
lag 2                              Down                                                             1
lag 3                              Down                                                             1
lag 4                              Down                                                             1
lag 5                              Down                                                             1
lag 6                              Down                                                             1
lag 7                              Down                                                             1
lag 8                              Down                                                             1
lag 9                              Down                                                             1
lag 10                             Down                                                             1
lag 11                             Down                                                             1
lag 12                             Down                                                             1
lag 13                             Down                                                             1
lag 14                             Down                                                             1
lag 15                             Down                                                             1
lag 16                             Down                                                             1
lag 17                             Down                                                             1
lag 18                             Down                                                             1
lag 19                             Down                                                             1
lag 20                             Down                                                             1
lag 21                             Down                                                             1
lag 22                             Down                                                             1
lag 23                             Down                                                             1
lag 24                             Down                                                             1
vlan 1                             Up      10 Half     10 Half     Unknown
vlan 4000                          Up      10 Half     10 Half     Unknown

(M4250-26G4XF-PoE+)# """
    #print(parse_fixed_width_table(["name","label","state","","speed"],data.split("\n")))

    data = """(M4250-26G4XF-PoE+)#show interface 0/1

Packets Received Without Error................. 0
Packets Received With Error.................... 0
Broadcast Packets Received..................... 0
Receive Packets Discarded...................... 0
Packets Transmitted Without Errors............. 0
Transmit Packets Discarded..................... 0
Transmit Packet Errors......................... 0
Collision Frames............................... 0
Number of link down events..................... 0
Load Interval.................................. 300
Received Rate(Mbps)............................ 0.0
Transmitted Rate(Mbps)......................... 0.0
Received Error Rate............................ 0
Transmitted Error Rate......................... 0
Packets Received Per Second.................... 0
Packets Transmitted Per Second................. 0
Percent Utilization Received................... 0%
Percent Utilization Transmitted................ 0%
Link Flaps..................................... 0
Time Since Counters Last Cleared............... 11 day 1 hr 50 min 29 sec

(M4250-26G4XF-PoE+)# """
    print(parse_key_value_list(data.split("\n")))
