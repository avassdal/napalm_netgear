"""Utility functions for parsing Netgear switch command output."""

import re
from typing import Dict, List, Optional, Any

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

    # Find column start positions from separator line (start of each dash group)
    positions = []
    in_separator = False
    for i, char in enumerate(separator):
        if char == "-" and not in_separator:
            positions.append(i)
            in_separator = True
        elif char != "-" and in_separator:
            in_separator = False

    if len(positions) < len(fields):
        return []

    # Parse each data line using column positions
    results = []
    for line in lines[header_index + 3:]:
        # Extract fields using positions
        try:
            port = line[positions[0]:positions[1]].strip()
            if not port.startswith(("0/", "1/", "g")):  # Only add if we have a valid port number
                continue

            # Extract values using positions
            values = {}
            for i, field in enumerate(fields):
                start = positions[i]
                end = positions[i + 1] if i + 1 < len(positions) else len(line)
                value = line[start:end].strip() if start < len(line) else ""
                values[field] = value

            results.append(values)
        except (ValueError, IndexError):
            continue

    return results

def parse_interfaces_ip(output: str) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    """Parse interface IP addresses from 'show ip interface brief'.
    
    Args:
        output: Command output to parse
        
    Returns:
        Dictionary of interfaces and their IP addresses:
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
            
    Example:
        >>> output = '''
        ... Interface    State  IP Address      IP Mask         TYPE            Method
        ... -----------  -----  --------------- --------------- --------------- ---------------
        ... vlan 1       Up     10.10.10.17     255.255.255.0   Primary         Manual
        ... vlan 50      Up     10.10.50.17     255.255.255.0   Primary         Manual
        ... '''
        >>> parse_interfaces_ip(output)
        {
            "vlan1": {
                "ipv4": {
                    "10.10.10.17": {
                        "prefix_length": 24
                    }
                },
                "ipv6": {}
            },
            "vlan50": {
                "ipv4": {
                    "10.10.50.17": {
                        "prefix_length": 24
                    }
                },
                "ipv6": {}
            }
        }
    """
    interfaces_ip = {}
    
    # Skip if no output or error
    if not output or "Command not found" in output:
        return interfaces_ip
        
    # Process each line
    for line in output.splitlines():
        line = line.strip()
        
        # Skip empty lines, headers, prompts
        if not line or "Interface" in line or "-" * 5 in line or line.startswith("(M4250"):
            continue
            
        # Split on whitespace and validate fields
        fields = line.split()
        if len(fields) < 4:  # Need at least: interface state ip mask
            continue
            
        # Get interface name (combine first two fields if needed)
        interface = fields[0]
        current_pos = 1
        
        if not interface.startswith("vlan"):
            continue
            
        # Handle "vlan X" format
        if interface == "vlan" and len(fields) > 1 and fields[1].isdigit():
            interface = f"vlan{fields[1]}"
            current_pos = 2
            
        # Get IP and mask (adjusting position based on interface parsing)
        try:
            ip = fields[current_pos + 1].strip()
            if ip == "unassigned":
                continue
                
            mask = fields[current_pos + 2].strip()
            if not all(x.isdigit() for x in mask.split('.')):
                continue
                
            # Convert netmask to prefix length
            prefix_length = sum(bin(int(x)).count('1') for x in mask.split('.'))
            
            # Initialize interface dict if needed
            if interface not in interfaces_ip:
                interfaces_ip[interface] = {"ipv4": {}, "ipv6": {}}
                
            # Add IP address
            interfaces_ip[interface]["ipv4"][ip] = {
                "prefix_length": prefix_length
            }
        except (ValueError, IndexError):
            continue
            
    return interfaces_ip

def parse_ipv6_interfaces(output: str) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
    """Parse IPv6 addresses from 'show ipv6 interface brief'.
    
    Args:
        output: Command output to parse
        
    Returns:
        Dictionary of interfaces and their IPv6 addresses in same format as parse_interfaces_ip
        
    Example:
        >>> output = '''
        ...              Oper.
        ... Interface    Mode     IPv6 Address/Length
        ... -----------  -------- ---------------------------------
        ... vlan 1       Disabled fe80::e246:eeff:fe20:6fd8/64                       [TENT]
        ... vlan 50      Disabled fe80::e246:eeff:fe20:6fd8/64                       [TENT]
        ... '''
        >>> parse_ipv6_interfaces(output)
        {
            "vlan1": {
                "ipv4": {},
                "ipv6": {
                    "fe80::e246:eeff:fe20:6fd8": {
                        "prefix_length": 64
                    }
                }
            },
            "vlan50": {
                "ipv4": {},
                "ipv6": {
                    "fe80::e246:eeff:fe20:6fd8": {
                        "prefix_length": 64
                    }
                }
            }
        }
    """
    interfaces_ip = {}
    
    # Skip if no output or error
    if not output or "Command not found" in output:
        return interfaces_ip
        
    # Process each line
    for line in output.splitlines():
        line = line.strip()
        
        # Skip empty lines, headers, prompts
        if not line or "Interface" in line or "-" * 5 in line or line.startswith("(M4250"):
            continue
            
        # Split on whitespace and validate fields
        fields = line.split()
        if len(fields) < 3:  # Need at least: interface mode address
            continue
            
        # Get interface name (combine first two fields if needed)
        interface = fields[0]
        current_pos = 1
        
        if not interface.startswith("vlan"):
            continue
            
        # Handle "vlan X" format
        if interface == "vlan" and len(fields) > 1 and fields[1].isdigit():
            interface = f"vlan{fields[1]}"
            current_pos = 2
            
        # Skip if no IPv6 address
        ipv6_addr = None
        for field in fields[current_pos:]:
            if "/" in field and "::" in field:
                ipv6_addr = field
                break
                
        if not ipv6_addr:
            continue
            
        # Extract address and prefix length
        try:
            addr, prefix = ipv6_addr.split("/")
            prefix_length = int(prefix)
            
            # Remove [TENT] flag if present
            addr = addr.split()[0]
            
            # Initialize interface dict if needed
            if interface not in interfaces_ip:
                interfaces_ip[interface] = {"ipv4": {}, "ipv6": {}}
                
            # Add IPv6 address
            interfaces_ip[interface]["ipv6"][addr] = {
                "prefix_length": prefix_length
            }
        except (ValueError, IndexError):
            continue
            
    return interfaces_ip
