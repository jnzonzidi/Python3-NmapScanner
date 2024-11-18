#!/usr/bin/python3

import nmap

# Initialize the Nmap PortScanner
scanner = nmap.PortScanner()

print("Welcome, this is a simple Nmap automation tool")
print("<----------------------------------------------------->")

# Input for target IP address
ip_addr = input("Please enter the IP address you want to scan: ").strip()
print(f"The IP you entered is: {ip_addr}")

# Scan type options
resp = input(
    """\nPlease enter the type of scan you want to run:
    1) SYN ACK Scan
    2) UDP Scan
    3) Comprehensive Scan 
Your choice: """
).strip()

# Mapping user response to Nmap commands and protocols
resp_dict = {
    '1': ['-v -sS', 'tcp'],  # SYN Scan
    '2': ['-v -sU', 'udp'],  # UDP Scan
    '3': ['-v -sS -sV -sC -A -O', 'tcp']  # Comprehensive Scan
}

# Validate user input
if resp not in resp_dict:
    print("Invalid option selected. Please choose 1, 2, or 3.")
else:
    # Display Nmap version
    print(f"Nmap Version: {scanner.nmap_version()}")

    # Execute the selected scan
    print("\nScanning in progress...")
    scanner.scan(ip_addr, "1-1024", resp_dict[resp][0])  # Scan ports 1-1024

    # Display scan results
    print("\nScan Info:", scanner.scaninfo())
    if 'up' in scanner[ip_addr].state():
        print(f"Scanner Status: {scanner[ip_addr].state()}")
        print(f"Protocols: {scanner[ip_addr].all_protocols()}")

        # Display open ports
        protocol = resp_dict[resp][1]
        if protocol in scanner[ip_addr]:
            print(f"Open Ports ({protocol}): {list(scanner[ip_addr][protocol].keys())}")
        else:
            print(f"No open {protocol} ports found.")
    else:
        print("The host is down or unresponsive.")
