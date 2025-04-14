# NetTools

A lightweight Python subnet scanner to discover live hosts, MAC addresses, NIC vendors, and open ports on your network.

## About

`network_tools.py` is a command-line tool for network exploration. It scans a subnet (e.g., `10.0.0.0/24`) to:
- Find live hosts using ICMP ping, with ARP scanning as a fallback.
- Retrieve MAC addresses from the ARP cache.
- Identify NIC vendors using an offline database.
- Check for open common ports (FTP, SSH, Telnet, HTTP, HTTPS, SMB, RDP).
- Display results in a clean, color-coded table with progress bars.

Perfect for network administrators or enthusiasts wanting to map local networks quickly.

## Features
- **Host Discovery**: Detects live devices via ICMP (`ping`) or ARP if ping is blocked.
- **MAC Address Lookup**: Pulls MACs from ARP (admin privileges required).
- **Vendor Identification**: Matches MACs to vendors (e.g., "VMware, Inc.") using `mac-vendor-lookup`.
- **Port Scanning**: Scans ports 21, 22, 23, 80, 443, 445, 3389.
- **Visual Output**: Green table with `colorama` and progress bars via `tqdm`.
- **Cross-Platform**: Works on Windows and Linux (Windows-focused).

## Prerequisites
- **Python**: 3.6 or later (tested with 3.13).
- **Dependencies**:
  - `tqdm` (progress bars)
  - `colorama` (colored output)
  - `mac-vendor-lookup` (vendor database)
- **Git**: To clone the repository.
- **Admin Privileges**: Needed for ARP-based MAC retrieval on Windows.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/256kMagic/NetTools.git
   cd NetTools
