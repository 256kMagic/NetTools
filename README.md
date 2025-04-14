# NetTools-v1

A Python-based subnet scanner to discover live hosts, retrieve MAC addresses, identify NIC vendors, and scan for open ports with service detection.

## Overview

`nettool-v8.py` is a command-line tool designed for network reconnaissance on Windows. It performs:
- **Ping Sweep**: Identifies live hosts in a subnet using parallelized pings.
- **MAC Address Retrieval**: Extracts MAC addresses from the ARP cache.
- **Vendor Lookup**: Maps MAC addresses to vendors using a local `mac_vendors.txt` file in IEEE OUI format.
- **Port Scanning**: Uses Nmap to scan common ports (21, 22, 23, 80, 443, 445, 3389) and detect services.

The tool uses a synchronous approach for vendor lookups to ensure reliability, avoiding async-related issues (e.g., event loop conflicts).

## Features
- Fast parallel scanning with `ThreadPoolExecutor` (50 workers for ping, 10 for MAC/port scans).
- Robust MAC vendor lookup from `mac_vendors.txt`, supporting IEEE OUI format (e.g., `28-6F-B9 (hex) Nokia Shanghai Bell Co., Ltd.`).
- Nmap integration for accurate port and service detection.
- User-friendly progress bars via `tqdm` and colored output with `colorama`.
- Handles encoding issues in `mac_vendors.txt` (UTF-8 with Latin1 fallback).
- Filters results to show only hosts with open ports or scan errors.

## Requirements
- **Python**: 3.6+
- **Dependencies**:
  - `colorama`: Colored console output.
  - `tqdm`: Progress bars.
  - `python-nmap`: Nmap integration.
  - Install via: `pip install colorama tqdm python-nmap`
- **Nmap**: Must be installed and added to PATH.
  - Download: [nmap.org](https://nmap.org/download.html)
- **Windows**: Run as Administrator for ARP and Nmap access.
- **`mac_vendors.txt`**: Local file with MAC vendor data in IEEE OUI format (see below).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/256kmagic/NetTools-v1.git
   cd NetTools-v1
