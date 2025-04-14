import subprocess
import ipaddress
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore
from tqdm import tqdm
import nmap

# Initialize colorama
init()

def load_mac_db(file_path="mac_vendors.txt"):
    """Load MAC vendor database from IEEE OUI format file with robust encoding."""
    mac_db = {}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith("#") and "(hex)" in line:
                    try:
                        # Match lines like "28-6F-B9 (hex) Nokia Shanghai Bell Co., Ltd."
                        match = re.match(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                        if match:
                            oui, vendor = match.groups()
                            # Normalize OUI to XX:XX:XX
                            oui = oui.replace("-", ":").upper()
                            mac_db[oui] = vendor.strip()
                        else:
                            print(f"{Fore.GREEN}Warning: Skipping malformed line {line_number}: {line}{Fore.RESET}")
                    except Exception as e:
                        print(f"{Fore.GREEN}Warning: Error parsing line {line_number}: {line} ({str(e)}){Fore.RESET}")
        if mac_db:
            print(f"{Fore.GREEN}Loaded {len(mac_db)} MAC vendors from {file_path}{Fore.RESET}")
        else:
            print(f"{Fore.GREEN}Warning: No valid OUI entries found in {file_path}{Fore.RESET}")
        return mac_db
    except FileNotFoundError:
        print(f"{Fore.GREEN}Error: {file_path} not found. All vendors will be Unknown.{Fore.RESET}")
        return {}
    except UnicodeDecodeError as e:
        print(f"{Fore.GREEN}Error: Failed to decode {file_path} ({str(e)}). Trying latin1 encoding.{Fore.RESET}")
        # Fallback to latin1 encoding
        try:
            with open(file_path, "r", encoding="latin1") as f:
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#") and "(hex)" in line:
                        try:
                            match = re.match(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                            if match:
                                oui, vendor = match.groups()
                                oui = oui.replace("-", ":").upper()
                                mac_db[oui] = vendor.strip()
                            else:
                                print(f"{Fore.GREEN}Warning: Skipping malformed line {line_number}: {line}{Fore.RESET}")
                        except Exception as e:
                            print(f"{Fore.GREEN}Warning: Error parsing line {line_number}: {line} ({str(e)}){Fore.RESET}")
            if mac_db:
                print(f"{Fore.GREEN}Loaded {len(mac_db)} MAC vendors from {file_path} (latin1){Fore.RESET}")
            else:
                print(f"{Fore.GREEN}Warning: No valid OUI entries found in {file_path} (latin1){Fore.RESET}")
            return mac_db
        except Exception as e:
            print(f"{Fore.GREEN}Error: Failed to parse {file_path} with latin1: {str(e)}. All vendors will be Unknown.{Fore.RESET}")
            return {}
    except Exception as e:
        print(f"{Fore.GREEN}Error parsing {file_path}: {str(e)}. All vendors will be Unknown.{Fore.RESET}")
        return {}

def lookup_vendor(mac, mac_db):
    """Look up vendor by MAC prefix synchronously."""
    prefix = mac[:8].upper()
    vendor = mac_db.get(prefix, "Unknown")
    print(f"{Fore.GREEN}Looking up {mac} (prefix {prefix}): {vendor}{Fore.RESET}")
    return vendor

def ping_host(ip):
    """Ping a host to check if it's live."""
    try:
        output = subprocess.run(["ping", "-n", "1", str(ip)], capture_output=True, text=True)
        return str(ip) if "TTL=" in output.stdout else None
    except:
        return None

def get_mac(ip):
    """Retrieve MAC address from ARP cache."""
    try:
        output = subprocess.run(["arp", "-a", str(ip)], capture_output=True, text=True)
        mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
        for line in output.stdout.splitlines():
            if str(ip) in line:
                match = re.search(mac_pattern, line)
                if match:
                    mac = match.group(0).replace("-", ":")
                    return mac.upper()
        return None
    except:
        return None

def check_nmap():
    """Verify Nmap is installed."""
    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        print(f"{Fore.GREEN}Error: Nmap not found. Please install from https://nmap.org/download.html and add to PATH.{Fore.RESET}")
        return False
    return True

def scan_ports_nmap(ip):
    """Scan ports using Nmap with service detection."""
    if not check_nmap():
        return [], ["Nmap not installed"]
    
    ports = [21, 22, 23, 80, 443, 445, 3389]
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments=f"-p {','.join(map(str, ports))} -sV --open")
        open_ports = []
        services = []
        if ip in nm.all_hosts():
            for port in nm[ip].all_tcp():
                if nm[ip]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
                    service = nm[ip]['tcp'][port].get('name', 'unknown')
                    version = nm[ip]['tcp'][port].get('version', '')
                    services.append(f"{service} {version}".strip())
        return open_ports, services
    except Exception as e:
        return [], [f"Nmap error: {str(e)}"]

def scan_host(ip):
    """Scan a single host for MAC and ports (vendor lookup done separately)."""
    mac = get_mac(ip)
    ports, services = scan_ports_nmap(ip)
    return {"ip": ip, "mac": mac, "ports": ports, "services": services}

def scan_subnet(subnet):
    """Scan subnet for live hosts, MACs, and ports with parallel execution."""
    try:
        network = ipaddress.ip_network(subnet)
    except ValueError:
        print(f"{Fore.GREEN}Invalid subnet format. Use CIDR (e.g., 10.0.0.0/24).{Fore.RESET}")
        return

    # Load MAC vendor database
    mac_db = load_mac_db()

    # Parallel ping sweep
    live_hosts = []
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(tqdm(
            executor.map(ping_host, hosts),
            total=len(hosts),
            desc=f"{Fore.GREEN}Scanning hosts{Fore.RESET}",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
        ))
        live_hosts = [ip for ip in results if ip is not None]

    # Parallel MAC and port scanning
    results = []
    if live_hosts:
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(tqdm(
                executor.map(scan_host, live_hosts),
                total=len(live_hosts),
                desc=f"{Fore.GREEN}Scanning ports/MAC{Fore.RESET}",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
            ))

        # Lookup vendors for valid MACs synchronously
        macs = [r["mac"] for r in results if r["mac"] and re.match(r"^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$", r["mac"])]
        print(f"{Fore.GREEN}MACs to lookup: {macs}{Fore.RESET}")
        vendors = [lookup_vendor(mac, mac_db) for mac in macs]
        
        # Assign vendors to results
        mac_to_vendor = dict(zip(macs, vendors))
        for result in results:
            result["vendor"] = mac_to_vendor.get(result["mac"], "Unknown") if result["mac"] else "Unknown"

        # Filter hosts with ports or errors
        results = [r for r in results if r['ports'] or r['services']]

    # Display results
    if results:
        print(f"{Fore.GREEN}\nLive Hosts with Open Ports:{Fore.RESET}")
        print(f"{Fore.GREEN}{'IP Address':<15} {'MAC Address':<18} {'NIC Vendor':<30} {'Open Ports':<17} {'Services':<30}{Fore.RESET}")
        print(f"{Fore.GREEN}{'-' * 110}{Fore.RESET}")
        for result in sorted(results, key=lambda x: x['ip']):  # Sort by IP for consistency
            ports_str = ", ".join(map(str, result['ports'])) if result['ports'] else "None"
            services_str = ", ".join(result['services']) if result['services'] else "None"
            print(f"{Fore.GREEN}{result['ip']:<15} {result['mac'] or 'None':<18} {result['vendor']:<30} {ports_str:<17} {services_str:<30}{Fore.RESET}")
    else:
        print(f"{Fore.GREEN}No live hosts with open ports found.{Fore.RESET}")

if __name__ == "__main__":
    print(f"{Fore.GREEN}NetTools Subnet Scanner{Fore.RESET}")
    subnet = input(f"{Fore.GREEN}Enter subnet (e.g., 10.0.0.0/24): {Fore.RESET}")
    scan_subnet(subnet)