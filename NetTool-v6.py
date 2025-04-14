import subprocess
import ipaddress
import re
from mac_vendor_lookup import MacLookup
from colorama import init, Fore
from tqdm import tqdm
import nmap

# Initialize colorama
init()
mac_lookup = MacLookup()

# Optional: Update vendor database at startup (uncomment if needed)
# try:
#     mac_lookup.update_vendors()
# except Exception as e:
#     print(f"{Fore.GREEN}Warning: Failed to update vendor database: {e}{Fore.RESET}")

def ping_host(ip):
    """Ping a host to check if it's live."""
    try:
        output = subprocess.run(["ping", "-n", "1", str(ip)], capture_output=True, text=True)
        return "TTL=" in output.stdout
    except:
        return False

def get_mac(ip):
    """Retrieve MAC address from ARP cache."""
    try:
        output = subprocess.run(["arp", "-a", str(ip)], capture_output=True, text=True)
        # Match MAC address format (e.g., 00-50-56-C0-00-01 or 00:50:56:C0:00:01)
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

def scan_ports_nmap(ip):
    """Scan ports using Nmap with service detection."""
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
        return [], [f"Error: {str(e)}"]

def scan_subnet(subnet):
    """Scan subnet for live hosts, MACs, and ports."""
    network = ipaddress.ip_network(subnet)
    live_hosts = []
    
    # Scan hosts silently
    for ip in tqdm(network.hosts(), total=network.num_addresses-2, desc=f"{Fore.GREEN}Scanning hosts{Fore.RESET}", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        if ping_host(ip):
            live_hosts.append(str(ip))
    
    results = []
    # Scan ports and MACs
    for ip in tqdm(live_hosts, desc=f"{Fore.GREEN}Scanning ports/MAC{Fore.RESET}", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        mac = get_mac(ip)
        # Validate MAC format before lookup
        if mac and re.match(r"^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$", mac):
            try:
                vendor = mac_lookup.lookup(mac)
            except:
                vendor = "Unknown"
        else:
            vendor = "Unknown"
        ports, services = scan_ports_nmap(ip)
        if ports:  # Only include hosts with open ports
            results.append({"ip": ip, "mac": mac, "vendor": vendor, "ports": ports, "services": services})
    
    # Display results
    if results:
        print(f"{Fore.GREEN}\nLive Hosts with Open Ports:{Fore.RESET}")
        print(f"{Fore.GREEN}{'IP Address':<15} {'MAC Address':<18} {'NIC Vendor':<17} {'Open Ports':<17} {'Services':<30}{Fore.RESET}")
        print(f"{Fore.GREEN}{'-' * 97}{Fore.RESET}")
        for result in results:
            ports_str = ", ".join(map(str, result['ports'])) if result['ports'] else "None"
            services_str = ", ".join(result['services']) if result['services'] else "None"
            print(f"{Fore.GREEN}{result['ip']:<15} {result['mac'] or 'None':<18} {result['vendor']:<17} {ports_str:<17} {services_str:<30}{Fore.RESET}")
    else:
        print(f"{Fore.GREEN}No live hosts with open ports found.{Fore.RESET}")

if __name__ == "__main__":
    print(f"{Fore.GREEN}NetTools Subnet Scanner{Fore.RESET}")
    subnet = input(f"{Fore.GREEN}Enter subnet (e.g., 10.0.0.0/24): {Fore.RESET}")
    try:
        scan_subnet(subnet)
    except ValueError:
        print(f"{Fore.GREEN}Invalid subnet format. Use CIDR (e.g., 10.0.0.0/24).{Fore.RESET}")