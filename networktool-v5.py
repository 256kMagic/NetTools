import subprocess
import socket
import threading
import ipaddress
import re
import platform
from queue import Queue
from tqdm import tqdm
import colorama
from colorama import Fore, Style
from mac_vendor_lookup import MacLookup

# Initialize colorama
colorama.init()

# Colors
GREEN = Fore.GREEN
RESET = Style.RESET_ALL

# Initialize MacLookup
mac_lookup = MacLookup()

# Cache for vendor results
VENDOR_CACHE = {}

def get_oui_vendor(mac):
    if not mac:
        return "Unknown"
    
    if mac in VENDOR_CACHE:
        return VENDOR_CACHE[mac]
    
    try:
        vendor = mac_lookup.lookup(mac)
        VENDOR_CACHE[mac] = vendor
        return vendor
    except:
        VENDOR_CACHE[mac] = "Unknown"
        return "Unknown"

def get_mac_address(ip):
    try:
        param = '-n' if platform.system() == "Windows" else '-c'
        subprocess.run(['ping', param, '3', ip], capture_output=True, text=True, timeout=10)
        if platform.system() == "Windows":
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            match = re.search(r"(\S+)\s+([0-9A-Fa-f-]{17})\s+dynamic", result.stdout)
            if match:
                return match.group(2).replace("-", ":")
        else:
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            match = re.search(r"at\s+([0-9A-Fa-f:]{17})", result.stdout, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""
    except subprocess.TimeoutExpired:
        print(f"Ping timeout for {ip} during MAC retrieval")
        return ""
    except Exception as e:
        print(f"MAC retrieval error for {ip}: {str(e)}")
        return ""

def scan_port(ip, port, open_ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        open_ports.append(port)
    sock.close()

def scan_ports(ip):
    common_ports = [21, 22, 23, 80, 443, 445, 3389]
    open_ports = []
    threads = []
    for port in common_ports:
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return sorted(open_ports)

def ping_host(ip, queue):
    try:
        param = '-n' if platform.system() == "Windows" else '-c'
        result = subprocess.run(['ping', param, '3', str(ip)], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and "TTL=" in result.stdout:
            queue.put(str(ip))
        else:
            print(f"Ping failed for {ip}: {result.stdout}")
    except subprocess.TimeoutExpired:
        print(f"Ping timeout for {ip}")
    except FileNotFoundError:
        print(f"Ping error for {ip}: ping command not found")
    except PermissionError:
        print(f"Ping error for {ip}: permission denied")
    except Exception as e:
        print(f"Ping error for {ip}: {str(e)}")

def arp_scan(subnet):
    try:
        print("ICMP scan found no hosts, trying ARP scan...")
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        hosts = set()
        for line in result.stdout.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]{17})", line)
            if match:
                ip = match.group(1)
                try:
                    network = ipaddress.ip_network(subnet, strict=False)
                    if ipaddress.ip_address(ip) in network:
                        hosts.add(ip)
                except ValueError:
                    continue
        return list(hosts)
    except Exception as e:
        print(f"ARP scan failed: {str(e)}")
        return []

def subnet_scanner(subnet):
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        print(f"Scanning subnet {network} for live hosts...")
        
        total_hosts = network.num_addresses - 2
        if total_hosts <= 0:
            print("Subnet too small.")
            return
        
        live_hosts = Queue()
        threads = []
        
        with tqdm(total=total_hosts, desc="Pinging hosts", unit="host") as pbar:
            for ip in network.hosts():
                t = threading.Thread(target=ping_host, args=(str(ip), live_hosts))
                threads.append(t)
                t.start()
                pbar.update(1)
                if len(threads) >= 20:
                    for t in threads:
                        t.join()
                    threads = []
            for t in threads:
                t.join()

        hosts = []
        while not live_hosts.empty():
            hosts.append(live_hosts.get())
        
        if not hosts:
            hosts = arp_scan(subnet)
        
        if not hosts:
            print("No live hosts found after ICMP and ARP scans.")
            return

        print(f"\nFound {len(hosts)} live hosts. Scanning for open ports and MAC addresses...")
        results = []
        
        with tqdm(total=len(hosts), desc="Scanning ports/MAC", unit="host") as pbar:
            for host in hosts:
                open_ports = scan_ports(host)
                if open_ports:
                    mac = get_mac_address(host)
                    vendor = get_oui_vendor(mac)
                    results.append((host, mac if mac else "Unknown", vendor, ", ".join(map(str, open_ports))))
                pbar.update(1)

        if not results:
            print("No live hosts with open ports found.")
            return

        print(f"\n{GREEN}Live Hosts with Open Ports:{RESET}")
        print(f"{'IP Address':<15} {'MAC Address':<20} {'NIC Vendor':<30} {'Open Ports':<20}")
        print(f"{GREEN}{'-' * 85}{RESET}")
        for ip, mac, vendor, ports in results:
            print(f"{GREEN}{ip:<15} {mac:<20} {vendor:<30} {ports:<20}{RESET}")

    except ValueError:
        print("Invalid subnet format! Use CIDR (e.g., 10.0.0.0/24).")

def main():
    subnet = input("Enter subnet (e.g., 10.0.0.0/24): ")
    subnet_scanner(subnet)

if __name__ == "__main__":
    main()