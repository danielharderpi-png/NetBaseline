import socket
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from scapy.all import ARP, Ether, srp, conf, get_if_addr
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from smb.SMBConnection import SMBConnection

# Suppress SSL warnings since most local routers have self-signed, untrusted certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_default_gateway():
    """Reads the local routing table to find the default gateway IP."""
    # 0.0.0.0 represents the default route. Index 2 holds the gateway IP string.
    return conf.route.route("0.0.0.0")[2]

def check_router_gateway(gateway_ip):
    print(f"[*] Testing gateway ({gateway_ip}) for default credentials...")
    default_creds = [
        ("admin", "admin"), 
        ("admin", "password"), 
        ("admin", ""), 
        ("root", "root")
    ]
    
    protocols = ["http", "https"]
    
    for proto in protocols:
        url = f"{proto}://{gateway_ip}"
        try:
            # 1. Ping the router to see how it responds
            resp = requests.get(url, timeout=2, verify=False)
            
            # 2. ONLY attempt a login if the router throws a 401 Unauthorized error
            if resp.status_code == 401:
                for user, pwd in default_creds:
                    auth_resp = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=2, verify=False)
                    
                    # 3. If the 401 changes to a 200 OK, the credentials actually worked
                    if auth_resp.status_code == 200:
                        return f"[CRITICAL] Router access granted on {url} with '{user}':'{pwd}'"
        except requests.exceptions.RequestException:
            pass
            
    return "[+] Gateway appears secure against basic default credential attacks."

def scan_subnet(target_ip):
    print(f"[*] Sweeping subnet: {target_ip}...")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    mac_db = MacLookup()
    devices = []
    
    for sent, received in result:
        mac = received.hwsrc
        try:
            vendor = mac_db.lookup(mac)
        except VendorNotFoundError:
            vendor = "Unknown Vendor"
            
        devices.append({'ip': received.psrc, 'mac': mac, 'vendor': vendor})
        
    return devices

def check_critical_ports(ip):
    target_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP"}
    open_ports = []
    
    for port, service in target_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0) 
        
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(f"{port} ({service})")
        except socket.error:
            pass
        finally:
            sock.close()
            
    return open_ports

def check_anonymous_smb(ip):
    conn = SMBConnection('', '', 'scanner_tool', 'target_machine', use_ntlm_v2=True, is_direct_tcp=True)
    exposed_shares = []
    
    try:
        if conn.connect(ip, 445, timeout=1.5):
            shares = conn.listShares(timeout=1.5)
            for share in shares:
                exposed_shares.append(share.name)
        conn.close()
    except Exception:
        pass
        
    return exposed_shares

if __name__ == "__main__":
    # --- 1. Identify Environment ---
    local_ip = get_if_addr(conf.iface)
    gateway_ip = get_default_gateway()
    subnet = ".".join(local_ip.split('.')[:-1]) + ".0/24"
    
    print("-" * 65)
    print(f"Local IP: {local_ip}")
    print(f"Target Subnet: {subnet}")
    print("-" * 65)
    
    # --- 2. Audit the Gateway ---
    gateway_result = check_router_gateway(gateway_ip)
    print(gateway_result)
    print("-" * 65)
    
    # --- 3. Sweep the Network ---
    found_devices = scan_subnet(subnet)
    print(f"\n[+] Discovered {len(found_devices)} live devices.")
    print("-" * 65)
    
    for device in found_devices:
        print(f"Target: {device['ip']:<15} | Vendor: {device['vendor']:<20}")
        exposed_services = check_critical_ports(device['ip'])
        
        if exposed_services:
            print("    [!] WARNING - Exposed Services:")
            for service in exposed_services:
                print(f"        -> Port {service}")
                
                if "445 (SMB)" in service:
                    shares = check_anonymous_smb(device['ip'])
                    if shares:
                        print("           [CRITICAL] Anonymous Null Session Allowed!")
                        print(f"           Exposed Shares: {', '.join(shares)}")
                    else:
                        print("           [+] SMB is locked down (Anonymous access denied).")
        else:
            print("    [+] No critical ports exposed.")
        print("-" * 65)