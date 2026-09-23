import socket
import requests
from requests.auth import HTTPBasicAuth
import urllib3
import re
from scapy.all import ARP, Ether, srp, conf, get_if_addr
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from smb.SMBConnection import SMBConnection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_default_gateway():
    return conf.route.route("0.0.0.0")[2]

def check_router_gateway(gateway_ip):
    default_creds = [("admin", "admin"), ("admin", "password"), ("admin", ""), ("root", "root")]
    protocols = ["http", "https"]
    
    for proto in protocols:
        url = f"{proto}://{gateway_ip}"
        try:
            resp = requests.get(url, timeout=2, verify=False)
            if resp.status_code == 401:
                for user, pwd in default_creds:
                    auth_resp = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=2, verify=False)
                    if auth_resp.status_code == 200:
                        return f"[POTENTIAL EXPOSURE] Default router credentials accepted ('{user}':'{pwd}')"
        except requests.exceptions.RequestException:
            pass
    return "[NO FINDINGS] Router did not accept common default credentials."

def scan_subnet(target_ip):
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
            vendor = "Unknown Manufacturer"
        devices.append({'ip': received.psrc, 'mac': mac, 'vendor': vendor})
    return devices

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Hostname"

def grab_http_title(ip, port):
    proto = "https" if port == 443 or port == 8443 else "http"
    try:
        resp = requests.get(f"{proto}://{ip}:{port}", timeout=1.0, verify=False)
        match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    except:
        pass
    return None

def grab_banner(ip, port):
    """Tier 4 Feature: Connects to a raw socket to extract software versions."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((ip, port))
        
        if port in [80, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner:
            return banner.split('\n')[0][:50]
    except:
        pass
    return None

def check_anonymous_smb(ip):
    conn = SMBConnection('', '', 'scanner', 'target', use_ntlm_v2=True, is_direct_tcp=True)
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

def classify_device(vendor, hostname, open_ports):
    v_lower = vendor.lower()
    h_lower = hostname.lower()
    
    if 3389 in open_ports:
        return "Windows Workstation/Server", "High"
    if 554 in open_ports or "camera" in h_lower or "dahua" in v_lower or "hikvision" in v_lower:
        return "IP Camera / Surveillance", "High"
    if 631 in open_ports or "printer" in h_lower or "hp" in v_lower or "epson" in v_lower:
        return "Network Printer", "High"
    if "apple" in v_lower:
        return "Apple Device", "High"
    if "synology" in v_lower or "qnap" in v_lower:
        return "Network Attached Storage (NAS)", "High"
    if "unknown" in v_lower:
        return "Unknown IoT / Embedded Device", "Low"
        
    return "Network Connected Device", "Low"

def deep_scan_device(ip):
    # Uncompromised Mode: All ports, all the time.
    target_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 
        139: "NetBIOS", 161: "SNMP", 443: "HTTPS", 445: "SMB", 
        554: "RTSP", 631: "IPP", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    
    open_ports = {}
    hostname = get_hostname(ip)
    
    for port, service in target_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) 
        if sock.connect_ex((ip, port)) == 0:
            open_ports[port] = {'service': service, 'details': None, 'banner': None}
        sock.close()
        
    # Contextual Enrichment & Banner Grabbing
    for port in list(open_ports.keys()):
        if port in [80, 443, 8080, 8443]:
            title = grab_http_title(ip, port)
            if title: open_ports[port]['details'] = f"Web Title: {title}"
            
        if port == 445:
            shares = check_anonymous_smb(ip)
            open_ports[445]['details'] = f"Anonymous Access: {', '.join(shares)}" if shares else "No null-session exposure"
            
        # Always attempt to grab software versions on open ports
        banner = grab_banner(ip, port)
        if banner:
            open_ports[port]['banner'] = banner
                
    return {'hostname': hostname, 'open_ports': open_ports}