import os
import customtkinter as ctk
from customtkinter import filedialog
import threading
import concurrent.futures
from PIL import Image

from scanner import get_default_gateway, check_router_gateway, scan_subnet, deep_scan_device, classify_device
from scapy.all import conf, get_if_addr
from report import build_pdf_report

# ---------------------------------------------------------
# TRANSLATOR ENGINE
# ---------------------------------------------------------
TRANSLATOR = {
    21: {"title": "FTP Exposed", "desc": "FTP transmits passwords and data in clear text without encryption.", "rec": "Disable FTP. Implement SFTP if required.", "color": "#F87171",
         "layman": "It's like sending a postcard in the mail. Anyone handling it can read the contents. It transmits passwords in plain, readable text."},
    22: {"title": "SSH Exposed", "desc": "Secure Shell administration is active.", "rec": "Ensure strong passwords or key-based authentication are enforced.", "color": "#3B82F6",
         "layman": "A direct 'back door' for IT to manage the system. If the password is weak or factory-default, hackers can walk right in and take full control."},
    23: {"title": "Telnet Detected", "desc": "Telnet uses zero encryption, making it highly vulnerable to packet sniffing.", "rec": "Disable Telnet. Replace with SSH.", "color": "#F87171",
         "layman": "A very old, unencrypted connection. It's like having a private conversation over a loud megaphone where anyone listening can hear your passwords."},
    53: {"title": "DNS Service", "desc": "Device is acting as a DNS resolver.", "rec": "Ensure it is not exposed externally to prevent DNS amplification attacks.", "color": "#A1A1AA",
         "layman": "The internet's phonebook. If left unprotected, bad actors can hijack it to launch massive web attacks against other companies."},
    80: {"title": "Unencrypted Web Interface", "desc": "Management page is accessible over standard HTTP.", "rec": "Ensure logins are not performed over this connection.", "color": "#FBBF24",
         "layman": "A web login screen missing the 'padlock' icon. Anything typed here can be intercepted by someone snooping on the network."},
    139: {"title": "NetBIOS Service", "desc": "Legacy Windows networking protocol detected.", "rec": "Disable if legacy support is not strictly required.", "color": "#A1A1AA",
         "layman": "An old Windows sharing feature that broadcasts too much information about the computer to anyone listening on the network."},
    161: {"title": "SNMP Agent Active", "desc": "SNMP is commonly used for monitoring, but v1/v2 transmit community strings in plain text.", "rec": "Ensure default community strings ('public'/'private') are changed.", "color": "#FBBF24",
         "layman": "A monitoring tool that acts like an open intercom. It often hands out system secrets without asking for a real password."},
    443: {"title": "Secure Web Interface", "desc": "Management page via HTTPS.", "rec": "Ensure default passwords have been changed.", "color": "#3B82F6",
         "layman": "A secure web login screen. The connection is safe, but we must ensure it isn't using a default factory password like 'admin'."},
    445: {"title": "File Sharing (SMB)", "desc": "Network file sharing is active. {details}", "rec": "Disable anonymous/guest access in sharing settings.", "color": "#F87171",
         "layman": "Network file sharing. If misconfigured, it's like leaving a company filing cabinet unlocked in the lobby for anyone to rummage through."},
    554: {"title": "RTSP Video Stream", "desc": "Device is broadcasting a video or camera feed.", "rec": "Ensure camera feeds are authenticated and segmented from guest networks.", "color": "#3B82F6",
         "layman": "A live video/camera feed. If not properly secured with a password, anyone on the network can watch the security stream."},
    631: {"title": "Network Printer (IPP)", "desc": "Internet Printing Protocol exposed.", "rec": "Standard for office printers. Monitor for unauthorized external access.", "color": "#A1A1AA",
         "layman": "Printer sharing. Hackers can sometimes abuse exposed printers to get a foothold into the rest of the business computers."},
    3389: {"title": "Remote Desktop (RDP)", "desc": "RDP is a primary target for ransomware lateral movement.", "rec": "Restrict RDP access to specific IT administration IP addresses only.", "color": "#FBBF24",
         "layman": "A remote-control feature for the whole computer. It is the #1 way ransomware gangs break into business networks."},
    8080: {"title": "Alternate Web Interface", "desc": "Secondary web application detected.", "rec": "Review web application for security requirements.", "color": "#FBBF24",
         "layman": "A secondary, unencrypted login screen. Often used by forgotten software or testing environments."},
    8443: {"title": "Alternate Secure Web", "desc": "Secondary HTTPS application detected.", "rec": "Review web application for security requirements.", "color": "#3B82F6",
         "layman": "A secondary secure login screen. We need to ensure it is actively managed and updated."}
}

def get_asset(relative_path):
    if os.path.exists(relative_path): return relative_path
    nested = os.path.join("NetBaseline", relative_path)
    if os.path.exists(nested): return nested
    return None

class AuditGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetBaseline")
        self.geometry("1200x850")
        self.configure(fg_color="#09090B") 
        ctk.set_appearance_mode("dark")
        self.audit_data = None
        self.card_widgets = [] 
        
        # Telemetry State Trackers
        self.metric_hosts = 0
        self.metric_ports = 0
        self.metric_risks = 0

        # --- WINDOW ICON & SPLASH SCREEN ---
        ico_path = get_asset("logo/NetBaseline.ico")
        if ico_path:
            try: self.iconbitmap(ico_path)
            except Exception: pass

        self.withdraw()
        self.splash = ctk.CTkToplevel(self)
        self.splash.overrideredirect(True) 
        self.splash.configure(fg_color="#09090B")
        self.splash.attributes("-topmost", True)

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        splash_w, splash_h = 400, 400
        x = (screen_w // 2) - (splash_w // 2)
        y = (screen_h // 2) - (splash_h // 2)
        self.splash.geometry(f"{splash_w}x{splash_h}+{x}+{y}")

        splash_png = get_asset("logo/png/256.png")
        if splash_png:
            try:
                img = ctk.CTkImage(Image.open(splash_png), size=(180, 180))
                lbl = ctk.CTkLabel(self.splash, image=img, text="")
                lbl.pack(expand=True, pady=(60, 10))
                loading_lbl = ctk.CTkLabel(self.splash, text="INITIALIZING SYSTEM...", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#3B82F6")
                loading_lbl.pack(pady=(0, 60))
            except Exception: pass

        self.after(2200, self.end_splash)

        # --- MAIN GUI SETUP ---
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.sidebar_frame = ctk.CTkFrame(self, width=290, corner_radius=0, fg_color="#18181B", border_width=1, border_color="#27272A")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        # Row 6 will act as our empty spacer, pushing everything below it to the bottom
        self.sidebar_frame.grid_rowconfigure(6, weight=1) 

        icon_png = get_asset("logo/png/32.png")
        if icon_png:
            try:
                icon_img = ctk.CTkImage(Image.open(icon_png), size=(26, 26))
                self.logo_label = ctk.CTkLabel(self.sidebar_frame, image=icon_img, text=" NetBaseline", compound="left", font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"), text_color="#FAFAFA")
            except Exception:
                self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="NetBaseline", font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"), text_color="#FAFAFA")
        else:
            self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="NetBaseline", font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"), text_color="#FAFAFA")
            
        self.logo_label.grid(row=0, column=0, padx=24, pady=(32, 4), sticky="w")
        
        self.subtitle_label = ctk.CTkLabel(self.sidebar_frame, text="Enterprise Security Auditor", font=ctk.CTkFont(family="Segoe UI", size=13), text_color="#A1A1AA")
        self.subtitle_label.grid(row=1, column=0, padx=24, pady=(0, 32), sticky="w")

        self.scan_button = ctk.CTkButton(self.sidebar_frame, text="Run Assessment", command=self.start_scan_thread, height=40, corner_radius=8, font=ctk.CTkFont(weight="bold"), fg_color="#FAFAFA", text_color="#09090B", hover_color="#E4E4E7")
        self.scan_button.grid(row=2, column=0, padx=24, pady=8, sticky="ew")

        self.progress_bar = ctk.CTkProgressBar(self.sidebar_frame, height=6, progress_color="#3B82F6", fg_color="#27272A")
        self.progress_bar.grid(row=3, column=0, padx=24, pady=16, sticky="ew")
        self.progress_bar.set(0)
        
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Ready", font=ctk.CTkFont(size=12), text_color="#A1A1AA")
        self.status_label.grid(row=4, column=0, padx=24, sticky="nw")

        # --- LIVE TELEMETRY DASHBOARD (The "Fun" middle area) ---
        self.telemetry_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="#09090B", corner_radius=8, border_width=1, border_color="#27272A")
        self.telemetry_frame.grid(row=5, column=0, padx=24, pady=(24, 0), sticky="ew")
        self.telemetry_frame.grid_columnconfigure(1, weight=1)

        self.lbl_host_title = ctk.CTkLabel(self.telemetry_frame, text="Active Hosts", font=ctk.CTkFont(size=12), text_color="#A1A1AA")
        self.lbl_host_title.grid(row=0, column=0, padx=16, pady=(16, 4), sticky="w")
        self.lbl_host_val = ctk.CTkLabel(self.telemetry_frame, text="0", font=ctk.CTkFont(size=13, weight="bold"), text_color="#FAFAFA")
        self.lbl_host_val.grid(row=0, column=1, padx=16, pady=(16, 4), sticky="e")

        self.lbl_port_title = ctk.CTkLabel(self.telemetry_frame, text="Open Ports", font=ctk.CTkFont(size=12), text_color="#A1A1AA")
        self.lbl_port_title.grid(row=1, column=0, padx=16, pady=4, sticky="w")
        self.lbl_port_val = ctk.CTkLabel(self.telemetry_frame, text="0", font=ctk.CTkFont(size=13, weight="bold"), text_color="#3B82F6")
        self.lbl_port_val.grid(row=1, column=1, padx=16, pady=4, sticky="e")

        self.lbl_risk_title = ctk.CTkLabel(self.telemetry_frame, text="Risks Detected", font=ctk.CTkFont(size=12), text_color="#A1A1AA")
        self.lbl_risk_title.grid(row=2, column=0, padx=16, pady=(4, 16), sticky="w")
        self.lbl_risk_val = ctk.CTkLabel(self.telemetry_frame, text="0", font=ctk.CTkFont(size=13, weight="bold"), text_color="#A1A1AA")
        self.lbl_risk_val.grid(row=2, column=1, padx=16, pady=(4, 16), sticky="e")

        # --- BOTTOM CONTROLS ---
        self.pdf_button = ctk.CTkButton(self.sidebar_frame, text="Export PDF Report", command=self.save_pdf, state="disabled", height=40, corner_radius=8, fg_color="transparent", border_width=1, border_color="#3F3F46", text_color="#FAFAFA", hover_color="#27272A")
        self.pdf_button.grid(row=7, column=0, padx=24, pady=(24, 16), sticky="ew")

        self.filter_var = ctk.BooleanVar(value=False)
        self.filter_switch = ctk.CTkSwitch(self.sidebar_frame, text="Show Flagged Items Only", variable=self.filter_var, command=self.apply_filter, font=ctk.CTkFont(size=12), text_color="#FAFAFA", progress_color="#3B82F6")
        self.filter_switch.grid(row=8, column=0, padx=24, pady=(0, 24), sticky="w")

        # --- OFFICIAL SIGNATURE ---
        signature_text = "Engineered by Daniel Harder\nNetBaseline Security • Est. 2026"
        self.signature_lbl = ctk.CTkLabel(self.sidebar_frame, text=signature_text, font=ctk.CTkFont(size=10), text_color="#52525B", justify="left")
        self.signature_lbl.grid(row=9, column=0, padx=24, pady=(0, 24), sticky="w")

        # --- MAIN VIEW ---
        self.main_scroll = ctk.CTkScrollableFrame(self, fg_color="#09090B", corner_radius=0)
        self.main_scroll.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_scroll.grid_columnconfigure(0, weight=1)

        # ---------------------------------------------------------
        # MAKE SCROLLING SNAPPY (Fixed Math)
        # ---------------------------------------------------------
        def snappy_scroll(event):
            # Default CTk math is (delta / 6). 
            # Dividing by 2 makes it 3x FASTER.
            if abs(event.delta) >= 120: # Windows
                units = int(-(event.delta / 2)) 
            else: # macOS
                units = int(-(event.delta * 3)) 
                
            self.main_scroll._parent_canvas.yview_scroll(units, "units")
            return "break" 
            
        self.bind_all("<MouseWheel>", snappy_scroll)
        # ---------------------------------------------------------

        self.empty_state = ctk.CTkLabel(self.main_scroll, text="Click 'Run Assessment' to perform network discovery.", font=ctk.CTkFont(size=14), text_color="#52525B")
        self.empty_state.grid(row=0, column=0, pady=200)

        self.row_counter = 1

    def end_splash(self):
        self.splash.destroy()
        self.deiconify()

    def start_scan_thread(self):
        self.scan_button.configure(state="disabled", text="Polling...")
        self.pdf_button.configure(state="disabled")
        self.progress_bar.set(0)
        self.card_widgets.clear() 
        
        # Reset Telemetry
        self.metric_hosts = 0
        self.metric_ports = 0
        self.metric_risks = 0
        self.update_telemetry()

        for widget in self.main_scroll.winfo_children():
            widget.destroy()
        self.row_counter = 1
        
        threading.Thread(target=self.run_audit, daemon=True).start()

    def update_status(self, text, progress=None):
        self.status_label.configure(text=text)
        if progress is not None: self.progress_bar.set(progress)
        
    def update_telemetry(self):
        """Updates the live dashboard numbers during the scan."""
        self.lbl_host_val.configure(text=str(self.metric_hosts))
        self.lbl_port_val.configure(text=str(self.metric_ports))
        
        risk_color = "#F87171" if self.metric_risks > 0 else "#A1A1AA"
        self.lbl_risk_val.configure(text=str(self.metric_risks), text_color=risk_color)

    def apply_filter(self):
        show_flagged_only = self.filter_var.get()
        for card_data in self.card_widgets:
            frame = card_data["frame"]
            is_flagged = card_data["flagged"]
            
            if show_flagged_only and not is_flagged:
                frame.grid_forget()
            else:
                frame.grid(row=card_data["row"], column=0, sticky="ew", pady=(0, 12))

    def render_gateway_card(self, ip, result_text):
        card = ctk.CTkFrame(self.main_scroll, fg_color="#18181B", corner_radius=12, border_width=1, border_color="#27272A")
        card.grid(row=self.row_counter, column=0, sticky="ew", pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)
        
        is_warned = "[POTENTIAL EXPOSURE]" in result_text
        self.card_widgets.append({"frame": card, "flagged": is_warned, "row": self.row_counter})
        self.row_counter += 1
        
        header = ctk.CTkLabel(card, text="Perimeter Gateway", font=ctk.CTkFont(size=16, weight="bold"), text_color="#FAFAFA")
        header.grid(row=0, column=0, sticky="w", padx=20, pady=(16, 4))
        
        ip_lbl = ctk.CTkLabel(card, text=ip, font=ctk.CTkFont(size=12), text_color="#A1A1AA")
        ip_lbl.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 16))

        if is_warned:
            warn = ctk.CTkLabel(card, text="Default Credentials Accepted. Router is vulnerable to takeover.", text_color="#F87171", font=ctk.CTkFont(weight="bold"))
            warn.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 16))
        else:
            ok = ctk.CTkLabel(card, text="✓ Gateway is protected against common default passwords.", text_color="#34D399")
            ok.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 16))
            
        if self.filter_var.get() and not is_warned:
            card.grid_forget()

    def render_device_card(self, device, hostname, device_type, open_ports):
        is_flagged = False
        for p, d in open_ports.items():
            if p in TRANSLATOR:
                if p == 445 and d.get('details') and "Anonymous" not in d['details']:
                    continue 
                is_flagged = True
                break

        border_color = "#3F3F46" if is_flagged else "#18181B"
        bg_color = "#18181B" if is_flagged else "#09090B"
        
        card = ctk.CTkFrame(self.main_scroll, fg_color=bg_color, corner_radius=12, border_width=1, border_color=border_color)
        card.grid(row=self.row_counter, column=0, sticky="ew", pady=(0, 12))
        card.grid_columnconfigure(0, weight=1)
        
        self.card_widgets.append({"frame": card, "flagged": is_flagged, "row": self.row_counter})
        self.row_counter += 1

        top_bar = ctk.CTkFrame(card, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 4))
        top_bar.grid_columnconfigure(0, weight=1)

        title_text = f"{device['ip']}  •  {hostname}"
        header = ctk.CTkLabel(top_bar, text=title_text, font=ctk.CTkFont(size=14, weight="bold"), text_color="#FAFAFA" if is_flagged else "#A1A1AA")
        header.grid(row=0, column=0, sticky="w")

        sub_text = f"{device_type} — {device['vendor']}"
        sub = ctk.CTkLabel(card, text=sub_text, font=ctk.CTkFont(size=12), text_color="#71717A")
        sub.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 16))

        findings_frame = ctk.CTkFrame(card, fg_color="transparent")
        findings_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=0)
        findings_frame.grid_columnconfigure(0, weight=1)

        if not open_ports:
            ok = ctk.CTkLabel(findings_frame, text="No in-scope exposure detected.", font=ctk.CTkFont(size=12), text_color="#52525B")
            ok.grid(row=0, column=0, sticky="w", pady=(0, 16))
        else:
            finding_row = 0
            for port, data in open_ports.items():
                if port in TRANSLATOR:
                    t_data = TRANSLATOR[port]
                    title = t_data['title']
                    desc = t_data['desc']
                    rec = t_data['rec']
                    color = t_data['color']
                    
                    if port == 445 and data.get('details'):
                        if "Anonymous" not in data['details']: 
                            title = "Secured File Sharing (SMB)"
                            desc = "Network file sharing is active, but anonymous access is securely blocked."
                            rec = "Good practice: Ensure employee passwords remain strong."
                            color = "#34D399" 
                        else:
                            desc = desc.format(details=data['details'])
                    elif "{details}" in desc:
                         desc = desc.replace("{details}", "")

                    f_frame = ctk.CTkFrame(findings_frame, fg_color="#1F1F22", corner_radius=8)
                    f_frame.grid(row=finding_row, column=0, sticky="ew", pady=(0, 16))
                    f_frame.grid_columnconfigure(0, weight=1)

                    f_title = ctk.CTkLabel(f_frame, text=f"Port {port}: {title}", font=ctk.CTkFont(size=13, weight="bold"), text_color=color)
                    f_title.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))

                    f_desc = ctk.CTkLabel(f_frame, text=desc, font=ctk.CTkFont(size=12), text_color="#D4D4D8", justify="left", wraplength=750)
                    f_desc.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 4))
                    
                    if data.get('banner') or (port in [80, 443, 8080, 8443] and data.get('details')):
                        extra_data = data.get('banner') if data.get('banner') else data.get('details')
                        f_meta = ctk.CTkLabel(f_frame, text=f"Data: {extra_data}", font=ctk.CTkFont(size=12, family="Consolas"), text_color="#FBBF24")
                        f_meta.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 4))
                        rec_row = 3
                    else:
                        rec_row = 2

                    f_rec = ctk.CTkLabel(f_frame, text=rec, font=ctk.CTkFont(size=12, slant="italic"), text_color="#A1A1AA", wraplength=750)
                    f_rec.grid(row=rec_row, column=0, sticky="w", padx=16, pady=(0, 12))
                    
                    finding_row += 1

        details_frame = ctk.CTkFrame(card, fg_color="#18181B" if not is_flagged else "#1F1F22", corner_radius=8)
        details_frame.grid_columnconfigure(0, weight=1)
        
        mac_text = f"Hardware MAC: {device.get('mac', 'Unknown')}"
        mac_lbl = ctk.CTkLabel(details_frame, text=mac_text, font=ctk.CTkFont(size=12, family="Consolas"), text_color="#A1A1AA")
        mac_lbl.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        
        scope_text = "Security Scope: 14 infrastructure ports audited (FTP, SSH, DNS, HTTP/S, SMB, RTSP, RDP...)"
        scope_lbl = ctk.CTkLabel(details_frame, text=scope_text, font=ctk.CTkFont(size=12), text_color="#71717A")
        scope_lbl.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 4))
        
        status_text = "Status: All tested service ports are closed or actively refusing unauthorized connections." if not open_ports else f"Status: {len(open_ports)} exposed services responded to baseline polling."
        status_lbl = ctk.CTkLabel(details_frame, text=status_text, font=ctk.CTkFont(size=12, weight="bold"), text_color="#34D399" if not is_flagged else "#FBBF24")
        status_lbl.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 12))

        if open_ports:
            layman_header = ctk.CTkLabel(details_frame, text="How to explain this to a client:", font=ctk.CTkFont(size=13, weight="bold"), text_color="#FAFAFA")
            layman_header.grid(row=3, column=0, sticky="w", padx=16, pady=(16, 4))
            
            exp_row = 4
            for port, data in open_ports.items():
                if port in TRANSLATOR:
                    title = TRANSLATOR[port]['title']
                    layman_text = TRANSLATOR[port]['layman']
                    
                    if port == 445 and data.get('details') and "Anonymous" not in data['details']:
                        title = "Secured File Sharing"
                        layman_text = "File sharing is enabled, but locked down securely. Only authorized employees with passwords can access it."
                        
                    l_text = f"• {title}: {layman_text}"
                    l_lbl = ctk.CTkLabel(details_frame, text=l_text, font=ctk.CTkFont(size=12, slant="italic"), text_color="#D4D4D8", justify="left", wraplength=750)
                    l_lbl.grid(row=exp_row, column=0, sticky="w", padx=24, pady=(2, 6))
                    exp_row += 1

        is_expanded = False
        def toggle_details():
            nonlocal is_expanded
            if is_expanded:
                details_frame.grid_forget()
                toggle_btn.configure(text="▼ Show Details")
                is_expanded = False
            else:
                details_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 16))
                toggle_btn.configure(text="▲ Hide Details")
                is_expanded = True

        toggle_btn = ctk.CTkButton(top_bar, text="▼ Show Details", width=100, height=24, corner_radius=4, 
                                   fg_color="#18181B" if is_flagged else "#09090B", 
                                   hover_color="#27272A", text_color="#A1A1AA", 
                                   font=ctk.CTkFont(size=11), command=toggle_details)
        toggle_btn.grid(row=0, column=1, sticky="e")
        
        if self.filter_var.get() and not is_flagged:
            card.grid_forget()

    def run_audit(self):
        current_audit_data = {'total_devices': 0, 'gateway_compromised': False, 'gateway_details': "", 'inventory': []}
        
        try:
            self.after(0, self.update_status, "Locating network perimeter...")
            local_ip = get_if_addr(conf.iface)
            gateway_ip = get_default_gateway()
            subnet = ".".join(local_ip.split('.')[:-1]) + ".0/24"
            
            gateway_result = check_router_gateway(gateway_ip)
            if "[POTENTIAL EXPOSURE]" in gateway_result:
                current_audit_data['gateway_compromised'] = True
                current_audit_data['gateway_details'] = gateway_result
                self.metric_risks += 1
                
            self.after(0, self.render_gateway_card, gateway_ip, gateway_result)
            self.after(0, self.update_telemetry)
            
            self.after(0, self.update_status, "Performing full network sweep...")
            found_devices = scan_subnet(subnet)
            total_devs = len(found_devices)
            current_audit_data['total_devices'] = total_devs
            
            completed = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
                future_to_device = {executor.submit(deep_scan_device, dev['ip']): dev for dev in found_devices}
                
                for future in concurrent.futures.as_completed(future_to_device):
                    device = future_to_device[future]
                    completed += 1
                    
                    self.after(0, self.update_status, f"Analyzing device {completed} of {total_devs}...", completed / total_devs)
                    
                    try:
                        scan_results = future.result()
                        hostname = scan_results['hostname']
                        open_ports = scan_results['open_ports']
                        
                        device_type, confidence = classify_device(device['vendor'], hostname, open_ports)
                        self.after(0, self.render_device_card, device, hostname, device_type, open_ports)
                        
                        # Update Live Telemetry
                        self.metric_hosts += 1
                        self.metric_ports += len(open_ports)
                        
                        is_flagged = False
                        for p, d in open_ports.items():
                            if p in TRANSLATOR:
                                if p == 445 and d.get('details') and "Anonymous" not in d['details']:
                                    continue
                                is_flagged = True
                                break
                        if is_flagged:
                            self.metric_risks += 1
                            
                        self.after(0, self.update_telemetry)
                        
                        exposure_summary = "None in tested ports"
                        finding_status = "No finding"
                        if open_ports:
                            exposure_list = [data['service'] for port, data in open_ports.items()]
                            exposure_summary = ", ".join(exposure_list)
                            
                            vuln_count = sum(1 for p, d in open_ports.items() if p in TRANSLATOR and not (p == 445 and "Anonymous" not in str(d.get('details'))))
                            
                            if vuln_count > 0:
                                finding_status = f"Review required: {vuln_count} flagged issues."
                            else:
                                finding_status = "Services secured."
                                
                        current_audit_data['inventory'].append({
                            'ip': device['ip'],
                            'classification': f"{device_type}\n({device['vendor']})",
                            'exposure': exposure_summary,
                            'finding': finding_status
                        })
                        
                    except Exception as e:
                        pass
                
            self.audit_data = current_audit_data
            self.after(0, self.update_status, "Assessment Complete", 1.0)
            
        except Exception as e:
            self.after(0, self.update_status, f"Error: {str(e)}")
            
        finally:
            self.after(0, lambda: self.scan_button.configure(state="normal", text="Run Assessment"))
            if self.audit_data:
                self.after(0, lambda: self.pdf_button.configure(state="normal", fg_color="#27272A"))

    def save_pdf(self):
        if self.audit_data:
            filepath = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile="NetBaseline_Executive_Report.pdf")
            if filepath:
                try:
                    build_pdf_report(self.audit_data, filename=filepath)
                    self.update_status("Report saved successfully.")
                except Exception as e:
                    self.update_status("Failed to save report.")

if __name__ == "__main__":
    app = AuditGUI()
    app.mainloop()