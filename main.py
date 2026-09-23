import customtkinter as ctk
from customtkinter import filedialog
import threading
import sys
import io
import os

# Import the scanning functions from your renamed backend file
from scanner import get_default_gateway, check_router_gateway, scan_subnet, check_critical_ports, check_anonymous_smb
from scapy.all import conf, get_if_addr

# Import the PDF generator
from report import build_pdf_report

class RedirectText(io.StringIO):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def write(self, string):
        self.text_widget.insert(ctk.END, string)
        self.text_widget.see(ctk.END)

class AuditGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("NetBaseline Security Auditor")
        self.geometry("900x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.audit_data = None

        # Grid Layout: 1 row, 2 columns (Sidebar and Main View)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # --- Sidebar Frame ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="NetBaseline", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.subtitle_label = ctk.CTkLabel(self.sidebar_frame, text="SMB Network Scanner", font=ctk.CTkFont(size=12), text_color="gray")
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 20))

        self.scan_button = ctk.CTkButton(self.sidebar_frame, text="Run Network Audit", command=self.start_scan_thread, height=40)
        self.scan_button.grid(row=2, column=0, padx=20, pady=10)

        self.pdf_button = ctk.CTkButton(self.sidebar_frame, text="Save PDF Report", command=self.save_pdf, state="disabled", height=40, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.pdf_button.grid(row=3, column=0, padx=20, pady=10)

        # --- Main Output Frame ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.output_box = ctk.CTkTextbox(self.main_frame, font=("Consolas", 13), fg_color="#1E1E1E", text_color="#00FF00")
        self.output_box.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        sys.stdout = RedirectText(self.output_box)

    def start_scan_thread(self):
        self.scan_button.configure(state="disabled", text="Scanning Subnet...")
        self.pdf_button.configure(state="disabled")
        self.output_box.delete("1.0", ctk.END)
        threading.Thread(target=self.run_audit, daemon=True).start()

    def run_audit(self):
        current_audit_data = {
            'total_devices': 0,
            'gateway_compromised': False,
            'gateway_details': "", 
            'vulnerable_devices': []
        }
        
        try:
            local_ip = get_if_addr(conf.iface)
            gateway_ip = get_default_gateway()
            subnet = ".".join(local_ip.split('.')[:-1]) + ".0/24"
            
            print("=" * 70)
            print(" INITIALIZING NETBASELINE AUDIT ENGINE")
            print("=" * 70)
            print(f"[*] Local Host IP:   {local_ip}")
            print(f"[*] Target Subnet:   {subnet}")
            print(f"[*] Default Gateway: {gateway_ip}\n")
            
            gateway_result = check_router_gateway(gateway_ip)
            print(gateway_result)
            
            if "[CRITICAL]" in gateway_result:
                current_audit_data['gateway_compromised'] = True
                current_audit_data['gateway_details'] = gateway_result
            print("-" * 70)
            
            found_devices = scan_subnet(subnet)
            current_audit_data['total_devices'] = len(found_devices)
            
            print(f"\n[+] Discovered {len(found_devices)} live devices on the network.")
            print("-" * 70)
            
            for device in found_devices:
                print(f"Target: {device['ip']:<15} | Hardware: {device['vendor']:<20}")
                exposed_services = check_critical_ports(device['ip'])
                
                device_findings = []
                
                if exposed_services:
                    print("    [!] WARNING - Exposed Services Detected:")
                    for service in exposed_services:
                        print(f"        -> Port {service}")
                        device_findings.append(f"Exposed Port: {service}")
                        
                        if "445 (SMB)" in service:
                            shares = check_anonymous_smb(device['ip'])
                            if shares:
                                print("           [CRITICAL] Anonymous Null Session Allowed!")
                                print(f"           Exposed Shares: {', '.join(shares)}")
                                device_findings.append(f"CRITICAL: Anonymous SMB Access (Shares: {', '.join(shares)})")
                            else:
                                print("           [+] SMB is locked down (Anonymous access denied).")
                else:
                    print("    [+] No critical ports exposed.")
                
                if device_findings:
                    current_audit_data['vulnerable_devices'].append({
                        'ip': device['ip'],
                        'vendor': device['vendor'],
                        'findings': device_findings
                    })
                    
                print("-" * 70)
                
            print("\n[+] Audit Execution Complete.")
            self.audit_data = current_audit_data
            
        except Exception as e:
            print(f"\n[!] A fatal error occurred during the scan: {e}")
            
        finally:
            self.scan_button.configure(state="normal", text="Run Network Audit")
            if self.audit_data:
                self.pdf_button.configure(state="normal")

    def save_pdf(self):
        if self.audit_data:
            # Open a file dialog asking the user where to save the PDF
            filepath = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                initialfile="Network_Audit_Report.pdf",
                title="Save PDF Report",
                filetypes=[("PDF Documents", "*.pdf")]
            )
            
            # If the user doesn't cancel the dialog, generate the file
            if filepath:
                try:
                    # We pass the chosen filepath directly to your report generator
                    build_pdf_report(self.audit_data, filename=filepath)
                    print(f"\n[+] PDF Report successfully saved to:\n    {filepath}")
                except Exception as e:
                    print(f"\n[!] Failed to save PDF: {e}")

if __name__ == "__main__":
    app = AuditGUI()
    app.mainloop()