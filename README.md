<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=timeGradient&height=200&section=header&text=NetBaseline&fontSize=50&animation=fadeIn&fontAlignY=38&desc=Lightweight%20SMB%20Network%20Auditor%20%7C%20Local-First%20Security&descAlignY=51&descAlign=62" />
</div>

### 🛡️ Non-Destructive SMB Network Security Baseline Auditor
A standalone desktop auditing engine engineered for mom-and-pop shops, small clinics, and local commercial environments[cite: 7]. Conducts fast, read-only discovery scans across local broadcast domains to identify exposed administrative interfaces, unsegmented infrastructure, and critical access gaps[cite: 7].

Built strictly around an **Evidence & Findings** framework—producing clean, executive-ready single-page PDF reports that map observations directly to real-world risk and remediation priorities[cite: 7].

---

### 🚀 Capabilities & Core Engine

* **Layer 2 Host Discovery & Hardware Resolution**
  * Automated broadcast domain calculation (`/24` subnet resolution)[cite: 3].
  * High-speed Layer 2 ARP sweeps via **Scapy** to map active network hosts without triggering firewall blocks[cite: 3, 7].
  * Automated OUI MAC resolution via `mac-vendor-lookup` to fingerprint endpoint hardware (e.g., Dell, ASRock, IoT appliances)[cite: 3, 7].

* **Perimeter & Router Gateway Hardening Checks**
  * Dynamic gateway resolution from local routing tables[cite: 3].
  * Targeted HTTP Basic Authentication challenges against administrative router portals[cite: 3, 7].
  * Intelligent `401 Unauthorized` filtering to prevent false positives against public landing/setup pages.

* **Targeted Critical Port Mapping**
  * Rapid TCP connection sweeps restricted strictly to high-risk administrative services: **FTP (21)**, **Telnet (23)**, **SMB (445)**, and **RDP (3389)**[cite: 7].
  * Zero fuzzing, zero exploitation payloads—strictly observational polling[cite: 7].

* **Anonymous SMB Null-Session Testing**
  * Direct probing of exposed port 445 instances using `pysmb`[cite: 7].
  * Verifies unauthenticated guest access to local network storage and shared drives[cite: 7].

* **Automated PDF Executive Reporting**
  * Clean, 1-page client-facing audit summaries generated dynamically via **ReportLab**[cite: 5, 7].
  * Color-coded risk tracking with specific credential/share exposure proof[cite: 5].
  * Native desktop file save dialog supporting local drives, external media, and synced Google Drive mounts[cite: 8].

---

### 💻 Stack & Dependencies

<p align="left">
  <a href="#"><img src="https://skillicons.dev/icons?i=python,git,windows,linux,vscode&perline=15" alt="Tech Stack Icons" /></a>
</p>

*   **Core Logic:** Python 3 (Scapy, pysmb, Requests, mac-vendor-lookup)
*   **Interface:** CustomTkinter (Threaded asynchronous GUI, live stdout redirection)[cite: 3]
*   **Reporting:** ReportLab PDF Engine[cite: 5]
*   **Driver Layer:** Npcap (Required on Windows for raw packet capture)

---

### ⚖️ Rules of Engagement & Legal Framework

NetBaseline is explicitly designed to operate under strict Rules of Engagement (ROE)[cite: 7]:
* **Read-Only / Non-Destructive:** Zero penetration testing payloads, no stress testing, no brute-forcing[cite: 7].
* **Zero Configuration Changes:** The baseline engine will never modify routing tables, firewall ACLs, or device credentials[cite: 7].
* **Zero Data Extraction:** Zero client records, customer data, or payment information are accessed, downloaded, or cached[cite: 7].
* **Governing Agreements:** Paired with an on-site *Authorization to Test & Scope of Work (SOW)* and *Hold Harmless Agreement* limiting liability to the engagement fee[cite: 7].

---

<div align="center">

[![Portfolio](https://img.shields.io/badge/Web-helloterminalio.com-000000?style=for-the-badge&logo=googlechrome&logoColor=white)](https://helloterminalio.com)
[![GitHub](https://img.shields.io/badge/GitHub-danielharderpi--png-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/danielharderpi-png)

</div>
