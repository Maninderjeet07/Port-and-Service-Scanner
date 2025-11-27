# full_scanner_gui.py
import socket
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import customtkinter as ctk
import requests
import os

# -----------------------------------------
# Configuration
# -----------------------------------------
AUTO_START_PORT = 1
AUTO_END_PORT = 1024

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

COMMON_API_PATHS = ["/", "/health", "/status", "/api", "/api/v1", "/login", "/auth", "/swagger.json", "/openapi.json"]

# -----------------------------------------
# Low-level scanner helpers
# -----------------------------------------
def scan_port_socket(ip, port, timeout=0.5):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        try:
            s.send(b"Hello\r\n")
        except:
            pass
        banner = s.recv(2048)
        s.close()
        return banner.decode(errors="ignore").strip()
    except:
        return None

# -----------------------------------------
# Nmap integration (subprocess + XML parse)
# -----------------------------------------
def run_nmap_xml(target, ports="1-1024"):
    """Run nmap -sV -p ports -oX - target and parse results into list of dicts.
       Returns (results_list, error_message). If error_message is None, results_list is valid.
    """
    # check if nmap is available
    try:
        which_proc = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if which_proc.returncode != 0:
            return None, "Nmap not found in PATH."
    except FileNotFoundError:
        return None, "Nmap not found in PATH."

    cmd = ["nmap", "-sV", "-p", ports, "-oX", "-", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:
        return None, f"Nmap execution failed: {e}"

    if proc.returncode != 0:
        # nmap may still output xml to stdout even with warnings, try parse
        if not proc.stdout:
            return None, f"Nmap error: {proc.stderr.strip()}"
    xml_out = proc.stdout
    try:
        root = ET.fromstring(xml_out)
    except ET.ParseError as e:
        return None, f"Failed to parse Nmap XML: {e}"

    results = []
    for host in root.findall('host'):
        # iterate ports
        ports_tag = host.find('ports')
        if ports_tag is None:
            continue
        for port in ports_tag.findall('port'):
            pnum = port.get('portid')
            proto = port.get('protocol')
            state_tag = port.find('state')
            state = state_tag.get('state') if state_tag is not None else 'unknown'
            svc = port.find('service')
            service_name = svc.get('name') if svc is not None else 'unknown'
            product = svc.get('product') if svc is not None and 'product' in svc.attrib else ''
            version = svc.get('version') if svc is not None and 'version' in svc.attrib else ''
            results.append({
                "port": int(pnum),
                "protocol": proto,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version
            })
    return results, None

# -----------------------------------------
# API scanner helpers
# -----------------------------------------
def test_api_endpoint(base_url, path="/", timeout=10):
    url = base_url.rstrip("/") + path
    try:
        start = datetime.now()
        # default GET request
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        elapsed = (datetime.now() - start).total_seconds()
        headers = dict(resp.headers)
        body_snippet = resp.text[:1000]  # limit body output
        cors = headers.get("Access-Control-Allow-Origin", None)
        auth_hint = False
        # naive check for auth required
        if resp.status_code in (401, 403) or "WWW-Authenticate" in headers:
            auth_hint = True
        return {
            "url": url,
            "status_code": resp.status_code,
            "time": elapsed,
            "content_type": headers.get("Content-Type", ""),
            "cors": cors,
            "auth_hint": auth_hint,
            "body_snippet": body_snippet
        }, None
    except requests.RequestException as e:
        return None, str(e)

# -----------------------------------------
# GUI
# -----------------------------------------
class FullScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Full Network + Nmap + API Scanner")
        self.geometry("1000x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Tabs: Network Scan | API Scan
        self.tab_view = ctk.CTkTabview(self, width=980, height=610)
        self.tab_view.pack(padx=10, pady=10, fill="both", expand=True)
        self.tab_view.add("Network Scan")
        self.tab_view.add("API Scan")

        # ---------------- Network Scan UI ----------------
        self.network_frame = self.tab_view.tab("Network Scan")

        nf_top = ctk.CTkFrame(self.network_frame)
        nf_top.pack(fill="x", padx=8, pady=8)

        ctk.CTkLabel(nf_top, text="Target IP / Domain:").grid(row=0, column=0, padx=8, pady=6, sticky="w")
        self.net_target_entry = ctk.CTkEntry(nf_top, width=420, placeholder_text="e.g. scanme.nmap.org")
        self.net_target_entry.grid(row=0, column=1, padx=8, pady=6, sticky="w")

        # Nmap toggle
        self.use_nmap_var = ctk.BooleanVar(value=True)
        self.nmap_check = ctk.CTkCheckBox(nf_top, text="Use Nmap (if installed)", variable=self.use_nmap_var)
        self.nmap_check.grid(row=0, column=2, padx=8, pady=6, sticky="w")

        # Auto range shown (disabled entries)
        ctk.CTkLabel(nf_top, text="Port Range (auto):").grid(row=1, column=0, padx=8, pady=6, sticky="w")
        self.net_start_entry = ctk.CTkEntry(nf_top, width=80)
        self.net_start_entry.grid(row=1, column=1, padx=8, pady=6, sticky="w")
        self.net_start_entry.insert(0, str(AUTO_START_PORT))
        self.net_start_entry.configure(state="disabled")
        self.net_end_entry = ctk.CTkEntry(nf_top, width=80)
        self.net_end_entry.grid(row=1, column=1, padx=(120,8), pady=6, sticky="w")
        self.net_end_entry.insert(0, str(AUTO_END_PORT))
        self.net_end_entry.configure(state="disabled")

        self.net_scan_btn = ctk.CTkButton(nf_top, text="Start Network Scan", command=self.start_network_scan_thread)
        self.net_scan_btn.grid(row=0, column=3, padx=8, pady=6)
        self.net_clear_btn = ctk.CTkButton(nf_top, text="Clear Output", fg_color="gray", command=self.clear_network_output)
        self.net_clear_btn.grid(row=0, column=4, padx=8, pady=6)

        self.net_output = ctk.CTkTextbox(self.network_frame, wrap="word")
        self.net_output.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.net_output.insert("end", "Network Scan ready. Use Nmap if installed for richer results.\n")

        # Save results button
        self.net_save_btn = ctk.CTkButton(self.network_frame, text="Save Network Results", command=self.save_network_results)
        self.net_save_btn.pack(anchor="e", padx=16, pady=(0,6))

        # ---------------- API Scan UI ----------------
        self.api_frame = self.tab_view.tab("API Scan")

        af_top = ctk.CTkFrame(self.api_frame)
        af_top.pack(fill="x", padx=8, pady=8)

        ctk.CTkLabel(af_top, text="Base URL (include scheme):").grid(row=0, column=0, padx=8, pady=6, sticky="w")
        self.api_base_entry = ctk.CTkEntry(af_top, width=500, placeholder_text="e.g. https://api.example.com")
        self.api_base_entry.grid(row=0, column=1, padx=8, pady=6, sticky="w", columnspan=3)

        # Endpoints area (editable)
        ctk.CTkLabel(af_top, text="Custom endpoints (one per line):").grid(row=1, column=0, padx=8, pady=6, sticky="nw")
        self.api_endpoints_text = ctk.CTkTextbox(af_top, width=400, height=120, wrap="word")
        self.api_endpoints_text.grid(row=1, column=1, padx=8, pady=6, sticky="w")
        # Pre-fill with common endpoints
        self.api_endpoints_text.insert("0.0", "\n".join(COMMON_API_PATHS))

        # Buttons
        self.api_run_btn = ctk.CTkButton(af_top, text="Run API Tests (GET)", command=self.start_api_scan_thread)
        self.api_run_btn.grid(row=1, column=2, padx=8, pady=6)
        self.api_auto_btn = ctk.CTkButton(af_top, text="Auto-Discover Common Endpoints", command=self.fill_common_endpoints)
        self.api_auto_btn.grid(row=1, column=3, padx=8, pady=6)
        self.api_clear_btn = ctk.CTkButton(af_top, text="Clear Output", fg_color="gray", command=self.clear_api_output)
        self.api_clear_btn.grid(row=0, column=4, padx=8, pady=6)

        self.api_output = ctk.CTkTextbox(self.api_frame, wrap="word")
        self.api_output.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.api_output.insert("end", "API Scan ready. Enter base URL and click Run API Tests.\n")

        self.api_save_btn = ctk.CTkButton(self.api_frame, text="Save API Results", command=self.save_api_results)
        self.api_save_btn.pack(anchor="e", padx=16, pady=(0,6))

    # ---------- Network helpers ----------
    def clear_network_output(self):
        self.net_output.delete("1.0", "end")
        self.net_output.insert("end", "Network Scan cleared.\n")

    def append_net_output(self, text):
        self.net_output.insert("end", text + "\n")
        self.net_output.see("end")

    def save_network_results(self):
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"network_scan_{now}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.net_output.get("1.0", "end"))
            self.append_net_output(f"Saved results to {fname}")
        except Exception as e:
            self.append_net_output(f"Failed to save: {e}")

    def start_network_scan_thread(self):
        t = threading.Thread(target=self.run_network_scan)
        t.daemon = True
        t.start()

    def run_network_scan(self):
        target = self.net_target_entry.get().strip()
        if not target:
            self.append_net_output("Please enter a target IP/domain.")
            return

        use_nmap = self.use_nmap_var.get()
        start_port = AUTO_START_PORT
        end_port = AUTO_END_PORT
        ports_str = f"{start_port}-{end_port}"

        self.net_scan_btn.configure(state="disabled")
        self.append_net_output("=" * 80)
        self.append_net_output(f"Scanning target: {target}  (ports {ports_str})")
        self.append_net_output(f"Started: {datetime.now()}  (Nmap mode: {use_nmap})")
        self.append_net_output("=" * 80)

        if use_nmap:
            results, err = run_nmap_xml(target, ports=ports_str)
            if err:
                self.append_net_output(f"Nmap not available or failed: {err}")
                self.append_net_output("Falling back to socket scanning...")
                use_nmap = False
            else:
                # show nmap results
                for r in sorted(results, key=lambda x: x["port"]):
                    if r["state"] == "open":
                        svc = r.get("service", "")
                        prod = r.get("product", "")
                        ver = r.get("version", "")
                        line = f"[NMAP] Port {r['port']:<5} | Service: {svc:<10} | Product: {prod} {ver}"
                        self.append_net_output(line)
                self.append_net_output("Nmap scan completed.")
        if not use_nmap:
            # socket-based scanning
            open_ports = []
            for port in range(start_port, end_port + 1):
                if scan_port_socket(target, port):
                    svc = COMMON_SERVICES.get(port, "Unknown")
                    banner = banner_grab(target, port)
                    banner_disp = banner if banner else "No banner"
                    open_ports.append((port, svc, banner_disp))
                    self.append_net_output(f"[SOCKET] Port {port:<5} | Service: {svc:<10} | Banner: {banner_disp}")
            if not open_ports:
                self.append_net_output("No open ports found (socket scan).")

        self.append_net_output("=" * 80)
        self.append_net_output("Network scan finished.\n")
        self.net_scan_btn.configure(state="normal")

    # ---------- API helpers ----------
    def clear_api_output(self):
        self.api_output.delete("1.0", "end")
        self.api_output.insert("end", "API Scan cleared.\n")

    def append_api_output(self, text):
        self.api_output.insert("end", text + "\n")
        self.api_output.see("end")

    def save_api_results(self):
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"api_scan_{now}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.api_output.get("1.0", "end"))
            self.append_api_output(f"Saved results to {fname}")
        except Exception as e:
            self.append_api_output(f"Failed to save: {e}")

    def fill_common_endpoints(self):
        self.api_endpoints_text.delete("1.0", "end")
        self.api_endpoints_text.insert("0.0", "\n".join(COMMON_API_PATHS))

    def start_api_scan_thread(self):
        t = threading.Thread(target=self.run_api_scan)
        t.daemon = True
        t.start()

    def run_api_scan(self):
        base = self.api_base_entry.get().strip()
        if not base:
            self.append_api_output("Please enter a base URL (with http/https).")
            return
        # collect endpoints (strip and ensure leading slash)
        raw = self.api_endpoints_text.get("1.0", "end").strip().splitlines()
        endpoints = [p.strip() if p.strip().startswith("/") else "/" + p.strip() for p in raw if p.strip()]

        self.api_run_btn.configure(state="disabled")
        self.append_api_output("=" * 80)
        self.append_api_output(f"API Tests for: {base}")
        self.append_api_output(f"Started: {datetime.now()}")
        self.append_api_output("=" * 80)

        for path in endpoints:
            self.append_api_output(f"Testing: {path} ...")
            res, err = test_api_endpoint(base, path)
            if err:
                self.append_api_output(f" - Error: {err}")
                continue
            # print summarized result
            self.append_api_output(f" - URL        : {res['url']}")
            self.append_api_output(f" - Status     : {res['status_code']}")
            self.append_api_output(f" - Time (s)   : {res['time']:.3f}")
            self.append_api_output(f" - Content-Type: {res['content_type']}")
            if res['cors']:
                self.append_api_output(f" - CORS header: {res['cors']}")
            if res['auth_hint']:
                self.append_api_output(" - Auth hint  : 401/403 or WWW-Authenticate present")
            self.append_api_output(f" - Body begin : {res['body_snippet'][:400].replace(chr(10),' ')}")
            self.append_api_output("-" * 60)

        self.append_api_output("=" * 80)
        self.append_api_output("API tests finished.\n")
        self.api_run_btn.configure(state="normal")

# -----------------------------------------
# Main
# -----------------------------------------
if __name__ == "__main__":
    app = FullScannerApp()
    app.mainloop()
# full_scanner_gui.py
import socket
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import customtkinter as ctk
import requests
import os

# -----------------------------------------
# Configuration
# -----------------------------------------
AUTO_START_PORT = 1
AUTO_END_PORT = 1024

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

COMMON_API_PATHS = ["/", "/health", "/status", "/api", "/api/v1", "/login", "/auth", "/swagger.json", "/openapi.json"]

# -----------------------------------------
# Low-level scanner helpers
# -----------------------------------------
def scan_port_socket(ip, port, timeout=0.5):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        try:
            s.send(b"Hello\r\n")
        except:
            pass
        banner = s.recv(2048)
        s.close()
        return banner.decode(errors="ignore").strip()
    except:
        return None

# -----------------------------------------
# Nmap integration (subprocess + XML parse)
# -----------------------------------------
def run_nmap_xml(target, ports="1-1024"):
    """Run nmap -sV -p ports -oX - target and parse results into list of dicts.
       Returns (results_list, error_message). If error_message is None, results_list is valid.
    """
    # check if nmap is available
    try:
        which_proc = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if which_proc.returncode != 0:
            return None, "Nmap not found in PATH."
    except FileNotFoundError:
        return None, "Nmap not found in PATH."

    cmd = ["nmap", "-sV", "-p", ports, "-oX", "-", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:
        return None, f"Nmap execution failed: {e}"

    if proc.returncode != 0:
        # nmap may still output xml to stdout even with warnings, try parse
        if not proc.stdout:
            return None, f"Nmap error: {proc.stderr.strip()}"
    xml_out = proc.stdout
    try:
        root = ET.fromstring(xml_out)
    except ET.ParseError as e:
        return None, f"Failed to parse Nmap XML: {e}"

    results = []
    for host in root.findall('host'):
        # iterate ports
        ports_tag = host.find('ports')
        if ports_tag is None:
            continue
        for port in ports_tag.findall('port'):
            pnum = port.get('portid')
            proto = port.get('protocol')
            state_tag = port.find('state')
            state = state_tag.get('state') if state_tag is not None else 'unknown'
            svc = port.find('service')
            service_name = svc.get('name') if svc is not None else 'unknown'
            product = svc.get('product') if svc is not None and 'product' in svc.attrib else ''
            version = svc.get('version') if svc is not None and 'version' in svc.attrib else ''
            results.append({
                "port": int(pnum),
                "protocol": proto,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version
            })
    return results, None

# -----------------------------------------
# API scanner helpers
# -----------------------------------------
def test_api_endpoint(base_url, path="/", timeout=10):
    url = base_url.rstrip("/") + path
    try:
        start = datetime.now()
        # default GET request
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        elapsed = (datetime.now() - start).total_seconds()
        headers = dict(resp.headers)
        body_snippet = resp.text[:1000]  # limit body output
        cors = headers.get("Access-Control-Allow-Origin", None)
        auth_hint = False
        # naive check for auth required
        if resp.status_code in (401, 403) or "WWW-Authenticate" in headers:
            auth_hint = True
        return {
            "url": url,
            "status_code": resp.status_code,
            "time": elapsed,
            "content_type": headers.get("Content-Type", ""),
            "cors": cors,
            "auth_hint": auth_hint,
            "body_snippet": body_snippet
        }, None
    except requests.RequestException as e:
        return None, str(e)

# -----------------------------------------
# GUI
# -----------------------------------------
class FullScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Full Network + Nmap + API Scanner")
        self.geometry("1000x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Tabs: Network Scan | API Scan
        self.tab_view = ctk.CTkTabview(self, width=980, height=610)
        self.tab_view.pack(padx=10, pady=10, fill="both", expand=True)
        self.tab_view.add("Network Scan")
        self.tab_view.add("API Scan")

        # ---------------- Network Scan UI ----------------
        self.network_frame = self.tab_view.tab("Network Scan")

        nf_top = ctk.CTkFrame(self.network_frame)
        nf_top.pack(fill="x", padx=8, pady=8)

        ctk.CTkLabel(nf_top, text="Target IP / Domain:").grid(row=0, column=0, padx=8, pady=6, sticky="w")
        self.net_target_entry = ctk.CTkEntry(nf_top, width=420, placeholder_text="e.g. scanme.nmap.org")
        self.net_target_entry.grid(row=0, column=1, padx=8, pady=6, sticky="w")

        # Nmap toggle
        self.use_nmap_var = ctk.BooleanVar(value=True)
        self.nmap_check = ctk.CTkCheckBox(nf_top, text="Use Nmap (if installed)", variable=self.use_nmap_var)
        self.nmap_check.grid(row=0, column=2, padx=8, pady=6, sticky="w")

        # Auto range shown (disabled entries)
        ctk.CTkLabel(nf_top, text="Port Range (auto):").grid(row=1, column=0, padx=8, pady=6, sticky="w")
        self.net_start_entry = ctk.CTkEntry(nf_top, width=80)
        self.net_start_entry.grid(row=1, column=1, padx=8, pady=6, sticky="w")
        self.net_start_entry.insert(0, str(AUTO_START_PORT))
        self.net_start_entry.configure(state="disabled")
        self.net_end_entry = ctk.CTkEntry(nf_top, width=80)
        self.net_end_entry.grid(row=1, column=1, padx=(120,8), pady=6, sticky="w")
        self.net_end_entry.insert(0, str(AUTO_END_PORT))
        self.net_end_entry.configure(state="disabled")

        self.net_scan_btn = ctk.CTkButton(nf_top, text="Start Network Scan", command=self.start_network_scan_thread)
        self.net_scan_btn.grid(row=0, column=3, padx=8, pady=6)
        self.net_clear_btn = ctk.CTkButton(nf_top, text="Clear Output", fg_color="gray", command=self.clear_network_output)
        self.net_clear_btn.grid(row=0, column=4, padx=8, pady=6)

        self.net_output = ctk.CTkTextbox(self.network_frame, wrap="word")
        self.net_output.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.net_output.insert("end", "Network Scan ready. Use Nmap if installed for richer results.\n")

        # Save results button
        self.net_save_btn = ctk.CTkButton(self.network_frame, text="Save Network Results", command=self.save_network_results)
        self.net_save_btn.pack(anchor="e", padx=16, pady=(0,6))

        # ---------------- API Scan UI ----------------
        self.api_frame = self.tab_view.tab("API Scan")

        af_top = ctk.CTkFrame(self.api_frame)
        af_top.pack(fill="x", padx=8, pady=8)

        ctk.CTkLabel(af_top, text="Base URL (include scheme):").grid(row=0, column=0, padx=8, pady=6, sticky="w")
        self.api_base_entry = ctk.CTkEntry(af_top, width=500, placeholder_text="e.g. https://api.example.com")
        self.api_base_entry.grid(row=0, column=1, padx=8, pady=6, sticky="w", columnspan=3)

        # Endpoints area (editable)
        ctk.CTkLabel(af_top, text="Custom endpoints (one per line):").grid(row=1, column=0, padx=8, pady=6, sticky="nw")
        self.api_endpoints_text = ctk.CTkTextbox(af_top, width=400, height=120, wrap="word")
        self.api_endpoints_text.grid(row=1, column=1, padx=8, pady=6, sticky="w")
        # Pre-fill with common endpoints
        self.api_endpoints_text.insert("0.0", "\n".join(COMMON_API_PATHS))

        # Buttons
        self.api_run_btn = ctk.CTkButton(af_top, text="Run API Tests (GET)", command=self.start_api_scan_thread)
        self.api_run_btn.grid(row=1, column=2, padx=8, pady=6)
        self.api_auto_btn = ctk.CTkButton(af_top, text="Auto-Discover Common Endpoints", command=self.fill_common_endpoints)
        self.api_auto_btn.grid(row=1, column=3, padx=8, pady=6)
        self.api_clear_btn = ctk.CTkButton(af_top, text="Clear Output", fg_color="gray", command=self.clear_api_output)
        self.api_clear_btn.grid(row=0, column=4, padx=8, pady=6)

        self.api_output = ctk.CTkTextbox(self.api_frame, wrap="word")
        self.api_output.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.api_output.insert("end", "API Scan ready. Enter base URL and click Run API Tests.\n")

        self.api_save_btn = ctk.CTkButton(self.api_frame, text="Save API Results", command=self.save_api_results)
        self.api_save_btn.pack(anchor="e", padx=16, pady=(0,6))

    # ---------- Network helpers ----------
    def clear_network_output(self):
        self.net_output.delete("1.0", "end")
        self.net_output.insert("end", "Network Scan cleared.\n")

    def append_net_output(self, text):
        self.net_output.insert("end", text + "\n")
        self.net_output.see("end")

    def save_network_results(self):
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"network_scan_{now}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.net_output.get("1.0", "end"))
            self.append_net_output(f"Saved results to {fname}")
        except Exception as e:
            self.append_net_output(f"Failed to save: {e}")

    def start_network_scan_thread(self):
        t = threading.Thread(target=self.run_network_scan)
        t.daemon = True
        t.start()

    def run_network_scan(self):
        target = self.net_target_entry.get().strip()
        if not target:
            self.append_net_output("Please enter a target IP/domain.")
            return

        use_nmap = self.use_nmap_var.get()
        start_port = AUTO_START_PORT
        end_port = AUTO_END_PORT
        ports_str = f"{start_port}-{end_port}"

        self.net_scan_btn.configure(state="disabled")
        self.append_net_output("=" * 80)
        self.append_net_output(f"Scanning target: {target}  (ports {ports_str})")
        self.append_net_output(f"Started: {datetime.now()}  (Nmap mode: {use_nmap})")
        self.append_net_output("=" * 80)

        if use_nmap:
            results, err = run_nmap_xml(target, ports=ports_str)
            if err:
                self.append_net_output(f"Nmap not available or failed: {err}")
                self.append_net_output("Falling back to socket scanning...")
                use_nmap = False
            else:
                # show nmap results
                for r in sorted(results, key=lambda x: x["port"]):
                    if r["state"] == "open":
                        svc = r.get("service", "")
                        prod = r.get("product", "")
                        ver = r.get("version", "")
                        line = f"[NMAP] Port {r['port']:<5} | Service: {svc:<10} | Product: {prod} {ver}"
                        self.append_net_output(line)
                self.append_net_output("Nmap scan completed.")
        if not use_nmap:
            # socket-based scanning
            open_ports = []
            for port in range(start_port, end_port + 1):
                if scan_port_socket(target, port):
                    svc = COMMON_SERVICES.get(port, "Unknown")
                    banner = banner_grab(target, port)
                    banner_disp = banner if banner else "No banner"
                    open_ports.append((port, svc, banner_disp))
                    self.append_net_output(f"[SOCKET] Port {port:<5} | Service: {svc:<10} | Banner: {banner_disp}")
            if not open_ports:
                self.append_net_output("No open ports found (socket scan).")

        self.append_net_output("=" * 80)
        self.append_net_output("Network scan finished.\n")
        self.net_scan_btn.configure(state="normal")

    # ---------- API helpers ----------
    def clear_api_output(self):
        self.api_output.delete("1.0", "end")
        self.api_output.insert("end", "API Scan cleared.\n")

    def append_api_output(self, text):
        self.api_output.insert("end", text + "\n")
        self.api_output.see("end")

    def save_api_results(self):
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"api_scan_{now}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.api_output.get("1.0", "end"))
            self.append_api_output(f"Saved results to {fname}")
        except Exception as e:
            self.append_api_output(f"Failed to save: {e}")

    def fill_common_endpoints(self):
        self.api_endpoints_text.delete("1.0", "end")
        self.api_endpoints_text.insert("0.0", "\n".join(COMMON_API_PATHS))

    def start_api_scan_thread(self):
        t = threading.Thread(target=self.run_api_scan)
        t.daemon = True
        t.start()

    def run_api_scan(self):
        base = self.api_base_entry.get().strip()
        if not base:
            self.append_api_output("Please enter a base URL (with http/https).")
            return
        # collect endpoints (strip and ensure leading slash)
        raw = self.api_endpoints_text.get("1.0", "end").strip().splitlines()
        endpoints = [p.strip() if p.strip().startswith("/") else "/" + p.strip() for p in raw if p.strip()]

        self.api_run_btn.configure(state="disabled")
        self.append_api_output("=" * 80)
        self.append_api_output(f"API Tests for: {base}")
        self.append_api_output(f"Started: {datetime.now()}")
        self.append_api_output("=" * 80)

        for path in endpoints:
            self.append_api_output(f"Testing: {path} ...")
            res, err = test_api_endpoint(base, path)
            if err:
                self.append_api_output(f" - Error: {err}")
                continue
            # print summarized result
            self.append_api_output(f" - URL        : {res['url']}")
            self.append_api_output(f" - Status     : {res['status_code']}")
            self.append_api_output(f" - Time (s)   : {res['time']:.3f}")
            self.append_api_output(f" - Content-Type: {res['content_type']}")
            if res['cors']:
                self.append_api_output(f" - CORS header: {res['cors']}")
            if res['auth_hint']:
                self.append_api_output(" - Auth hint  : 401/403 or WWW-Authenticate present")
            self.append_api_output(f" - Body begin : {res['body_snippet'][:400].replace(chr(10),' ')}")
            self.append_api_output("-" * 60)

        self.append_api_output("=" * 80)
        self.append_api_output("API tests finished.\n")
        self.api_run_btn.configure(state="normal")

# -----------------------------------------
# Main
# -----------------------------------------
if __name__ == "__main__":
    app = FullScannerApp()
    app.mainloop()
