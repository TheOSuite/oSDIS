import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from tkinter import ttk  # Import the ttk module
import requests
from bs4 import BeautifulSoup
import hashlib
from datetime import datetime
import base64
import threading
from urllib.parse import urlparse, parse_qs

class SecurityScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Software and Data Integrity Scanner")

        # URL input
        self.url_label = tk.Label(master, text="Target URL:")
        self.url_label.grid(row=0, column=0, padx=5, pady=5)

        self.url_entry = tk.Entry(master, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        # Timeout input
        self.timeout_label = tk.Label(master, text="Timeout (seconds):")
        self.timeout_label.grid(row=1, column=0, padx=5, pady=5)

        self.timeout_entry = tk.Entry(master, width=10)
        self.timeout_entry.grid(row=1, column=1, padx=5, pady=5)
        self.timeout_entry.insert(tk.END, "10")  # Default timeout

        # Proxy input
        self.proxy_label = tk.Label(master, text="Proxy (optional):")
        self.proxy_label.grid(row=2, column=0, padx=5, pady=5)

        self.proxy_entry = tk.Entry(master, width=50)
        self.proxy_entry.grid(row=2, column=1, padx=5, pady=5)

        # Scan button
        self.scan_button = tk.Button(master, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5)

        # Results area
        self.results_area = scrolledtext.ScrolledText(master, width=80, height=20)
        self.results_area.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

        # Save report button
        self.save_button = tk.Button(master, text="Save Report (HTML)", command=self.save_report)
        self.save_button.grid(row=2, column=1, padx=5, pady=5)

        # Progress bar
        self.progress = tk.Label(master, text="Progress:")
        self.progress.grid(row=3, column=0, padx=5, pady=5)

        self.progress_bar = ttk.Progressbar(master, length=200, mode="determinate") # Use ttk.Progressbar
        self.progress_bar.grid(row=3, column=1, padx=5, pady=5)

        # Configure tags for coloring
        self.results_area.tag_config("high", background="red", foreground="white")
        self.results_area.tag_config("medium", background="orange", foreground="black")
        self.results_area.tag_config("low", background="yellow", foreground="black")
        self.results_area.tag_config("info", foreground="blue")

        self.findings = []  # Store findings for the HTML report

    def start_scan(self):
        target_url = self.url_entry.get()
        timeout = int(self.timeout_entry.get())
        proxy = self.proxy_entry.get().strip() if self.proxy_entry.get().strip() else None

        if not target_url:
            self.display_result("Please enter a target URL.", "info")
            return

        self.results_area.delete(1.0, tk.END)
        self.findings = []  # Clear previous findings
        self.display_result(f"Scanning: {target_url}\n", "info")

        # Define the number of scan steps
        self.scan_steps = 6  # Adjust this if you add or remove check functions
        self.progress_bar["maximum"] = self.scan_steps
        self.progress_bar["value"] = 0
        self.progress_value = 0
        self.update_progress_label(f"Starting scan...")

        # Start the scan in a new thread to avoid blocking the UI
        threading.Thread(target=self.perform_scan, args=(target_url, timeout, proxy)).start()

    def perform_scan(self, target_url, timeout, proxy):
        try:
            proxies = {"http": proxy, "https": proxy} if proxy else None
            response = requests.get(target_url, timeout=timeout, proxies=proxies)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # --- Implement scanning logic with progress updates ---
            self.update_progress("Checking HTTP Headers")
            self.check_http_headers(response.headers)

            self.update_progress("Checking Script Integrity")
            self.check_script_integrity(soup)

            self.update_progress("Checking Update Integrity")
            self.check_update_integrity(soup)

            self.update_progress("Checking Content Security Policy")
            self.check_content_security_policy(response.headers)

            self.update_progress("Checking Subresource Integrity")
            self.check_subresource_integrity(soup)

            self.update_progress("Checking for Deserialization Indicators")
            self.check_deserialization_indicators(target_url, soup)

            self.update_progress_label("Scan finished.")
            self.display_result("\nScan finished.", "info")

        except requests.exceptions.RequestException as e:
            self.display_result(f"Error during scan: {e}", "high")
            self.update_progress_label(f"Error during scan: {e}")
        except Exception as e:
            self.display_result(f"An unexpected error occurred: {e}", "high")
            self.update_progress_label(f"An unexpected error occurred: {e}")
        finally:
            self.progress_bar["value"] = self.scan_steps # Ensure progress bar is full on completion/error

    def update_progress(self, task_name):
        self.progress_value += 1
        self.progress_bar["value"] = self.progress_value
        self.update_progress_label(f"Progress: {self.progress_value}/{self.scan_steps} - {task_name}")

    def update_progress_label(self, text):
        self.progress.config(text=text)

    def display_result(self, message, severity="info"):
        self.results_area.insert(tk.END, message + "\n", severity)
        self.results_area.see(tk.END)  # Auto-scroll to the end
        self.findings.append({"message": message, "severity": severity})

    def check_http_headers(self, headers):
        self.display_result("\n--- HTTP Header Analysis ---", "info")
        security_headers = {
            "Server": {"severity": "low", "description": "Reveals server software and version. Could aid attackers."},
            "X-Powered-By": {"severity": "low", "description": "Reveals backend technology. Could aid attackers."},
            "Strict-Transport-Security": {"severity": "high", "description": "Missing or misconfigured HSTS can lead to downgrade attacks and cookie hijacking.",
                                        "check": lambda h: h is not None and ("max-age" not in h.lower() or int(h.lower().split("max-age=")[1].split(';')[0].strip()) < 31536000) if h is not None and "max-age" in h.lower() else True},
            "Content-Security-Policy": {"severity": "medium", "description": "Missing or overly permissive CSP can allow various attacks, including XSS.",
                                        "check": lambda h: not h},
            "X-Frame-Options": {"severity": "medium", "description": "Missing or misconfigured XFO can lead to clickjacking.",
                                "check": lambda h: h is not None and h.lower() not in ["deny", "sameorigin"]},
            "X-Content-Type-Options": {"severity": "high", "description": "Missing 'nosniff' can lead to MIME sniffing vulnerabilities.",
                                        "check": lambda h: h is not None and h.lower() != "nosniff"},
            "Referrer-Policy": {"severity": "low", "description": "Lack of a proper referrer policy might leak sensitive information.",
                                "check": lambda h: h is not None and (not h or h.lower() == "unsafe-url")},
            "Permissions-Policy": {"severity": "low", "description": "Missing or misconfigured Permissions Policy can allow unwanted browser features.",
                                   "check": lambda h: not h}, # This one might be okay without h is not None if the check is 'not h'
            "Cache-Control": {"severity": "low", "description": "Inadequate cache control might lead to sensitive information being cached.",
                              "check": lambda h: h is not None and ("no-store" not in h.lower() and "private" not in h.lower())},
            "Pragma": {"severity": "info", "description": "The 'Pragma: no-cache' directive is outdated for modern browsers; use Cache-Control instead.",
                       "check": lambda h: h is not None and h.lower() == "no-cache"},
            "Expires": {"severity": "info", "description": "The 'Expires' header is outdated; use Cache-Control instead.",
                        "check": lambda h: h is not None},
            "Set-Cookie": {"severity": "low", "description": "Consider security flags for cookies.",
                           "check": lambda h: h is not None and ("secure" not in h.lower() or "httponly" not in h.lower())},
        }

        for header, details in security_headers.items():
            header_value = headers.get(header) # Use .get() which returns None if not found
            if header_value is not None: # Check if the header is present
                self.display_result(f"  {header}: {header_value}", "info")
                if "check" in details and not details["check"](header_value):
                    self.display_result(f"    Potential issue: {details['description']}", details["severity"])
                    self.findings.append({"message": f"HTTP Header Issue: {header} - {details['description']} (Value: {header_value})", "severity": details["severity"]})
            else:
                # Header is missing
                if "check" in details:
                     # If the check is designed to flag missing headers, handle it here.
                     # For simplicity, we'll assume missing headers are issues based on your original logic.
                     # We still need to call the check with None to see if it flags missing.
                     if not details["check"](None): # Pass None to the check
                         self.display_result(f"  {header}: Not present", details["severity"])
                         self.findings.append({"message": f"HTTP Header Missing: {header} - {details['description']}", "severity": details["severity"]})
                     else:
                         # If the check returned True for None, it doesn't consider missing an issue
                         self.display_result(f"  {header}: Not present", "info")
                else:
                     # If no specific check for missing, just report as info
                     self.display_result(f"  {header}: Not present", "info")

    def check_script_integrity(self, soup):
        self.display_result("\n--- Script Integrity Analysis ---", "info")
        scripts = soup.find_all('script', src=True)
        if not scripts:
            self.display_result("  No external scripts found.", "info")
            return

        for script in scripts:
            src = script['src']
            integrity = script.get('integrity')
            crossorigin = script.get('crossorigin')

            if src and (src.startswith('http') or src.startswith('//')): # External scripts
                if integrity:
                    self.display_result(f"  External script with SRI: {src} (integrity='{integrity}')", "info")
                    # You could potentially validate the format of the integrity attribute here
                else:
                    self.display_result(f"  External script without SRI: {src}", "high") # Changed to high severity as missing SRI is a significant risk
                    self.findings.append({"message": f"External script without Subresource Integrity (SRI): {src}", "severity": "high"})

                if not crossorigin:
                    self.display_result(f"  External script without 'crossorigin' attribute: {src}", "medium") # Changed to medium severity as it impacts SRI functionality
                    self.findings.append({"message": f"External script without 'crossorigin' attribute: {src}", "severity": "medium"})
                elif crossorigin.lower() not in ['anonymous', 'use-credentials']:
                    self.display_result(f"  External script with potentially problematic 'crossorigin' attribute: {src} (crossorigin='{crossorigin}')", "medium") # Changed to medium
                    self.findings.append({"message": f"External script with non-standard 'crossorigin' attribute: {src}", "severity": "medium"})

            else:
                self.display_result(f"  Local script: {src}", "info")
                # For local scripts, SRI isn't directly applicable in the same way,
                # but you might consider suggesting checks on the server-side to ensure
                # these files haven't been tampered with.

        # Inline scripts (without src)
        inline_scripts = soup.find_all('script', src=False)
        if inline_scripts:
            self.display_result("\n  --- Inline Script Analysis ---", "info") # Added spacing
            for script_tag in inline_scripts:
                if script_tag.string and len(script_tag.string.strip()) > 50: # Basic filter for non-empty inline scripts
                    self.display_result("  Potentially significant inline script found. Review source for integrity measures.", "low")
                    self.findings.append({"message": "Potentially significant inline script found. Review source.", "severity": "low"})

    def check_update_integrity(self, soup):
        self.display_result("\n--- Software Update Integrity Analysis ---", "info")
        potential_update_links = []
        checksum_related_links = []

        for link in soup.find_all('a', href=True):
            href = link['href']
            if any(ext in href.lower() for ext in ['.zip', '.tar.gz', '.exe', '.msi', '.rpm', '.deb', '.pkg', '.dmg']):
                potential_update_links.append(href)
            if link.text and any(text in link.text.lower() for text in ['checksum', 'sha', 'md5', 'signature', 'sig', 'hash']): # Added check for link.text
                checksum_related_links.append((link.text, href))
            if any(href.lower().endswith(ext) for ext in ['.sha1', '.sha256', '.sha512', '.md5', '.asc', '.sig']):
                checksum_related_links.append((link.text if link.text else 'N/A', href)) # Handle missing link text

        if potential_update_links:
            self.display_result("  Potential software update links found:", "info")
            for link in potential_update_links:
                self.display_result(f"    {link}", "low")
                self.findings.append({"message": f"Potential software update link found: {link}", "severity": "low"})
                # Further analysis: Try to fetch the page containing this link and look for associated checksums

        if checksum_related_links:
            self.display_result("\n  Potential checksum or signature related links:", "info")
            for text, href in checksum_related_links:
                self.display_result(f"    {text}: {href}", "low")
                self.findings.append({"message": f"Potential checksum/signature link: {text} - {href}", "severity": "low"})
                # Further analysis: Attempt to associate these with update files found

        # Look for common patterns indicating update mechanisms
        patterns = [
            r"update(s)?\.xml",
            r"version\.txt",
            r"changelog(\.txt|\.md)?",
            r"download(s)?/.*?\.(zip|tar\.gz|exe|msi|rpm|deb|pkg|dmg)",
            r"releases?(/.*)?",
        ]
        self.display_result("\n  Checking for potential update-related URL patterns:", "info")
        parsed_url = urlparse(self.url_entry.get())
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        for pattern in patterns:
            full_pattern_url = f"{base_url}/{pattern}"
            try:
                # Using HEAD request is more efficient if you only need the status code
                response = requests.head(full_pattern_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    self.display_result(f"    Found potential update-related pattern: {full_pattern_url} (Status: {response.status_code})", "low")
                    self.findings.append({"message": f"Potential update-related URL pattern found: {full_pattern_url}", "severity": "low"})
                elif response.status_code != 404:
                     # Report non-404 status codes as potentially interesting
                    self.display_result(f"    Potential update-related pattern: {full_pattern_url} (Status: {response.status_code})", "info")
            except requests.exceptions.RequestException as e:
                # Handle network errors gracefully
                self.display_result(f"    Error checking pattern {full_pattern_url}: {e}", "info")
            except Exception as e:
                 self.display_result(f"    Unexpected error checking pattern {full_pattern_url}: {e}", "info")


        # Look for update-related meta tags (extending previous check)
        version_meta = soup.find_all('meta', attrs={'name': lambda x: x and ('version' in x.lower() or 'update' in x.lower())}) # Added check for x
        if version_meta:
            self.display_result("\n  Software/Update information found in meta tags:", "info")
            for meta in version_meta:
                name = meta.get('name', 'N/A')
                content = meta.get('content', 'N/A')
                self.display_result(f"    {name}: {content}", "info")
                # Consider if outdated version info should be a low severity finding
        else:
            self.display_result("  No specific software/update information found in meta tags.", "info")

        # Basic check for "http" on update-related links (potential for insecure updates)
        if potential_update_links:
            self.display_result("\n  Checking update links for insecure HTTP:", "info")
            for link in potential_update_links:
                if link and link.startswith("http://"): # Added check for link
                    self.display_result(f"    Insecure HTTP update link found: {link}", "medium")
                    self.findings.append({"message": f"Insecure HTTP update link found: {link}", "severity": "medium"})

    def check_content_security_policy(self, headers):
        self.display_result("\n--- Content Security Policy Analysis ---", "info")
        csp = headers.get('Content-Security-Policy')
        if csp:
            self.display_result(f"  Content-Security-Policy: {csp}", "info")
            directives = {}
            for directive_string in csp.split(';'):
                if directive_string.strip():
                    parts = [part.strip() for part in directive_string.split()]
                    if parts: # Ensure there's at least a directive name
                        directive = parts[0]
                        sources = parts[1:]
                        directives[directive] = sources

            # Helper function to check for 'unsafe-inline' or '*' in a directive's sources
            def check_unsafe(directive_name, sources, severity="high"):
                if "'unsafe-inline'" in sources:
                    self.display_result(f"  Warning: '{directive_name}' allows 'unsafe-inline'. This is a significant risk.", severity)
                    self.findings.append({"message": f"CSP: '{directive_name}' allows 'unsafe-inline'", "severity": severity})
                if '*' in sources and '*' not in ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'"]:
                    self.display_result(f"  Caution: '{directive_name}' allows any origin ('*'). Restrict to trusted sources.", "medium")
                    self.findings.append({"message": f"CSP: '{directive_name}' allows any origin ('*')", "severity": "medium"})

            # Analyze key directives
            if 'default-src' not in directives:
                self.display_result("  Warning: 'default-src' is missing. This can lead to overly permissive fallback behavior.", "medium")
                self.findings.append({"message": "CSP: Missing 'default-src' directive", "severity": "medium"})
            else:
                check_unsafe('default-src', directives.get('default-src', [])) # Use .get() with default

            script_src = directives.get('script-src', directives.get('default-src', []))
            check_unsafe('script-src', script_src)
            if "'unsafe-eval'" in script_src:
                self.display_result("  Warning: 'script-src' allows 'unsafe-eval', which can enable code injection.", "high")
                self.findings.append({"message": "CSP: 'script-src' allows 'unsafe-eval'", "severity": "high"})

            style_src = directives.get('style-src', directives.get('default-src', []))
            check_unsafe('style-src', style_src, severity="medium") # Lower severity for style

            img_src = directives.get('img-src', directives.get('default-src', ["'self'"]))
            if '*' in img_src and '*' not in ["'self'", "data:"]:
                self.display_result("  Caution: 'img-src' allows images from any origin ('*').", "low")
                self.findings.append({"message": "CSP: 'img-src' allows images from any origin ('*')", "severity": "low"})

            object_src = directives.get('object-src', ["'none'"])
            if "'none'" not in object_src:
                self.display_result("  Recommendation: 'object-src' should be set to 'none' to prevent plugin loading.", "low")
                self.findings.append({"message": "CSP: 'object-src' is not 'none'", "severity": "low"})

            form_action = directives.get('form-action', ["'self'"])
            if '*' in form_action and '*' not in ["'self'"]:
                self.display_result("  Caution: 'form-action' allows form submissions to any origin ('*').", "low")
                self.findings.append({"message": "CSP: 'form-action' allows form submissions to any origin ('*')", "severity": "low"})

            frame_ancestors = directives.get('frame-ancestors')
            if not frame_ancestors:
                self.display_result("  Recommendation: 'frame-ancestors' directive is missing. Consider for clickjacking protection.", "low")
                self.findings.append({"message": "CSP: Missing 'frame-ancestors' directive", "severity": "low"})
            elif '*' in frame_ancestors:
                self.display_result("  Warning: 'frame-ancestors' allows embedding from any origin ('*'). Potential clickjacking risk.", "medium")
                self.findings.append({"message": "CSP: 'frame-ancestors' allows embedding from any origin ('*')", "severity": "medium"})

            # Check for report-uri or report-to for CSP violation reporting
            if 'report-uri' not in directives and 'report-to' not in directives:
                self.display_result("  Recommendation: Neither 'report-uri' nor 'report-to' is present. Consider setting up CSP violation reporting.", "low")
                self.findings.append({"message": "CSP: Missing 'report-uri' and 'report-to' for violation reporting", "severity": "low"})

            # Check for upgrade-insecure-requests
            if 'upgrade-insecure-requests' in directives:
                 self.display_result("  Note: 'upgrade-insecure-requests' directive is present. Good practice for migrating to HTTPS.", "info")
            else:
                self.display_result("  Note: 'upgrade-insecure-requests' directive is not present. Consider using it to upgrade insecure requests.", "low")

            # Check for block-all-mixed-content
            if 'block-all-mixed-content' in directives:
                 self.display_result("  Note: 'block-all-mixed-content' directive is present. Good for preventing mixed content issues.", "info")
            else:
                self.display_result("  Note: 'block-all-mixed-content' directive is not present. Consider using it to prevent loading mixed HTTP/HTTPS content.", "low")

        else:
            self.display_result("  Content-Security-Policy: Not present", "high")
            self.findings.append({"message": "HTTP Header Missing: Content-Security-Policy", "severity": "high"})

    def check_subresource_integrity(self, soup):
        self.display_result("\n--- Subresource Integrity (SRI) Analysis ---", "info")
        elements_to_check = soup.find_all(['script', 'link'])
        found_external = False

        for element in elements_to_check:
            src = element.get('src') or element.get('href')
            integrity = element.get('integrity')
            crossorigin = element.get('crossorigin')
            tag_name = element.name

            if src and (src.startswith('http') or src.startswith('//')):
                found_external = True
                if integrity:
                    self.display_result(f"  External <{tag_name}> with SRI: {src} (integrity='{integrity}')", "info")
                    # You could add validation of the integrity attribute format here (e.g., algorithm and hash length)
                    if not crossorigin:
                        self.display_result(f"    Note: Missing 'crossorigin' attribute. SRI might not function correctly.", "low")
                        self.findings.append({"message": f"<{tag_name}> {src} missing 'crossorigin' for SRI", "severity": "low"})
                    elif crossorigin.lower() not in ['anonymous', 'use-credentials']:
                        self.display_result(f"    Note: Non-standard 'crossorigin' attribute: '{crossorigin}'. SRI behavior might be unexpected.", "low")
                        self.findings.append({"message": f"<{tag_name}> {src} has non-standard 'crossorigin': {crossorigin}", "severity": "low"})
                else:
                    self.display_result(f"  External <{tag_name}> without SRI: {src}", "high")
                    self.findings.append({"message": f"External <{tag_name}> without Subresource Integrity (SRI): {src}", "severity": "high"})

        if not found_external:
            self.display_result("  No external scripts or stylesheets found to check for SRI.", "info")

    def check_deserialization_indicators(self, target_url, soup):
        self.display_result("\n--- Potential Deserialization Indicators ---", "info")

        # Check Content-Type headers
        try: # Added try-except for the HEAD request
            headers = requests.head(target_url, allow_redirects=True).headers
            content_type = headers.get('Content-Type', '')
            if "x-java-serialized-object" in content_type:
                self.display_result(f"  Suspicious Content-Type found: {content_type}", "medium")
                self.findings.append({"message": f"Potential Java Deserialization via Content-Type: {content_type}", "severity": "medium"})
            elif "vnd.php.serialized" in content_type:
                self.display_result(f"  Suspicious Content-Type found: {content_type}", "medium")
                self.findings.append({"message": f"Potential PHP Deserialization via Content-Type: {content_type}", "severity": "medium"})
            else:
                 self.display_result(f"  Content-Type: {content_type}", "info") # Report Content-Type even if not suspicious
        except requests.exceptions.RequestException as e:
             self.display_result(f"  Error retrieving Content-Type header: {e}", "low")
        except Exception as e:
             self.display_result(f"  Unexpected error retrieving Content-Type header: {e}", "low")


        # Analyze cookies (very basic check for base64)
        try:
            response = requests.get(target_url, allow_redirects=True)
            if response.cookies: # Check if there are any cookies
                 self.display_result("\n  Analyzing cookies:", "info")
                 for cookie_name, cookie_value in response.cookies.items():
                    if len(cookie_value) > 50 and self.is_base64(cookie_value):
                        self.display_result(f"    Potentially encoded cookie: {cookie_name}={cookie_value}", "low")
                        self.findings.append({"message": f"Potentially encoded cookie: {cookie_name}", "severity": "low"})
                    else:
                         self.display_result(f"    Cookie: {cookie_name}", "info")
            else:
                 self.display_result("\n  No cookies found.", "info")


            # Analyze URL parameters (very basic check for base64)
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            if query_params: # Check if there are any query parameters
                 self.display_result("\n  Analyzing URL parameters:", "info")
                 for param_name, param_values in query_params.items():
                    for param_value in param_values:
                        if len(param_value) > 50 and self.is_base64(param_value):
                            self.display_result(f"    Potentially encoded URL parameter: {param_name}={param_value}", "low")
                            self.findings.append({"message": f"Potentially encoded URL parameter: {param_name}", "severity": "low"})
                        else:
                             self.display_result(f"    URL parameter: {param_name}={param_value}", "info")
            else:
                 self.display_result("\n  No URL parameters found.", "info")


        except requests.exceptions.RequestException as e:
            self.display_result(f"  Error analyzing cookies/parameters: {e}", "low")
        except Exception as e:
            self.display_result(f"  Unexpected error during cookie/parameter analysis: {e}", "low")

    def is_base64(self, s):
        """Improved base64 check with more accurate validation."""
        if not isinstance(s, str): # Ensure input is a string
            return False
        # Base64 strings typically have lengths divisible by 4
        if len(s) % 4 != 0:
            return False
        try:
            # Attempt to decode and then re-encode to validate
            decoded = base64.b64decode(s, validate=True)
            return base64.b64encode(decoded).decode() == s
        except (TypeError, base64.binascii.Error):
            return False

    def save_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html"), ("All files", "*.*")])
        if file_path:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            html_report = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Security Scan Report - {self.url_entry.get()}</title>
                <style>
                    body {{ font-family: sans-serif; margin: 20px; }}
                    h1, h2 {{ color: #333; }}
                    .finding {{ margin-bottom: 10px; padding: 10px; border: 1px solid #ccc; }}
                    .severity-high {{ background-color: #ffe0e0; border-color: #ffaaaa; color: #d00000; }}
                    .severity-medium {{ background-color: #fff0d0; border-color: #ffc060; color: #a06000; }}
                    .severity-low {{ background-color: #ffffe0; border-color: #ffff80; color: #808000; }}
                    .severity-info {{ background-color: #e0f0ff; border-color: #a0c0ff; color: #0060c0; }}
                    .timestamp {{ color: #777; font-size: small; margin-top: 10px; }}
                </style>
            </head>
            <body>
                <h1>Security Scan Report</h1>
                <p><strong>Target URL:</strong> {self.url_entry.get()}</p>
                <p><strong>Scan Timestamp:</strong> {now}</p>

                <h2>Findings</h2>
            """
            if not self.findings:
                html_report += "<p>No significant findings.</p>"
            else:
                for finding in self.findings:
                    severity_class = f"severity-{finding['severity']}"
                    html_report += f"""
                    <div class="finding {severity_class}">
                        <strong>Severity:</strong> {finding['severity'].capitalize()}<br>
                        <strong>Issue:</strong> {finding['message']}
                    </div>
                    """

            html_report += f"""
            <div class="timestamp">Report generated on: {now}</div>
            </body>
            </html>
            """

            try:
                with open(file_path, "w") as f:
                    f.write(html_report)
                self.display_result(f"Report saved to: {file_path}", "info")
            except Exception as e:
                self.display_result(f"Error saving report: {e}", "high")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityScannerGUI(root)
    root.mainloop()
