# Software and Data Integrity Scanner

This script is a Python-based tool with a graphical user interface (GUI) built using Tkinter. It's designed to help identify potential Software and Data Integrity Failures (aligned with OWASP Top 10 2021 A08) by performing a one-time audit of a target website.

**Disclaimer:** This tool is intended for educational and auditing purposes only. **Only scan websites that you have explicit permission to test.** Unauthorized scanning can be illegal and unethical. This tool identifies *potential* indicators and does not attempt to exploit vulnerabilities.

## Features

*   **GUI Interface:** Easy-to-use graphical interface built with Tkinter.
*   **Website Scanning:** Fetches and analyzes the HTML content and HTTP headers of a target URL.
*   **HTTP Security Header Analysis:** Checks for the presence and configuration of common security headers (HSTS, CSP, X-Frame-Options, etc.).
*   **Script Integrity Checks:** Analyzes external `<script>` tags for the presence of Subresource Integrity (SRI) attributes and checks for potentially significant inline scripts.
*   **Software Update Integrity Indicators:** Identifies potential links to software update files and looks for associated checksum or signature links. Also checks for insecure HTTP update links and common update-related URL patterns.
*   **Content Security Policy (CSP) Analysis:** Parses and analyzes the `Content-Security-Policy` header for risky directives (`unsafe-inline`, `unsafe-eval`, `*`) and missing important directives.
*   **Subresource Integrity (SRI) Analysis:** Checks both external scripts and stylesheets (`<link rel="stylesheet">`) for the presence of the `integrity` attribute.
*   **Potential Deserialization Indicators:** Looks for potential indicators of insecure deserialization by analyzing `Content-Type` headers, cookies, and URL parameters for patterns like base64 encoding. **Note: This is a heuristic check and may produce false positives.**
*   **Severity Coloring:** Displays findings in the GUI with color coding based on severity (High, Medium, Low, Info).
*   **HTML Report Generation:** Saves the scan results as a formatted HTML report.
*   **Timeout Configuration:** Allows setting a timeout for HTTP requests.
*   **Proxy Support:** Supports configuring an HTTP/HTTPS proxy for scanning.
*   **Threading:** Performs the scan in a separate thread to keep the GUI responsive.
*   **Progress Indicator:** Shows the progress of the scan in the GUI.

## Installation

1.  **Install Python:** If you don't have Python installed, download and install the latest version from [python.org](https://www.python.org/). Ensure you add Python to your system's PATH during installation.
2.  **Install Required Libraries:** Open your terminal or command prompt and run the following command:

    ```bash
    pip install requests beautifulsoup4
    ```

    Tkinter and `hashlib`, `datetime`, `base64`, `threading`, and `urllib.parse` are usually included with standard Python installations.

## How to Use

1.  **Save the Script:** Save the provided Python code as a `.py` file (e.g., `sdis.py`).
2.  **Run the Script:** Open your terminal or command prompt, navigate to the directory where you saved the script, and run:

    ```bash
    python oSDIS.py
    ```
3.  **Enter Target URL:** In the GUI, enter the full URL of the website you want to scan (e.g., `https://example.com`).
4.  **Configure Options (Optional):**
    *   **Timeout:** Adjust the timeout value in seconds for HTTP requests.
    *   **Proxy:** Enter the proxy address (e.g., `http://127.0.0.1:8080`) if you want to use a proxy.
5.  **Start Scan:** Click the "Scan" button.
6.  **View Results:** The scan results will appear in the text area, color-coded by severity.
7.  **Save Report:** Click the "Save Report (HTML)" button to save the findings as an HTML file.

## Understanding the Results

The results area and the HTML report will display findings categorized by the type of check performed. Each finding includes:

*   **Severity:** Indicates the potential impact (High, Medium, Low, Info).
*   **Issue:** A description of the potential vulnerability or misconfiguration.
*   **Details (often):** Specific information like the problematic header value, URL, or script source.

**Important Notes on Findings:**

*   **Potential Deserialization Indicators:** Findings in this category are based on heuristics (like base64 encoding) and are **not definitive proof** of a deserialization vulnerability. They indicate areas that warrant manual investigation.
*   **External Audit Limitations:** This tool performs an external audit. It cannot see the internal workings of the application or the CI/CD pipeline. Findings are based on observable information.
*   **Severity Levels:** Severity levels are assigned based on the potential risk of the identified issue from an external perspective. They may differ from internal risk assessments.

## Disclaimer

This tool is provided "as is" without any warranty. The author is not responsible for any misuse or damage caused by this tool. By using this tool, you agree to use it responsibly and only on systems you have authorization to scan.
