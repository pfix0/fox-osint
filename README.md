<p align="center">
  <img src="https://github.com/user-attachments/assets/65c2292b-0720-4db4-a6be-f5f970b3770e" alt="logo" width="240">
</p>

# 🦊 Fox OSINT: Advanced Cyber Reconnaissance Tool 🕵️

Fox OSINT is a Python-based command-line tool designed for Open Source Intelligence (OSINT) gathering and reconnaissance on a target domain. It automates several information-gathering tasks, presenting the results in a structured and readable format in your terminal.

---

## 🎯 Key Features

* **📜 DNS Record Enumeration**: Retrieves various DNS record types for the target domain, including A, AAAA, MX, NS, CNAME, and TXT records.
* **🚪 Port Scanning**:
    * Scans a predefined list of common TCP ports (e.g., 21, 22, 80, 443, 3306, 8080) on the main domain.
    * Identifies services potentially running on open ports by attempting to resolve the service name associated with the port number.
    * Performs port scanning on discovered subdomains that are found to be live.
* **🔗 Subdomain Discovery**:
    * Queries the `crt.sh` service, utilizing its JSON output from certificate transparency logs to discover subdomains associated with the target domain.
    * Limits the number of processed subdomains to a predefined maximum (`MAX_SUBDOMAINS`, defaulting to 100) to manage performance for domains with a large number of subdomains.
* **📍 IP Address Resolution**: Resolves the IP address(es) for each discovered subdomain.
* **🚦 Subdomain Liveness Check**:
    * Tests each discovered subdomain for responsiveness over HTTP and HTTPS protocols to determine if it's "Working" or "Not Working".
* **📊 Rich CLI Output**:
    * Utilizes the `rich` Python library to display information in well-formatted tables, panels, and progress bars, enhancing the user experience.
    * Presents distinct tables for DNS records, main domain open ports, subdomain IP addresses, subdomain status, and open ports for working subdomains.

---

## ⚙️ Workflow

The tool follows this general operational flow:

1.  **⌨️ User Input**: The process begins when the user is prompted to enter the domain name they wish to investigate.
2.  **🎯 Main Domain Analysis**:
    * Fetches and displays DNS records for the entered domain.
    * Scans the main domain for open ports from the `TOP_PORTS` list and displays the results.
3.  **🗺️ Subdomain Enumeration**:
    * Retrieves a list of subdomains from `crt.sh`.
4.  **🔬 Subdomain Analysis (Iterative Process with Progress Bars)**:
    * **IP Resolution**: For each subdomain (up to `MAX_SUBDOMAINS`), its IP address is resolved.
    * **Status Check**: Each subdomain's status (live via HTTP/HTTPS) is checked.
    * **Port Scanning**: For subdomains confirmed as "Working", a port scan is conducted using the `TOP_PORTS` list.
5.  **📋 Results Aggregation & Display**:
    * Displays a table mapping subdomains to their resolved IP addresses.
    * Displays a table showing the status (Working/Not Working) and accessible URL for each subdomain.
    * Displays a table detailing open ports and services for each working subdomain.

---

## 🛠️ Prerequisites

* Python 3.x
* Internet connectivity (for DNS resolution, `crt.sh` queries, HTTP/HTTPS checks, and potentially service lookups).

---

## 🚀 Setup & Installation

1.  **🐑 Clone the repository** (if you haven't already):
    ```bash
    https://github.com/pfix0/fox-osint.git
    cd fox-osint
    ```

2.  **📦 Install dependencies**:
    The script relies on external Python libraries listed in `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```
    Key dependencies include:
    * `requests` (for HTTP requests to `crt.sh` and subdomain status checks)
    * `rich` (for enhanced terminal output, tables, progress bars)
    * `dnspython` (for DNS record lookups)

---

## ▶️ Usage

To run the tool, execute the `fox_osint.py` script using Python:

```bash
python fox_osint.py
