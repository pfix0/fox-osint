<p align="center">
  <img src="https://github.com/user-attachments/assets/65c2292b-0720-4db4-a6be-f5f970b3770e" alt="logo" width="240">
</p>

# 🦊 Fox OSINT

**Fox OSINT** is a modern cyber reconnaissance tool designed for security researchers and OSINT enthusiasts.  
It automates information gathering for any domain or organization by combining DNS lookup, subdomain discovery, port scanning, and service checking — all with a stylish cyber fox terminal banner.

---

## 🔍 What does Fox OSINT do?

- **DNS Enumeration:**  
  Retrieves all major DNS record types (A, AAAA, MX, NS, CNAME, TXT) for any domain.

- **Port Scanning:**  
  Scans the most critical/common ports (like 80, 443, 22, etc.) and identifies running services.

- **Subdomain Discovery:**  
  Uses [crt.sh](https://crt.sh/) to find subdomains registered in public certificate transparency logs.

- **IP Resolution:**  
  Resolves the IP address of every discovered subdomain.

- **Subdomain Status Check:**  
  Automatically checks if each subdomain is live over HTTP and HTTPS.


---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/pfix0/fox-osint.git
cd fox-osint
pip install -r requirements.txt
python fox_osint.py
