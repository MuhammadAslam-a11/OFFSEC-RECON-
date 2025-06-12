<p align="center">
  <img src="https://i.imgur.com/YOUR_LOGO.jpg" alt="OFFSEC RECON Logo">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square">
  <img src="https://img.shields.io/badge/OSINT-Reconnaissance-red?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

<p align="center">
  <a href="https://twitter.com/YOUR_TWITTER"><b>Twitter</b></a> •
  <a href="https://github.com/YOUR_USERNAME"><b>GitHub</b></a> •
  <a href="https://YOUR_BLOG_URL"><b>Blog</b></a>
</p>

<h1 align="center">OFFSEC RECON</h1>
<p align="center">Comprehensive Offensive Security Reconnaissance Toolkit</p>

---

## Overview
OFFSEC RECON is an all-in-one web reconnaissance tool designed for penetration testers and security researchers. It combines multiple OSINT techniques into a single Python script (`recon_tool.py`) to quickly gather comprehensive target intelligence.

```bash
python3 recon_tool.py --full --url https://target.com
Features
Multi-Phase Reconnaissance:

DNS enumeration

Subdomain discovery

Port scanning

Directory brute-forcing

SSL certificate analysis

Intelligent Data Correlation:

Cross-reference results from different modules

Automatic false-positive reduction

Flexible Output:

Console reporting

JSON/TXT exports

Customizable verbosity levels

Installation
bash
# Clone repository
git clone https://github.com/MuhammadAslam-a11/OFFSEC-RECON-.git
cd OFFSEC-RECON

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x recon_tool.py
Quick Start
bash
# Full reconnaissance suite
./recon_tool.py --full --url https://example.com

# Targeted scans
./recon_tool.py --dns --url example.com
./recon_tool.py --subdomains --url example.com
./recon_tool.py --dirscan --url https://example.com -w wordlists/custom.txt
Command Reference
Option	Description
--url	Target URL/Domain
--full	Run all reconnaissance modules
--dns	DNS enumeration
--subdomains	Subdomain discovery
--dirscan	Directory brute-forcing
--ports	Port scanning
--ssl	SSL certificate analysis
-w	Custom wordlist for directory scan
-o OUTPUT_DIR	Custom output directory
-t THREADS	Thread count (default: 50)
Configuration
Create config.ini for API keys and settings:

ini
[apis]
shodan_key = YOUR_SHODAN_API
virustotal_key = YOUR_VT_API

[settings]
timeout = 30
threads = 75
wordlist = default.txt
Sample Output
text
[+] Target: https://example.com
[+] DNS Records:
    - A: 93.184.216.34
    - MX: mail.example.com
[+] Subdomains:
    - admin.example.com
    - dev.example.com
[+] Port Scan:
    - 80 (HTTP) OPEN
    - 443 (HTTPS) OPEN
[+] Directories:
    - /backup (403)
    - /admin (302)
Contribution
Contributions welcome! Follow these steps:

Fork the repository

Create feature branch (git checkout -b new-feature)

Commit changes (git commit -am 'Add feature')

Push to branch (git push origin new-feature)

Open a Pull Request
