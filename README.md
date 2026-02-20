# 🛡 IP Investigate Automation Tool

A Cyber Threat Intelligence automation tool built using Flask.

This tool allows SOC analysts, cybersecurity students, and threat hunters to scan bulk IP addresses and check their malicious reputation using:

- VirusTotal (Engine detection percentage)
- AbuseIPDB (Abuse confidence score)

---

## 🚀 Features

- Bulk IP scanning from uploaded .txt files
- VirusTotal API v3 integration
- AbuseIPDB API v2 integration
- Automatic private IP filtering
- CSV result generation
- Export only malicious IPs (VT > 50%)
- Secure API key management using `.env`
- Clean cyber-themed web interface

---

## 📂 Project Structure
