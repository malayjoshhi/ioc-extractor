# 🔍 Cyber Threat IOC Extractor & Defanger

A Threat Intelligence parsing tool built to scan raw text files, emails, or system logs and automatically extract and defang Indicators of Compromise (IOCs) such as IPv4 addresses, URLs, Email addresses, and Cryptographic File Hashes (MD5, SHA1, SHA256).

---

## 🌟 Features

- Extracts emails, URLs, IP addresses, and file hashes.
- Defangs malicious indicators (e.g., converts http:// to http[:]//) for safe reporting.
- Export results to firewalls or threat intelligence feeds.

---

## 🚀 Quick Start

```bash
# Parse sample threat report and print defanged IOCs
python main.py sample_threat_report.txt

# Export extracted IOCs to JSON file
python main.py sample_threat_report.txt -o ioc_feed.json
```
