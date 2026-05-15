# 🔥 Overview

PDF Sentinel is an advanced Python-based PDF threat hunting and malware analysis tool designed to detect malicious indicators, embedded payloads, exploit signatures, obfuscation techniques, suspicious JavaScript, and hidden threats inside PDF documents.

The tool combines:

Static PDF analysis
IOC (Indicators of Compromise) detection
Obfuscation analysis
Embedded payload discovery
Stream decompression
Known exploit signature matching
VirusTotal integration
Entropy-based anomaly detection

## It is built for:

SOC Analysts
Malware Researchers
DFIR Investigators
Threat Hunters
Security Researchers
Blue Team Operations
🚀 Features
✅ File Intelligence
SHA256 & MD5 Hash Generation
File Size Analysis
Shannon Entropy Detection
Risk Scoring Engine
✅ IOC Detection

## Detects:

URLs
IP Addresses
Emails
PowerShell Indicators
cmd.exe References
Suspicious URI Actions
Embedded Executables (MZ Header)
OpenAction & Launch Triggers
✅ Advanced Obfuscation Detection

## Identifies:

Hex Encoding
Unicode Escapes
Base64 Obfuscation
Eval-Based JavaScript
Dynamic Execution
Array/Object Obfuscation
Encoded Payloads
Shellcode Markers
NOP Sleds
Binary Payload Patterns
✅ PDF Stream Analysis
Extracts and decompresses Flate streams
Detects malicious JavaScript inside streams
Detects embedded PE executables
Identifies hidden payloads
✅ JavaScript Threat Detection

## Detects:

Embedded JS
Eval Usage
Dangerous Functions
Suspicious PDF JavaScript Actions
✅ Embedded Payload Discovery
Finds embedded PE files
Detects hidden executable payloads
Flags suspicious binaries
✅ CVE Exploit Signature Detection

## Includes signatures for dozens of known PDF exploits including:

Adobe Reader Exploits
Flash-based PDF Exploits
JBIG2 Exploits
JavaScript Engine Vulnerabilities
XFA Vulnerabilities
Rich Media Exploits
✅ VirusTotal Integration

## Optional VirusTotal API support:

Upload PDF for scanning
Retrieve AV engine detections
Malicious ratio analysis
Threat intelligence enrichment
🛡️ Threat Scoring Engine

## PDF Sentinel assigns a dynamic risk score based on:

Malicious indicators
Obfuscation techniques
Embedded executables
Exploit signatures
JavaScript behavior
Stream anomalies
Risk Levels
Score	Verdict
0	CLEAN
1–20	LOW RISK
21–50	SUSPICIOUS
51–100	HIGH RISK
100+	CRITICAL

## ⚙️ Technologies Used
* Python 3
* Regex Pattern Matching
* zlib Stream Decompression
* VirusTotal API
* Entropy Analysis
* Binary Inspection
* Static Malware Analysis Techniques
## Features

Malicious Ranking:

| Score  | Verdict    |
| ------ | ---------- |
| 0      | CLEAN      |
| 1–20   | LOW RISK   |
| 21–50  | SUSPICIOUS |
| 51–100 | HIGH RISK  |
| 100+   | CRITICAL   |

## Installation

Install PdfSentinel using git 

```bash
git clone https://github.com/DaddyUchiha/PdfSentinel
cd PdfSentinel
pip install requests
```

## Usage
```bash
python3 PdfSentinel.py
```
Enter the absolute path of the PDF file when prompted.

#### Optional:

* Enable VirusTotal API integration for enhanced detection.
## ⚠️ Disclaimer

This tool is intended for:

Educational purposes
Security research
Defensive security operations
Authorized malware analysis environments

Do not use this tool against systems or files you do not own or have permission to analyze.
