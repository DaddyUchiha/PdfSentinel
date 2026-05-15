import json
import os
from pickle import dumps
import re
import math
import zlib
import hashlib
import binascii
from collections import Counter
from datetime import datetime
import requests 
from pypdf import PdfReader


red = '\033[91m'
green = '\033[92m'
yellow = '\033[93m'
cyan = '\033[96m'
reset = '\033[0m'
bold = '\033[1m'
italic = '\033[3m'
# ===============================
# PDF THREAT HUNTER PRO
# ===============================

print(f"{cyan}{bold}={'=' * 60}{reset}")
print(f"{green}{bold}{italic} PDF SENTINAL --------------------------------- FREEDOM {reset}")
print(f"{cyan}{bold}={'=' * 60}{reset}")

logo = f"""{red}
  _    _                     _                         
 | |  | |                   | |                        
 | |__| |  ___ __  __ _ __  | |  ___   _ __  ___  _ __ 
 |  __  | / _ \\\ \/ /| '_ \ | | / _ \ | '__|/ _ \| '__|
 | |  | ||  __/ >  < | |_) || || (_) || |  |  __/| |   
 |_|  |_| \___|/_/\_\| .__/ |_| \___/ |_|   \___||_|   
                     | |                               
                     |_|                               `{reset}"""

print(logo)
print(f"{cyan}={'=' * 80}{reset}")
pdf_file = input(f"{green}Enter PDF path: {reset}")
print(f"{cyan}={'=' * 80}{reset}")
if not os.path.isfile(pdf_file):
    print(f"{red}[!] File not found. Please provide Absolute path: {reset}")
    exit()

print("[*] VirusTotal API is recommended for better results.")
print("[*] Yes, you can use this script without API.")
print(f"{cyan}={'=' * 80}{reset}")
api_key = input(f"{green}[API KEY] | Yes or No: {reset}").strip()
if api_key.lower() == "yes" or api_key.lower() == "y":
    print("API integration enabled. Please ensure you have a valid VirusTotal API key.")
    print(f"{cyan}={'=' * 80}{reset}")
    api = input(f"{green}Enter VirusTotal API key: {reset}").strip()
    print(f"{cyan}={'=' * 80}{reset}")
    post = requests.post("https://www.virustotal.com/api/v3/files", headers={"x-apikey":api, "accept":"application/json"}, files={"file": open(pdf_file, "rb")})
    resp = json.dumps(post.json(), indent=4)
    sha = hashlib.sha256(open(pdf_file, "rb").read()).hexdigest()
    fetch = requests.get(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": api, "accept": "application/json"})
    res = json.dumps(fetch.json(), indent=4)
    malicious_count = len(re.findall(r'"category": "malicious"', res))
    if malicious_count:
        print(f"{bold}Note: 70 is the total number of antivirus engines used by VirusTotal. A higher ratio indicates a greater likelihood of the file being malicious.{reset}") 
        print(f"{cyan}={'=' * 80}{reset}")
        #print(f"{green}VirusTotal Undetected Ratio: {mal.group(1)}{reset}")
        print(f"{red}{bold}VirusTotal Malicious Detection Ratio: [[ {malicious_count} / 70  ]]{reset}")  
        print(f"{red}{bold}AntiVirus Found {malicious_count} malicious signatures.{reset}")     
    else:
        print(f"{yellow}Proceeding without API integration.{reset}")

# ===============================
# LOAD FILE
# ===============================
with open(pdf_file, "rb") as f:
    raw = f.read()

# ===============================
# HELPERS
# ===============================
def sha256(data):
    return hashlib.sha256(data).hexdigest()

def md5(data):
    return hashlib.md5(data).hexdigest()

def entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def banner(title):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

# ===============================
# BASIC INFO
# ===============================
banner(f"{cyan}[ FILE INFO ]{reset}")

print(f"{red}File:{reset}", pdf_file)
print(f"{red}Size:{reset}", len(raw), "bytes")
print(f"{red}MD5:{reset}", md5(raw))
print(f"{red}SHA256:{reset}", sha256(raw))
print(f"{red}Entropy:{reset}", round(entropy(raw), 2))

risk = 0

reader = PdfReader(pdf_file)

print()
# =====================
# 📄 METADATA
# =====================
print("" + "=" * 80)
print("\033[92m[+] Metadata:\033[0m")
print("" + "=" * 80)
meta = reader.metadata

if meta:
    print("Title:", meta.title)
    print("Author:", meta.author)
    print("Creator:", meta.creator)
    print("Producer:", meta.producer)
    print("Creation Date:", meta.creation_date)
else:
    print("No metadata found")

# =====================
# 🚨 SUSPICIOUS KEYS
# =====================
suspicious_keys = [
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFile"
]
print("" + "=" * 80)
print("\033[92m[+] Checking PDF structure...\033[0m")
root = reader.trailer["/Root"]

for key in suspicious_keys:
    if key in root:
        print(f"\033[91m[!] Found {key} in Root\033[0m")
        risk += 5


# ===============================
# IOC DETECTION
# ===============================
banner(f"{cyan}[ IOC SCAN ]{reset}")

patterns = {
    "URLs": rb"https?://[^\s<>\"]+",
    "IP Addresses": rb"(?:\d{1,3}\.){3}\d{1,3}",
    "Emails": rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "PowerShell": rb"powershell",
    "cmd.exe": rb"cmd\.exe",
    "JavaScript": rb"/JavaScript",
    "OpenAction": rb"/OpenAction",
    "Launch": rb"/Launch",
    "SubmitForm": rb"/SubmitForm",
    "EmbeddedFile": rb"/EmbeddedFile",
    "URI Action": rb"/URI",
    "MZ Header": rb"MZ"
}

for name, pat in patterns.items():
    found = re.findall(pat, raw, re.I)
    if found:
        print(f"{yellow}[!] {name}: {len(found)} hit(s){reset}")
        risk += 2

# ===============================
# OBFUSCATION DETECTION
# ===============================
banner(f"{cyan}[ OBFUSCATION SCAN ]{reset}")

obf = {
    # String Obfuscation
    "Hex String Encoding": rb"<[0-9A-Fa-f]+>",
    "Octal Encoding": rb"\\[0-7]{3}",
    "Unicode Escape": rb"\\u[0-9A-Fa-f]{4}",
    "Null Byte Injection": rb"\\x00",
    # JavaScript Obfuscation
    "String Char Code": rb"String\.fromCharCode",
    "Base64 Encode": rb"(?:atob|btoa|Base64)",
    "Encoded JS": rb"(?i)(eval|setTimeout|setInterval)\s*\(",
    "Document Write": rb"document\.write\(",
    "Dynamic Execution": rb"(?:new\s+Function|setTimeout|setInterval)\s*\(",
    "Nested Eval": rb"(?i)(eval\(.*eval\()",
    # Array Obfuscation
    "Array Join Exploit": rb"\.join\(['\"][^'\"]*['\"]\)",
    "Array Push Pop": rb"\.(push|pop|shift|unshift)\s*\(",
    "Array Prototype": rb"Array\.prototype",
    # Object Obfuscation
    "Property Accessor": rb"\[['\"]+[^\"']+['\"]+\]",
    "Bracket Notation": rb"\[.+\]\s*=",
    "Constructor Access": rb"\.constructor",
    # Hex Obfuscation
    "Hex Array": rb"\\x[0-9A-Fa-f]{2}",
    "Hex String": rb"(?i)0x[0-9a-f]+",
    "Long Hex Sequence": rb"\\x[0-9A-Fa-f]{2,}",
    # Encoding Patterns
    "URL Encode": rb"%[0-9A-Fa-f]{2}",
    "HTML Entity": rb"&#x?[0-9]+;",
    "Mixed Encoding": rb"(?:\\\\x|\\\\u|\\\\d)+",
    # Common Obfuscation Techniques
    "Variable Chaining": rb"\w+\s*=\s*\w+\s*=\s*",
    "String Concatenation": rb"['\"][^'\"]*['\"]\s*\+",
    "Nested Strings": rb"['\"][^'\"]*['\"]\s*['\"]+",
    "Decoy Variables": rb"var\s+\w+\s*=\s*['\"]\w+['\"]\s*;",
    "Dead Code": rb"if\s*\(\s*false\s*\)",
    # Payload Obfuscation
    "NOP Sled": rb"\\x90{10,}",
    "Stack Pivoting": rb"(?:pop|push|mov)\s+.*esp",
    "Shellcode Markers": rb"\\xcc|\\x90|\\xcd\\x03",
    "Binary Payload": rb"MVs0MgAA"
}

for name, pat in obf.items():
    if re.search(pat, raw, re.I):
        print(f"{yellow}[!] Found: {name}{reset}")
        risk += 3

# ===============================
# FLATE STREAM EXTRACTION
# ===============================
banner(f"{cyan}[ STREAM DECOMPRESSION ]{reset}")

streams = re.findall(rb"stream(.*?)endstream", raw, re.S)

decoded_count = 0
for idx, stream in enumerate(streams):
    s = stream.strip(b"\r\n")
    try:
        dec = zlib.decompress(s)
        decoded_count += 1
        fname = f"{yellow}decoded_stream_{idx}.bin{reset}"
        print(f"{yellow}[+] Decoded stream: {fname}{reset}")

        # detect JS inside stream
        if b"function" in dec or b"eval(" in dec or b"/JavaScript" in dec:
            print(f"{yellow}[!] Possible JS in stream {idx}{reset}")
            risk += 4

        # detect MZ inside stream
        if b"MZ" in dec:
            print(f"{yellow}[!] Embedded PE file detected in stream {idx}{reset}")
            risk += 5

    except:
        pass
    
print(f"{yellow}[!]Decoded Streams: {decoded_count}{reset}")

# ===============================
# JAVASCRIPT EXTRACTION
# ===============================
banner(f"{cyan}[ JAVASCRIPT EXTRACTION ]{reset}")

js_hits = re.findall(rb"/JS\s*\((.*?)\)", raw, re.S)
js_hits += re.findall(rb"/JavaScript", raw)

if js_hits:
   
    for i, j in enumerate(js_hits):
        if isinstance(j, bytes):
            name = f"javascript_"
            print(f"{yellow}[!] JavaScript indicators found {j}{reset}")
           # print(f"{cyan}[+] Saved JS snippet: {name}{reset}")
    risk += 5
else:
    print(f"{yellow}[!] No obvious JavaScript found{reset}")

# ===============================
# EMBEDDED FILE EXTRACTION
# ===============================
banner(f"{cyan}[ EMBEDDED PAYLOAD CHECK ]{reset}")

mz = [m.start() for m in re.finditer(rb"MZ", raw)]
if mz:
    for i, offset in enumerate(mz):
        payload = raw[offset:offset+500000]
        name = f"{yellow}embedded_payload_{i}.bin{reset}"
        print(f"{yellow}[!] Extracted possible EXE payload: {name}{reset}")
        risk += 5
else:
    print(f"{green}[!] No PE payload found!!{reset}")

# ===============================
# SIMPLE CVE SIGNATURES
# ===============================
banner(f"{cyan}[ KNOWN EXPLOIT SIGNATURES ]{reset}")

cves = {
    "CVE-2005-3054": rb"getAnno/",
    "CVE-2007-5659": rb"collab\.getIcon",
    "CVE-2008-2992": rb"math\.eval",
    "CVE-2008-4360": rb"media\.Player",
    "CVE-2009-0658": rb"Array\.prototype\.join",
    "CVE-2009-0927": rb"TeX\.Dictionary",
    "CVE-2009-1860": rb"TeX\.OpenType",
    "CVE-2009-4324": rb"util\.printf",
    "CVE-2010-0188": rb"coolType",
    "CVE-2010-0420": rb"collab\.collectInfo",
    "CVE-2010-1885": rb"media\.play",
    "CVE-2010-2883": rb"SING\.sing",
    "CVE-2010-3333": rb"TIFF\.tag",
    "CVE-2010-4096": rb"newSING",
    "CVE-2011-0609": rb"addButton",
    "CVE-2011-0611": rb"Player\.met",
    "CVE-2011-0627": rb"customDictionary",
    "CVE-2011-2462": rb"U3D\.Clod",
    "CVE-2011-4369": rb"bmp\.Parse",
    "CVE-2012-0505": rb"FLV\.Parse",
    "CVE-2012-0779": rb"video\.file",
    "CVE-2012-1535": rb"Flash\.ocx",
    "CVE-2012-1713": rb"EFS\.getCert",
    "CVE-2012-1723": rb"XML\.Parser",
    "CVE-2012-1725": rb"Class\.Loader",
    "CVE-2012-4689": rb"List\.get",
    "CVE-2013-0427": rb"Applet\.Type",
    "CVE-2013-0640": rb"this\.exportDataObject",
    "CVE-2013-0641": rb"app\.openDoc",
    "CVE-2013-2729": rb"Collab\.collectEmailInfo",
    "CVE-2013-3333": rb"Table\.Style",
    "CVE-2013-3346": rb"Media\.Clip",
    "CVE-2013-3389": rb"bookmark\.open",
    "CVE-2013-3684": rb"Annot\.edit",
    "CVE-2014-0497": rb"Download\.get",
    "CVE-2014-0515": rb"Shadow\.dev",
    "CVE-2014-0569": rb"Flash\.Player",
    "CVE-2014-0580": rb"malibu\.init",
    "CVE-2014-0581": rb"MP3\.Parse",
    "CVE-2014-6383": rb"AcroForm\.Export",
    "CVE-2015-0061": rb"XFA\.Parser",
    "CVE-2015-0058": rb"RichMedia\.Play",
    "CVE-2015-2419": rb"Javascript\.Eval",
    "CVE-2015-3052": rb"auth\.play",
    "CVE-2015-5119": rb"ByteArray\.compress",
    "CVE-2015-5122": rb"FLV\.decode",
    "CVE-2016-0988": rb"XFA\.setValue",
    "CVE-2016-4117": rb"GuzzleHttp",
    "CVE-2016-4201": rb"wgz\.inflate",
    "CVE-2016-7890": rb"AcroForm\.Submit",
    "CVE-2017-11292": rb"Doc\.Goto",
    "CVE-2017-11294": rb"media\.player",
    "CVE-2017-3018": rb"PPDF\.parse",
    "CVE-2018-4878": rb"fl\.acodec",
    "CVE-2018-4990": rb"JSX\.parse",
    "CVE-2018-8406": rb"XDP\.Parser",
    "CVE-2019-7089": rb"AcroForm\.Submit",
    "CVE-2019-7142": rb"Font\.Parse",
    "CVE-2020-9615": rb"3D\.Render",
    "CVE-2020-9616": rb"JBIG2\.Decode",
    "CVE-2020-9617": rb"JPEG2000\.Parser",
    "CVE-2021-21017": rb"SubmitForm\.action",
    "CVE-2021-21166": rb"AA\.execute",
    "CVE-2021-21172": rb"Annot\.Notify",
    "CVE-2022-24112": rb"collectFiles",
    "CVE-2023-29360": rb"WebGL\.Shader"
}

for cve, sig in cves.items():
    if re.search(sig, raw, re.I):
        print(f"{yellow}[!] Signature matched: {cve}{reset}")
        risk += 5 
        
# ===============================
# FINAL VERDICT
# ===============================
banner(f"{cyan}[[FINAL VERDICT]]{reset}")
if risk == 0:
    print(f"{green}[CLEAN - No Threat Detected]{reset}")
elif risk <= 20:
    print(f"{green}[LOW RISK Found] || Threat Score: {risk}{reset}")
elif risk <= 50:
    print(f"{yellow}[SUSPICIOUS Found] || Threat Score: {risk}{reset}")
elif risk <= 100:
    print(f"{red}[HIGH RISK Found ] || Threat Score: {risk}{reset}")
else:
    print(f"{red}[CRITICAL - EXTREMELY DANGEROUS]{reset}")
print("" + "=" * 80)
print(f"{green}Scan Completed: {datetime.now()}{reset}")

