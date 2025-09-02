# rarADSExtractor

## What Problem Does This Tool Solve?

Recent **WinRAR 0-day vulnerabilities** — including [CVE-2025-8088](https://thehackernews.com/2025/08/winrar-zero-day-under-active.html) and [CVE-2025-6218](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/) — have highlighted how attackers abuse WinRAR archives in phishing and intrusion campaigns.  

Adversaries are weaponizing RAR archives by:
- Embedding **Alternate Data Streams (ADS)** inside files in the archive
- Using **malformed headers** or **XTRA blocks** to bypass detection
- Leveraging WinRAR parsing vulnerabilities to achieve **code execution** when archives are opened

Traditional tools like `unrar.exe` or WinRAR’s GUI:
- Can be **dangerous to run** on malicious samples (risk of exploitation)
- May **not expose hidden ADS streams** directly
- Are often unsuitable for automated SOC/IR pipelines

**This tool provides a safe, Python-only parser** that allows **Incident Responders, Threat Hunters, and SOC analysts** to inspect suspicious RAR5 archives, carve out ADS payloads, and analyze them **without invoking vulnerable binaries**.

---

## How It Works

1. **RAR5 Parsing in Pure Python**  
   - Validates the RAR5 magic header  
   - Iterates through RAR5 headers (`HEAD_TYPE`, `HEAD_FLAGS`)  
   - Extracts **header body**, **extra area**, and **data area**  

2. **ADS Detection**  
   - Scans for `:<streamname>` markers that indicate **Alternate Data Streams**  
   - Handles streams embedded in `XTRA` blocks and across header/data areas  

3. **Safe Extraction**  
   - Dumps the raw ADS bytes to an output directory  
   - Filenames follow the pattern:  
     ```
     <basefilename>__<streamname>
     ```

4. **Automatic Decoding (when possible)**  
   - If the ADS is **stored (uncompressed)** as plain text, the tool attempts to decode it:  
     - UTF-8 / UTF-16 / UTF-32 / Latin-1  
     - If successful → creates an additional `*.decoded.txt` file with the readable content  
   - If the ADS is **RAR-compressed or encrypted**, the tool still preserves the raw bytes for further analysis  

---

## Why This Matters for SOC/IR

- **Safe Analysis** → avoids risky execution of WinRAR or `unrar.exe`  
- **Visibility** → uncovers hidden ADS streams often abused in malware delivery  
- **Automation-Friendly** → Python-only, no external dependencies, easy to integrate into SOC pipelines  
- **Detection & Hunting** → enables responders to quickly inspect suspicious archives seen in campaigns exploiting **CVE-2025-8088** and **CVE-2025-6218**

---

## Usage

```bash
python rarADSExtractor.py suspicious.rar ADS_DUMP
```

---

## Output 
[+] invoice.pdf :: Zone.Identifier -> ADS_DUMP/invoice_pdf__Zone.Identifier (123 bytes)
    [decoded via text:utf-16le] ADS_DUMP/invoice_pdf__Zone.Identifier.decoded.txt
    [preview] [ZoneTransfer]\nZoneId=3\nReferrerUrl=hxxp://malicious[.]site\n...
