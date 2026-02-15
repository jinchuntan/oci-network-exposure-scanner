# OCI Network Exposure Scanner

Scans OCI Security Lists and Network Security Groups (NSGs) for inbound TCP rules that allow 0.0.0.0/0 on common ports (SSH/RDP/HTTP/HTTPS). Generates JSON + Markdown reports and uploads them to Object Storage.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
notepad .env
python .\src\main.py
```


## Project

**Title:** OCI Network Exposure Scanner – Security List and NSG Rule Audit with Uploaded Reports
**Description:**
Built a standalone Python tool using the OCI Python SDK to audit network exposure across a target compartment. The script enumerates Security Lists and Network Security Groups (NSGs), analyzes ingress TCP rules, and flags configurations that allow 0.0.0.0/0 access on common ports such as SSH (22) and RDP (3389). It generates timestamped JSON and Markdown reports and uploads the artifacts to OCI Object Storage for traceable evidence and review. Screenshots include script execution output and the uploaded report objects visible in OCI Console.
**Tags:** OCI, Networking, Virtual Cloud Network (VCN), Network Security Groups, Security Lists, Python, SDK, Object Storage

## Output

<img width="940" height="145" alt="image" src="https://github.com/user-attachments/assets/79df68d1-442e-4f61-b09e-dc3e23151fe8" />
<img width="940" height="464" alt="image" src="https://github.com/user-attachments/assets/71db802d-02de-4be4-a1e6-0a21b099b745" />


