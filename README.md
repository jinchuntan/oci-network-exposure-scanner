# OCI Network Exposure Scanner

Scans OCI Security Lists and Network Security Groups (NSGs) for inbound TCP rules that allow 0.0.0.0/0 on common ports (SSH/RDP/HTTP/HTTPS). Generates JSON + Markdown reports and uploads them to Object Storage.

## Setup and Run

Run these commands from the repository root with Python 3.11 or newer.
Configure OCI API-key authentication in `~/.oci/config` first
(`%USERPROFILE%\.oci\config` on Windows).

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
.\.venv\Scripts\python.exe src/main.py
```

### macOS / Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
# Edit .env with your compartment OCID and destination bucket before running.
.venv/bin/python src/main.py
```

Copy the template only on first setup; keep an existing `.env` when updating.
If your Windows installation uses `python` instead of `py -3.11`, substitute
that command when creating the environment. No environment activation is needed.

### Configuration and Permissions

| Setting | Meaning |
| --- | --- |
| `OCI_COMPARTMENT_OCID` | Required: the compartment to inspect. |
| `OCI_BUCKET_NAME` | Required: the destination bucket for reports. |
| `OCI_OBJECT_PREFIX` | Report object prefix; defaults to `network-exposure`. |
| `OCI_PROFILE` | OCI SDK profile name; defaults to `DEFAULT`. |

The configured identity must be allowed to read Security Lists, NSGs and their rules,
resolve the Object Storage namespace, and upload objects to the selected bucket.
The script checks the bucket and creates a private bucket if it is missing,
so it also needs permission to read the bucket and create it when necessary.
Reports are saved under `reports/` before upload. Resource collection is read-only,
but uploading reports writes to Object Storage.

Local `.env` files, signing keys, environments and generated reports are ignored by Git.

## Project

**Title:** OCI Network Exposure Scanner – Security List and NSG Rule Audit with Uploaded Reports
**Description:**
Built a standalone Python tool using the OCI Python SDK to audit network exposure across a target compartment. The script enumerates Security Lists and Network Security Groups (NSGs), analyzes ingress TCP rules, and flags configurations that allow 0.0.0.0/0 access on common ports such as SSH (22) and RDP (3389). It generates timestamped JSON and Markdown reports and uploads the artifacts to OCI Object Storage for traceable evidence and review. Screenshots include script execution output and the uploaded report objects visible in OCI Console.
**Tags:** OCI, Networking, Virtual Cloud Network (VCN), Network Security Groups, Security Lists, Python, SDK, Object Storage

## Output

<img width="940" height="145" alt="image" src="https://github.com/user-attachments/assets/79df68d1-442e-4f61-b09e-dc3e23151fe8" />
<img width="940" height="464" alt="image" src="https://github.com/user-attachments/assets/71db802d-02de-4be4-a1e6-0a21b099b745" />


