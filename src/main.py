import os
from pathlib import Path

import oci
from dotenv import load_dotenv

from oci_helpers import get_config_and_signer, ensure_bucket, upload_file
from scan import scan_security_lists, scan_nsgs
from report import ts_utc, write_json, write_md


def require(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise SystemExit(f"ERROR: Missing env var: {name}")
    return v


def main():
    load_dotenv()

    compartment_id = require("OCI_COMPARTMENT_OCID")
    bucket_name = require("OCI_BUCKET_NAME")
    prefix = os.getenv("OCI_OBJECT_PREFIX", "network-exposure")

    config, signer = get_config_and_signer()
    vcn_client = oci.core.VirtualNetworkClient(config, signer=signer)
    os_client = oci.object_storage.ObjectStorageClient(config, signer=signer)
    namespace = os_client.get_namespace().data

    findings = []
    findings += scan_security_lists(vcn_client, compartment_id)
    findings += scan_nsgs(vcn_client, compartment_id)

    stamp = ts_utc()
    reports_dir = Path("reports")
    json_path = reports_dir / f"network_exposure_{stamp}.json"
    md_path = reports_dir / f"network_exposure_{stamp}.md"

    write_json(findings, json_path)
    write_md(findings, md_path)

    status = ensure_bucket(os_client, namespace, compartment_id, bucket_name)
    upload_file(os_client, namespace, bucket_name, f"{prefix}/{json_path.name}", str(json_path))
    upload_file(os_client, namespace, bucket_name, f"{prefix}/{md_path.name}", str(md_path))

    print("Scan complete.")
    print(f"Bucket: {bucket_name} ({status})")
    print(f"Findings: {len(findings)}")
    print(f"Uploaded: {prefix}/{json_path.name}")
    print(f"Uploaded: {prefix}/{md_path.name}")


if __name__ == "__main__":
    main()
