import os
import oci


def get_config_and_signer():
    profile = os.getenv("OCI_PROFILE", "DEFAULT")
    config = oci.config.from_file(profile_name=profile)
    signer = oci.signer.Signer(
        tenancy=config["tenancy"],
        user=config["user"],
        fingerprint=config["fingerprint"],
        private_key_file_location=config["key_file"],
        pass_phrase=config.get("pass_phrase"),
    )
    return config, signer


def ensure_bucket(os_client, namespace: str, compartment_id: str, bucket_name: str):
    try:
        os_client.get_bucket(namespace_name=namespace, bucket_name=bucket_name)
        return "exists"
    except oci.exceptions.ServiceError as e:
        if e.status != 404:
            raise

    details = oci.object_storage.models.CreateBucketDetails(
        name=bucket_name,
        compartment_id=compartment_id,
        public_access_type="NoPublicAccess",
        storage_tier="Standard",
        versioning="Disabled",
    )
    os_client.create_bucket(namespace_name=namespace, create_bucket_details=details)
    return "created"


def upload_file(os_client, namespace: str, bucket_name: str, object_name: str, local_path: str):
    with open(local_path, "rb") as f:
        os_client.put_object(
            namespace_name=namespace,
            bucket_name=bucket_name,
            object_name=object_name,
            put_object_body=f,
        )
