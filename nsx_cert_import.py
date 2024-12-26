# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "click",
#     "requests",
#     "python-dotenv"
# ]
# ///
import click
import requests
import os
from dotenv import load_dotenv
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env_nsx"))

@click.command()
@click.option("--cert-name", required=True, help="The name of the certificate.")
@click.option("--cert-file", required=True, help="The path to the certificate file (PEM format).")
@click.option("--key-file", default="private.key", help="The path to the private key file (PEM format).")
@click.option("--key-pass",  help="The passphrase for the private key file (if any).")
def main(cert_name, cert_file, key_file, key_pass):
    """
    Imports a certificate and private key to NSX-T manager.
    """
    nsx_host = os.getenv("NSX_MANAGER_ADDRESS")
    nsx_user = os.getenv("NSX_USERNAME")
    nsx_password = os.getenv("NSX_PASSWORD")

    if not all([nsx_host, nsx_user, nsx_password]):
        print("Error: NSX connection details not found in .env_nsx file.")
        return

    try:
        with open(cert_file, 'r') as f:
            cert_content = f.read()
        with open(key_file, 'r') as f:
            key_content = f.read()
    except FileNotFoundError:
        print("Error: Certificate or key file not found.")
        return

    
    url = f"https://{nsx_host}/api/v1/trust-management/certificates?action=import"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if key_pass is None:
        key_pass = nsx_password
    payload = {
        "display_name": cert_name,
        "pem_encoded": cert_content,
        "private_key": key_content,
        "passphrase": key_pass
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, auth=(nsx_user, nsx_password), verify=False)
        response.raise_for_status()
        print("Certificate imported successfully.")
        print(response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error importing certificate: {e}")
        if response.text:
            print(f"Response: {response.text}")


if __name__ == "__main__":
    main()