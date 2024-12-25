# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests",
#     "python-dotenv",
#     "cryptography",
#     "click",
#     "rich"
# ]
# ///
import os
import requests
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import click
import subprocess
import urllib3
import shlex
from rich.console import Console
from rich import print
import json

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
OUTPUT_DIR = "certs"
PRIVATE_KEY_FILE = "private.key"
# OID Mapping for Extended Key Usage
EKU_OID_TO_NAME = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
}

# Initialize rich console
console = Console()

def load_nsx_config(env_file=".env_nsx"):
    """Loads NSX configuration from a .env file."""
    load_dotenv(dotenv_path=env_file)
    manager_address = os.getenv("NSX_MANAGER_ADDRESS")
    username = os.getenv("NSX_USERNAME")
    password = os.getenv("NSX_PASSWORD")
    if not all([manager_address, username, password]):
        raise ValueError(
            "Missing required NSX configuration in .env_nsx file. "
            "Please ensure NSX_MANAGER_ADDRESS, NSX_USERNAME, and NSX_PASSWORD are set."
        )
    return manager_address, username, password

def get_nsx_certificates(manager_address, username, password, verify_ssl=False):
    """Retrieves certificates from NSX-T Manager."""
    url = f"https://{manager_address}/api/v1/trust-management/certificates"
    auth = (username, password)
    headers = {"Accept": "application/json"}
    try:
        response = requests.get(url, auth=auth, headers=headers, verify=verify_ssl)
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError:
            raise Exception(f"Invalid JSON response from NSX Manager: {response.text}")
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError):
            print(
                f"[bold red]HTTP Error:[/bold red] {e.response.status_code} - {e.response.reason}"
            )
            print(f"[bold red]Response Body:[/bold red] {e.response.text}")
        else:
            print(f"[bold red]Request Exception:[/bold red] {e}")
        raise Exception(f"Error fetching certificates from NSX Manager: {e}")

def save_certificate(cert_pem, cert_name, output_dir=OUTPUT_DIR, suffix=""):
    """Saves a certificate to a file in DER format (.cer) using provided name."""
    os.makedirs(output_dir, exist_ok=True)
    file_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in cert_name)
    file_path = os.path.join(output_dir, f"{file_name}{suffix}.cer")
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
        with open(file_path, "wb") as f:
            f.write(cert_der)
        print(f"  Certificate saved to: {file_path}")
    except Exception as e:
        print(f"[bold red]Error saving certificate to file:[/bold red] {e}")
        raise

def extract_cert_info(cert_pem):
    """Extracts relevant information from a certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Extract Subject information
    subject_str = ""
    for name in cert.subject:
        subject_str += f"/{name.oid.dotted_string}={name.value}"

    # Extract Subject Alternative Names
    san_list = []
    try:
        san_extension = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for san in san_extension.value:
            san_list.append(str(san.value))
    except x509.ExtensionNotFound:
        pass
    san_string = "\n".join([f"DNS.{i + 1} = {san}" for i, san in enumerate(san_list)])

    # Extract Extended Key Usage
    eku_list = []
    try:
        eku_extension = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        )
        for eku in eku_extension.value:
            eku_list.append(EKU_OID_TO_NAME.get(eku.dotted_string, eku.dotted_string))
    except x509.ExtensionNotFound:
        pass
    eku_string = ", ".join(eku_list)

    # Extract Basic Constraints
    basic_constraints = None
    try:
        basic_constraints_extension = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        if basic_constraints_extension.value.ca:
            basic_constraints = "CA:TRUE"
        else:
            basic_constraints = "CA:FALSE"
    except x509.ExtensionNotFound:
        pass

    return subject_str, san_string, eku_string, basic_constraints

def generate_openssl_config(cert_pem, cert_name, output_dir=OUTPUT_DIR):
    """Generates an OpenSSL configuration file from an existing certificate."""
    os.makedirs(output_dir, exist_ok=True)
    file_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in cert_name)
    config_path = os.path.join(output_dir, f"{file_name}.conf")
    try:
        subject_str, san_string, eku_string, basic_constraints = extract_cert_info(
            cert_pem
        )

        config_content = f"""
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
# This section is not used, the subject is passed via -subj

[v3_req]
"""
        if eku_string:
            config_content += f"extendedKeyUsage = {eku_string}\n"

        if san_string:
            config_content += f"subjectAltName = @alt_names\n"

        config_content += f"""
subjectKeyIdentifier = hash
"""
        if basic_constraints:
            config_content += f"basicConstraints = {basic_constraints}\n"

        if san_string:
            config_content += f"""
[alt_names]
{san_string}
"""
        with open(config_path, "w") as f:
            f.write(config_content)
        print(f"  OpenSSL config file saved to: {config_path}")
        return config_path, subject_str
    except Exception as e:
        print(f"[bold red]Error creating OpenSSL config file:[/bold red] {e}")
        raise

def generate_private_key(key_path=PRIVATE_KEY_FILE, password=None):
    """Generates a private key if it doesn't exist."""
    if not os.path.exists(key_path):
        print(f"  Private key not found, generating a new one at: {key_path}")
        try:
            cmd = ["openssl", "genrsa"]
            if password:
                cmd.extend(["-des3", "-passout", f"pass:{password}"])
            cmd.extend(["-out", key_path, "2048"])

            print(
                f"  Executing: \n{' '.join(cmd).replace(f'-passout pass:{password}', '-passout pass:********')}"
            )
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, cmd, result.stdout, result.stderr
                )
            print(f"  Private key generated at: {key_path}")
        except subprocess.CalledProcessError as e:
            print(f"[bold red]Error generating private key:[/bold red] {e}")
            if e.stderr:
                print(f"[bold red]OpenSSL Error Output:[/bold red]\n{e.stderr}")
            raise
    else:
        print(f"  Private key found at: {key_path}")
    return key_path

def generate_csr(key_path, config_path, subject_str, cert_name, password=None):
    """Generates a CSR using OpenSSL."""
    file_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in cert_name)
    csr_path = os.path.join(OUTPUT_DIR, f"{file_name}.csr")

    # Reformat subject string to handle hyphens in CN
    subject_parts = subject_str.split("/")
    formatted_subject_parts = []
    for part in subject_parts:
        if part.startswith("2.5.4.3="):  # CN
            cn_value = part.split("=", 1)[1]
            if cn_value.startswith("-"):
                formatted_subject_parts.append(f"2.5.4.3=x{cn_value}")
            else:
                formatted_subject_parts.append(part)
        else:
            formatted_subject_parts.append(part)
    formatted_subject_str = "/".join(formatted_subject_parts)

    try:
        cmd = [
            "openssl",
            "req",
            "-new",
            "-batch",
            "-key",
            key_path,
            "-out",
            csr_path,
            "-config",
            config_path,
            "-subj",
            formatted_subject_str,
        ]
        if password:
            cmd.extend(["-passin", f"pass:{password}"])

        # Manually construct the command string for printing
        print_cmd = ["openssl", "req", "-new", "-batch", "-key", key_path, "-out", shlex.quote(csr_path), "-config", shlex.quote(config_path), "-subj", shlex.quote(formatted_subject_str)]
        if password:
            print_cmd.extend(["-passin", "pass:********"])
        print(f"  Executing: \n{' '.join(print_cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        print(f"  CSR generated at: {csr_path}")
        return csr_path
    except subprocess.CalledProcessError as e:
        print(f"[bold red]Error generating CSR:[/bold red] {e}")
        if e.stderr:
            print(f"[bold red]OpenSSL Error Output:[/bold red]\n{e.stderr}")
        raise

def generate_self_signed_cert(key_path, csr_path, config_path, subject_str, cert_name, password=None):
    """Generates a self-signed certificate using OpenSSL."""
    file_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in cert_name)
    cert_path = os.path.join(OUTPUT_DIR, f"{file_name}-new.pem")
    try:
        cmd = [
            "openssl",
            "x509",
            "-req",
            "-in",
            csr_path,
            "-signkey",
            key_path,
            "-out",
            cert_path,
            "-days",
            "3650",
            "-extfile",
            config_path,
            "-extensions",
            "v3_req",
            "-set_issuer",
            subject_str,
        ]
        if password:
            cmd.extend(["-passin", f"pass:{password}"])

        # Manually construct the command string for printing
        print_cmd = ["openssl", "x509", "-req", "-in", shlex.quote(csr_path), "-signkey", key_path, "-out", shlex.quote(cert_path), "-days", "3650", "-extfile", shlex.quote(config_path), "-extensions", "v3_req", "-set_issuer", shlex.quote(subject_str)]
        if password:
            print_cmd.extend(["-passin", "pass:********"])
        print(f"  Executing: \n{' '.join(print_cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        print(f"  Self-signed certificate generated at: {cert_path}")
        return cert_path
    except subprocess.CalledProcessError as e:
        print(f"[bold red]Error generating self-signed certificate:[/bold red] {e}")
        if e.stderr:
            print(f"[bold red]OpenSSL Error Output:[/bold red]\n{e.stderr}")
        raise

def find_certificate_by_name_or_id(certs_data, cert_name):
    """Finds a certificate by its name or ID in the provided certificate data."""
    if "results" not in certs_data:
        raise Exception(f"Unexpected response format: {certs_data}")

    for cert in certs_data["results"]:
        if "id" in cert and cert["id"] == cert_name:
            if "pem_encoded" in cert:
                return cert
            else:
                raise Exception(
                    f"Certificate with ID '{cert_name}' is missing 'pem_encoded' field."
                )
        elif "display_name" in cert and cert["display_name"] == cert_name:
            if "pem_encoded" in cert:
                return cert
            else:
                raise Exception(
                    f"Certificate with name '{cert_name}' is missing 'pem_encoded' field."
                )
    return None

def clone_certificate(cert_name, manager_address, username, password):
    """Clones the specified certificate."""
    print(f"Connecting to NSX Manager at: {manager_address}")
    certs_data = get_nsx_certificates(manager_address, username, password)

    found_cert = find_certificate_by_name_or_id(certs_data, cert_name)

    if found_cert:
        print("\n[bold green]Certificate Found:[/bold green]")
        save_certificate(found_cert["pem_encoded"], cert_name)

        config_path, subject_str = generate_openssl_config(
            found_cert["pem_encoded"], cert_name
        )
        key_path = generate_private_key(password=password)

        csr_path = generate_csr(
            key_path, config_path, subject_str, cert_name, password=password
        )
        new_cert_path = generate_self_signed_cert(
            key_path, csr_path, config_path, subject_str, cert_name, password=password
        )
        return new_cert_path
    else:
        raise Exception(f"Certificate with name or ID '{cert_name}' not found.")

def print_comparison_commands(cert_name, new_cert_path):
    """Prints OpenSSL commands to compare the original and new certificates."""
    print("\n[bold green]Certificate cloning process completed successfully.[/bold green]")
    file_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in cert_name)
    old_cert_path = os.path.join(OUTPUT_DIR, f"{file_name}.cer")
    print("\n[bold]OpenSSL commands to compare certificates:[/bold]")
    print(
        f"  [dim]Old Certificate:[/dim] \nopenssl x509 -in {old_cert_path} -inform der -text"
    )
    print(
        f"  [dim]New Certificate:[/dim] \nopenssl x509 -in {new_cert_path} -text"
    )

@click.command()
@click.argument("cert_name")
def main(cert_name):
    """Main function to download and generate certificates."""
    try:
        print(
            "[bold blue]NSX Certificate Cloning Tool[/bold blue]\n----------------------------------------"
        )
        manager_address, username, password = load_nsx_config()

        new_cert_path = clone_certificate(cert_name, manager_address, username, password)

        print_comparison_commands(cert_name, new_cert_path)

    except Exception as e:
        print(f"\n[bold red]An error occurred:[/bold red] {e}")
        exit(1)
    print("----------------------------------------")

if __name__ == "__main__":
    main()
