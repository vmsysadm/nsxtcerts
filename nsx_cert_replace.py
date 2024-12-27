# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests",
#     "python-dotenv",
#     "click",
#     "rich",
#     "dateparser",
#     "cryptography"
# ]
# ///
import os
import requests
from dotenv import load_dotenv
import click
from rich.console import Console
from rich import print
import json
import urllib3
import dateparser
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize rich console
console = Console()


def load_nsx_config(env_file=".env_nsx"):
    """Loads NSX configuration from a .env file."""
    load_dotenv(dotenv_path=env_file)
    manager_address = os.getenv("NSX_MANAGER_ADDRESS")
    username = os.getenv("NSX_USERNAME")
    password = os.getenv("NSX_PASSWORD")
    debug_enabled = os.getenv("DEBUG") == "1" if os.getenv("DEBUG") else False
    if not all([manager_address, username, password]):
        raise ValueError(
            "Missing required NSX configuration in .env_nsx file. "
            "Please ensure NSX_MANAGER_ADDRESS, NSX_USERNAME, and NSX_PASSWORD are set."
        )
    return manager_address, username, password, debug_enabled


def get_nsx_certificates(manager_address, username, password, debug_enabled, verify_ssl=False):
    """Retrieves certificates from NSX-T Manager."""
    url = f"https://{manager_address}/api/v1/trust-management/certificates"
    auth = (username, password)
    headers = {"Accept": "application/json"}
    try:
        if debug_enabled:
            print(f"[bold blue]DEBUG:[/bold blue] GET {url}")
        response = requests.get(url, auth=auth, headers=headers, verify=verify_ssl)
        response.raise_for_status()
        try:
            if debug_enabled:
                print(f"[bold blue]DEBUG:[/bold blue] Response: {response.json()}")
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


def find_certificates_by_name(certs_data, cert_name, debug_enabled):
    """Finds all certificates matching the given name."""
    if "results" not in certs_data:
        raise Exception(f"Unexpected response format: {certs_data}")

    matching_certs = []
    for cert in certs_data["results"]:
        if "display_name" in cert and cert["display_name"] == cert_name:
            matching_certs.append(cert)
    if debug_enabled:
        print(f"[bold blue]DEBUG:[/bold blue] Matching certificates: {matching_certs}")
    return matching_certs


def format_expiration_date(cert_pem, debug_enabled):
    """Formats the expiration date from a PEM-encoded certificate."""
    if cert_pem:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            expiration_date = cert.not_valid_after_utc
            formatted_date = expiration_date.strftime("%Y-%m-%d %H:%M:%S")
            if debug_enabled:
                print(f"[bold blue]DEBUG:[/bold blue] Formatted Expiration Date: {formatted_date}")
            return formatted_date
        except Exception as e:
            print(f"[bold red]Error decoding certificate:[/bold red] {e}")
            return "Invalid Date"
    return "N/A"

def get_nsx_node_name(manager_address, username, password, node_id, debug_enabled, verify_ssl=False):
    """Retrieves the node name from NSX-T Manager using the node ID."""
    url = f"https://{manager_address}/api/v1/cluster/nodes/{node_id}"
    auth = (username, password)
    headers = {"Accept": "application/json"}
    try:
        if debug_enabled:
            print(f"[bold blue]DEBUG:[/bold blue] GET {url}")
        response = requests.get(url, auth=auth, headers=headers, verify=verify_ssl)
        response.raise_for_status()
        try:
            node_data = response.json()
            if debug_enabled:
                print(f"[bold blue]DEBUG:[/bold blue] Response: {node_data}")
            return node_data.get("display_name", "N/A")
        except json.JSONDecodeError:
            raise Exception(f"Invalid JSON response from NSX Manager: {response.text}")
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError):
            if e.response.status_code == 404:
                print(f"[bold red]Node Not Found:[/bold red] Node ID {node_id} not found in NSX.")
                return "N/A"
            print(
                f"[bold red]HTTP Error:[/bold red] {e.response.status_code} - {e.response.reason}"
            )
            print(f"[bold red]Response Body:[/bold red] {e.response.text}")
        else:
            print(f"[bold red]Request Exception:[/bold red] {e}")
        return "N/A"


def display_certificate_details(certificates, manager_address, username, password, debug_enabled):
    """Displays certificate details in a line-by-line format."""
    cert_ids = []
    for index, cert in enumerate(certificates):
        cert_id = cert["id"]
        cert_ids.append(cert_id)
        # Extract service types from the certificate object
        service_types = []
        used_by_data = cert.get("used_by")
        if used_by_data:
            for item in used_by_data:
                if "service_types" in item:
                    service_types.extend(item["service_types"])
        if debug_enabled:
            print(f"[bold blue]DEBUG:[/bold blue] Certificate object: {cert}")
        expiration_date = format_expiration_date(cert.get("pem_encoded"), debug_enabled)
        print(f"  [cyan]Index:[/cyan] {index + 1}")
        print(f"  [magenta]ID:[/magenta] {cert_id}")
        print(f"  [green]Name:[/green] {cert['display_name']}")
        if service_types:
            print(f"  [blue]Service Types:[/blue] {', '.join(service_types)}")
        else:
             print(f"  [blue]Service Types:[/blue] [bold red]NOT_USED[/bold red]")
        if "API" in service_types and used_by_data:
            for item in used_by_data:
                if "node_id" in item:
                    node_id = item["node_id"]
                    node_name = get_nsx_node_name(manager_address, username, password, node_id, debug_enabled)
                    print(f"  [blue]  Node ID:[/blue] {node_id} ([italic]{node_name}[/italic])")
                    break
        print(f"  [yellow]Expiration Date:[/yellow] {expiration_date}")
        if debug_enabled:
            print(f"  [bold blue]DEBUG:[/bold blue] Used By: {used_by_data}")
        print("-" * 40)
    return cert_ids

def apply_certificate_to_services(manager_address, username, password, cert_id, service_types, debug_enabled, old_cert_used_by, verify_ssl=False):
    """Applies the new certificate to the specified service types."""
    for service_type in service_types:
        url = f"https://{manager_address}/api/v1/trust-management/certificates/{cert_id}?action=apply_certificate&service_type={service_type}"
        if service_type == "API" and old_cert_used_by:
            for item in old_cert_used_by:
                if "node_id" in item:
                   node_id = item["node_id"]
                   url += f"&node_id={node_id}"
                   break
        auth = (username, password)
        headers = {"Accept": "application/json"}
        try:
            if debug_enabled:
                print(f"[bold blue]DEBUG:[/bold blue] POST {url}")
            response = requests.post(url, auth=auth, headers=headers, verify=verify_ssl)
            response.raise_for_status()
            if debug_enabled:
                 print(f"[bold blue]DEBUG:[/bold blue] Response: {response.text}")
            print(f"  Certificate applied to service type: {service_type}")
        except requests.exceptions.RequestException as e:
            if isinstance(e, requests.exceptions.HTTPError):
                print(
                    f"[bold red]HTTP Error:[/bold red] {e.response.status_code} - {e.response.reason}"
                )
                print(f"[bold red]Response Body:[/bold red] {e.response.text}")
            else:
                print(f"[bold red]Request Exception:[/bold red] {e}")
            raise Exception(f"Error applying certificate to service type {service_type}: {e}")


def replace_certificate(cert_name, manager_address, username, password, debug_enabled):
    """Replaces an existing certificate with a new one."""
    print(f"Connecting to NSX Manager at: {manager_address}")
    certs_data = get_nsx_certificates(manager_address, username, password, debug_enabled)

    matching_certs = find_certificates_by_name(certs_data, cert_name, debug_enabled)

    if not matching_certs:
        raise Exception(f"No certificates found with the name '{cert_name}'.")

    print(f"Found {len(matching_certs)} certificates with the name '{cert_name}':")
    cert_ids = display_certificate_details(matching_certs, manager_address, username, password, debug_enabled)

    while True:
        try:
            old_cert_index_str = input("Enter the index of the OLD certificate: ")
            if not old_cert_index_str:
                print("\nCertificate replacement aborted due to empty input.")
                return
            new_cert_index_str = input("Enter the index of the NEW certificate: ")
            if not new_cert_index_str:
                 print("\nCertificate replacement aborted due to empty input.")
                 return

            old_cert_index = int(old_cert_index_str) - 1
            new_cert_index = int(new_cert_index_str) - 1


            if 0 <= old_cert_index < len(matching_certs) and 0 <= new_cert_index < len(matching_certs):
                if old_cert_index == new_cert_index:
                    print("[bold red]Error:[/bold red] Old and new certificate cannot be the same.")
                    continue
                break
            else:
                print("[bold red]Error:[/bold red] Invalid index. Please try again.")
        except ValueError:
            print("[bold red]Error:[/bold red] Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nCertificate replacement aborted.")
            return
        except EOFError:
            print("\nCertificate replacement aborted due to empty input.")
            return


    old_cert = matching_certs[old_cert_index]
    new_cert = matching_certs[new_cert_index]

    print(f"  Selected old certificate: {old_cert['display_name']} (ID: {old_cert['id']})")
    print(f"  Selected new certificate: {new_cert['display_name']} (ID: {new_cert['id']})")

    # Extract service types from the old certificate object
    service_types = []
    used_by_data = old_cert.get("used_by")
    if used_by_data:
        for item in used_by_data:
            if "service_types" in item:
                service_types.extend(item["service_types"])
    print(f"  Old certificate service types: {service_types}")

    if "LOCAL_MANAGER" in service_types:
        print(f"  Replacing Principal Identity certificate for service type: LOCAL_MANAGER")
        apply_certificate_to_services(manager_address, username, password, new_cert["id"], ["LOCAL_MANAGER"], debug_enabled, old_cert.get("used_by"))
        # Ask for confirmation to apply to other service types, excluding CLIENT_AUTH
        other_service_types = [st for st in service_types if st != "LOCAL_MANAGER" and st != "CLIENT_AUTH"]
        if other_service_types:
            confirmation = input(f"Do you want to apply the new certificate to the other service types: {', '.join(other_service_types)}? (yes/no): ").lower()
            if confirmation == "yes":
                print(f"[bold yellow]Warning:[/bold yellow] The new certificate might not be valid for other service types. Proceed with caution.")
                apply_certificate_to_services(manager_address, username, password, new_cert["id"], other_service_types, debug_enabled, old_cert.get("used_by"))
        if "CLIENT_AUTH" in service_types:
            confirmation = input(f"The old certificate is also used for CLIENT_AUTH. Do you want to apply the new certificate to CLIENT_AUTH as well? (yes/no): ").lower()
            if confirmation == "yes":
                print(f"[bold yellow]Warning:[/bold yellow] Applying the new certificate to CLIENT_AUTH might impact client authentication. Proceed with caution.")
                apply_certificate_to_services(manager_address, username, password, new_cert["id"], ["CLIENT_AUTH"], debug_enabled, old_cert.get("used_by"))
    else:
    # Ask for confirmation
        confirmation = input("Do you want to apply the new certificate to the old certificate's service types? (yes/no): ").lower()
        if confirmation != "yes":
            print("Certificate replacement aborted.")
            return
        apply_certificate_to_services(manager_address, username, password, new_cert["id"], service_types, debug_enabled, old_cert.get("used_by"))

    print("\n[bold yellow]Note:[/bold yellow] It's possible that the old certificate might still show as expired in the NSX-T UI due to a known issue. Please refer to VMware KB article 314332 for more information and contact Broadcom Support if needed.")
    print("\n[bold green]Certificate replacement process completed successfully.[/bold green]")


@click.command()
@click.argument("cert_name")
def main(cert_name):
    """Main function to replace certificates."""
    try:
        print(
            "[bold blue]NSX Certificate Replacement Tool[/bold blue]\n----------------------------------------"
        )
        manager_address, username, password, debug_enabled = load_nsx_config()

        replace_certificate(cert_name, manager_address, username, password, debug_enabled)

    except Exception as e:
        print(f"\n[bold red]An error occurred:[/bold red] {e}")
        exit(1)
    print("----------------------------------------")


if __name__ == "__main__":
    main()