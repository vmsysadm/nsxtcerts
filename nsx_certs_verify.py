# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests",
#     "python-dotenv",
#     "click",
#     "rich"
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


def verify_principal_identity_certificate(manager_address, username, password, debug_enabled, verify_ssl=False):
    """Verifies and prints details of all Principal Identity certificates."""
    url = f"https://{manager_address}/api/v1/trust-management/principal-identities"
    auth = (username, password)
    headers = {"Accept": "application/json"}
    try:
        if debug_enabled:
            print(f"[bold blue]DEBUG:[/bold blue] GET {url}")
        response = requests.get(url, auth=auth, headers=headers, verify=verify_ssl)
        response.raise_for_status()
        if debug_enabled:
            print(f"[bold blue]DEBUG:[/bold blue] Response Status Code: {response.status_code}")
            print(f"[bold blue]DEBUG:[/bold blue] Response Headers: {response.headers}")
            print(f"[bold blue]DEBUG:[/bold blue] Response Text: {response.text}")
        try:
            response_json = response.json()
        except json.JSONDecodeError:
            print(f"[bold red]Error:[/bold red] Invalid JSON response: {response.text}")
            return
        if "results" in response_json:
            for item in response_json["results"]:
                name = item.get("name", "N/A")
                node_id = item.get("node_id", "N/A")
                cert_id = item.get("certificate_id", "N/A")
                role = item.get("role", "N/A")

                if name.startswith("LocalManagerIdentity"):
                    service_entity = "[cyan]Local Manager[/cyan]"
                elif name.startswith("GlobalManagerIdentity"):
                    service_entity = "[magenta]Global Manager[/magenta]"
                elif name.startswith("ClientAuthIdentity"):
                    service_entity = "[yellow]Client Auth[/yellow]"
                else:
                    service_entity = "[red]Unknown[/red]"


                print(f"  [bold]Service/Entity:[/bold] {service_entity}")
                print(f"  [bold]Location/Federation Node ID:[/bold] {node_id}")
                print(f"  [bold]Certificate ID:[/bold] {cert_id}")
                print(f"  [bold]Role:[/bold] {role}")
                print("-" * 40)
        else:
            print("[bold red]Error:[/bold red] No Principal Identity certificates found.")
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError):
            print(
                f"[bold red]HTTP Error:[/bold red] {e.response.status_code} - {e.response.reason}"
            )
            print(f"[bold red]Response Body:[/bold red] {e.response.text}")
        else:
            print(f"[bold red]Request Exception:[/bold red] {e}")
        raise Exception(f"Error verifying Principal Identity certificates: {e}")


@click.command()
def main():
    """Main function to verify Principal Identity certificates."""
    try:
        print(
            "[bold blue]NSX Principal Identity Certificate Verification Tool[/bold blue]\n----------------------------------------"
        )
        manager_address, username, password, debug_enabled = load_nsx_config()

        verify_principal_identity_certificate(manager_address, username, password, debug_enabled)

    except Exception as e:
        print(f"\n[bold red]An error occurred:[/bold red] {e}")
        exit(1)
    print("----------------------------------------")


if __name__ == "__main__":
    main()