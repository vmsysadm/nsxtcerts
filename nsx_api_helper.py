# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests",
#     "click",
#     "rich",
#     "python-dotenv"
# ]
# ///
import os
import requests
import click
from rich import print
import json
import urllib3
from dotenv import load_dotenv, set_key

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_nsx_config(env_file, fqdn=None):
    """Loads NSX configuration from a .env file."""
    load_dotenv(dotenv_path=env_file)
    manager_address = os.getenv("NSX_MANAGER_ADDRESS")
    username = os.getenv("NSX_USERNAME")
    password = os.getenv("NSX_PASSWORD")
    debug_enabled = os.getenv("DEBUG") == "1" if os.getenv("DEBUG") else False
    if fqdn:
         manager_address = fqdn
         set_key(env_file, "NSX_MANAGER_ADDRESS", fqdn)
         print(f"[bold green]NSX_MANAGER_ADDRESS updated to {fqdn} in {env_file}.[/bold green]")
    if not all([manager_address, username, password]):
        raise ValueError(
            "Missing required NSX configuration in .env file. "
            "Please ensure NSX_MANAGER_ADDRESS, NSX_USERNAME, and NSX_PASSWORD are set."
        )
    return manager_address, username, password, debug_enabled


def get_nsx_credentials(env_file, force_reenter):
    """Gets NSX credentials interactively or from .env file."""
    load_dotenv(dotenv_path=env_file)
    username = os.getenv("NSX_USERNAME")
    password = os.getenv("NSX_PASSWORD")

    if force_reenter or not username or not password:
        print("[bold yellow]NSX Credentials:[/bold yellow]")
        username = click.prompt("Username", type=str)
        password = click.prompt("Password", type=str, hide_input=True)
        set_key(env_file, "NSX_USERNAME", username)
        set_key(env_file, "NSX_PASSWORD", password)
        print(f"[bold green]Credentials set in {env_file} for future sessions.[/bold green]")
    elif username and password:
        print("[bold green]Using existing credentials from .env file.[/bold green]")
    return username, password


def make_nsx_api_call(manager_address, username, password, api_call, debug_enabled, json_data=None, verify_ssl=False):
    """Makes an API call to the NSX-T Manager and returns the raw JSON response."""
    auth = (username, password)
    headers = {"Accept": "application/json"}
    try:
        method, url = api_call.split(" ", 1) if " " in api_call else ("GET", api_call)
        url = url if url.startswith("https://") else f"https://{manager_address}{url}"

        if debug_enabled:
            print(f"[bold blue]DEBUG:[/bold blue] {method} {url}")

        method = method.upper()
        if method == "GET":
            response = requests.get(url, auth=auth, headers=headers, verify=verify_ssl, json=json_data)
        elif method == "POST":
             response = requests.post(url, auth=auth, headers=headers, verify=verify_ssl, json=json_data)
        elif method == "PUT":
            response = requests.put(url, auth=auth, headers=headers, verify=verify_ssl, json=json_data)
        elif method == "DELETE":
            response = requests.delete(url, auth=auth, headers=headers, verify=verify_ssl, json=json_data)
        elif method == "PATCH":
            response = requests.patch(url, auth=auth, headers=headers, verify=verify_ssl, json=json_data)
        else:
             response = requests.request(method, url, auth=auth, headers=headers, verify=verify_ssl, json=json_data)

        response.raise_for_status()
        if debug_enabled:
            print(f"[bold blue]DEBUG:[/bold blue] Response Headers: {response.headers}")
        
        if response.text:
            try:
                if debug_enabled:
                    print(f"[bold blue]DEBUG:[/bold blue] Response: {response.json()}")
                return response.json()
            except json.JSONDecodeError:
                print(f"[bold red]Error:[/bold red] Invalid JSON response from NSX Manager:")
                print(f"[bold red]Raw Response:[/bold red] {response.text}")
                raise Exception(f"Invalid JSON response from NSX Manager: {response.text}")
        else:
            if debug_enabled:
                print(f"[bold blue]DEBUG:[/bold blue] Empty Response Body.")
            return {} # Return empty dict for empty response
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError):
            print(
                f"[bold red]HTTP Error:[/bold red] {e.response.status_code} - {e.response.reason}"
            )
            print(f"[bold red]Response Body:[/bold red] {e.response.text}")
        else:
            print(f"[bold red]Request Exception:[/bold red] {e}")
        raise Exception(f"Error fetching data from NSX Manager: {e}")


@click.command()
@click.option("--env-file", default=".env_nsx", help="Path to the .env file")
@click.option("--fqdn", help="FQDN of the NSX-T Manager (optional)")
@click.option("--force-reenter", is_flag=True, help="Force re-entry of credentials")
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.option("--json-data", help="JSON data to send in the request body (optional)")
@click.argument("api_call")
def main(env_file, fqdn, force_reenter, debug, api_call, json_data):
    """Main function to make an API call and print the raw JSON response."""
    try:
        print(
            "[bold blue]NSX API Helper Tool[/bold blue]\n----------------------------------------"
        )
        manager_address, username, password, debug_enabled = load_nsx_config(env_file, fqdn)
        username, password = get_nsx_credentials(env_file, force_reenter)
        response_data = make_nsx_api_call(manager_address, username, password, api_call, debug_enabled, json.loads(json_data) if json_data else None)
        print(json.dumps(response_data, indent=2))
        if api_call.upper().startswith("POST") and not response_data:
            print(f"[bold yellow]Note:[/bold yellow] An empty JSON response from a POST request usually indicates success.")

    except Exception as e:
        print(f"\n[bold red]An error occurred:[/bold red] {e}")
        exit(1)
    print("----------------------------------------")


if __name__ == "__main__":
    main()