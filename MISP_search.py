#!/var/ossec/framework/python/bin/python3
# Copyright Whysecurity Srl Cellatica 2024.

# Import required libraries
import json
import sys
import ipaddress
import logging
import re
import urllib3
from socket import socket, AF_UNIX, SOCK_DGRAM

# Disable security warnings for unverified HTTPS connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import 'requests' library for HTTP requests and handle missing module
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global variables
debug_enabled = True  # Toggle debug mode
socket_addr = "/var/ossec/queue/sockets/queue"  # Default Wazuh socket path

# Configure logging to output to a file
logging.basicConfig(
    filename='debug.log',  # Log file path
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %H:%M:%S %Z %Y'
)

def main(args):
    """
    Main function to execute the script. It handles arguments, loads alerts, 
    and initiates MISP queries.
    """
    debug("Starting script execution")

    # Validate command-line arguments
    if len(args) < 3:
        logging.error("Usage: python script_name.py path_to_alerts.json api_key")
        sys.exit(1)

    # Retrieve arguments
    alert_file_location = args[1]  # Path to the alerts JSON file
    api_key = args[2]  # MISP API key

    debug("Loading and parsing alert file")
    # Load and parse the alert JSON file
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
    except Exception as e:
        logging.error(f"Failed to load or parse the alert file: {str(e)}")
        sys.exit(1)

    debug("Alert loaded successfully")
    # Query MISP for information based on extracted IPs
    misp_info = request_misp_info(json_alert, api_key)

    # Process the response if available
    if misp_info:
        process_misp_info(misp_info)

def debug(msg):
    """Logs a debug message if debug mode is enabled."""
    if debug_enabled:
        logging.debug(msg)

def is_public_ip(ip):
    """Checks whether the provided IP address is a public IP."""
    ip_addr = ipaddress.ip_address(ip)
    return not ip_addr.is_private  # Return True for public IPs, False otherwise

def query_misp(ip, ip_type, api_key):
    """
    Sends a query to the MISP server to retrieve information for a specific IP.

    Args:
        ip (str): The IP address to query.
        ip_type (str): The type of IP (e.g., 'ip-src', 'ip-dst').
        api_key (str): The API key for authentication with MISP.

    Returns:
        dict or None: Parsed JSON response from MISP or None on failure.
    """
    url = 'https://<your_MISP_IP>/attributes/restSearch'  # MISP API endpoint
    headers = {'Accept': 'application/json', 'Authorization': api_key}
    payload = {'returnFormat': 'json', 'type': ip_type, 'value': ip}

    try:
        print(f"Sending query to MISP for IP: {ip}, type: {ip_type}")
        response = requests.post(url, headers=headers, json=payload, verify=False)
        
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")  # Print full response for debugging

        if response.status_code == 200:
            return response.json()  # Parse and return JSON response
        else:
            debug(f"Error querying MISP: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Failed to query MISP: {str(e)}")
        return None

def request_misp_info(alert, api_key):
    """
    Extracts public IPs from the alert and queries MISP for information.

    Args:
        alert (dict): Parsed alert JSON data.
        api_key (str): MISP API key for authentication.

    Returns:
        dict: MISP information for each IP address.
    """
    debug("Extracting IPs using regex")
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # Regex to match IPv4 addresses
    alert_str = json.dumps(alert)  # Convert alert to string for regex matching
    found_ips = re.findall(ip_regex, alert_str)  # Find all IPs in the alert

    # Filter only public IPs
    public_ips = list(set(ip for ip in found_ips if is_public_ip(ip)))
    if not public_ips:
        debug("No public IPs found.")
        return None

    # Query MISP for each public IP
    misp_data = {}
    for ip in public_ips:
        misp_data[ip] = {
            'ip-src': query_misp(ip, 'ip-src', api_key),
            'ip-dst': query_misp(ip, 'ip-dst', api_key)
        }
    return misp_data

def process_misp_info(misp_info):
    """
    Processes the retrieved MISP information and sends events to Wazuh.

    Args:
        misp_info (dict): MISP data organized by IP address.
    """
    print("Processing MISP data...")
    print(json.dumps(misp_info, indent=4))  # Print full MISP object for debugging

    # Define a list of excluded IPs to ignore
    excluded_ips = ["IPv4_1", "1.1.1.1"]

    # Iterate over the MISP information for each IP
    for key, value in misp_info.items():
        print(f"Checking data for IP: {key}")
        if isinstance(value, dict) and 'response' in value and 'Attribute' in value['response']:
            attributes = value['response']['Attribute']
            for attribute in attributes:
                # Skip excluded IP addresses
                if "value" in attribute and attribute["value"] in excluded_ips:
                    print(f"Skipping excluded IP: {attribute['value']}")
                    continue
                # Send relevant attribute to Wazuh
                send_event(attribute)
        else:
            print(f"No valid attributes for IP: {key}")

def send_event(msg, agent=None):
    """
    Sends event data to the Wazuh socket for processing.

    Args:
        msg (dict): The message/event data to send.
        agent (dict, optional): Agent information. Defaults to None.
    """
    debug("Sending event to Wazuh")
    # Format the message string based on agent information
    if not agent or agent["id"] == "000":
        string = "1:misp:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->misp:{3}".format(
            agent["id"],
            agent["name"],
            agent["ip"] if "ip" in agent else "any",
            json.dumps(msg),
        )
    try:
        # Open a Unix socket and send the message
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
        debug("Message sent to Wazuh socket")
    except Exception as e:
        debug(f"Failed to send message to Wazuh socket: {str(e)}")

if __name__ == "__main__":
    """
    Entry point for the script. Handles uncaught exceptions gracefully.
    """
    try:
        main(sys.argv)
    except Exception as e:
        debug(str(e))
