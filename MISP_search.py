#!/var/ossec/framework/python/bin/python3
# Copyright Whysecurity Srl Cellatica 2024.

import json  # For JSON file parsing
import sys  # For command-line arguments
import ipaddress  # To check if an IP address is public or private
import logging  # For logging errors and debug information
import re  # For regular expressions to extract IP addresses
import urllib3  # For disabling SSL warnings with unverified HTTPS
from socket import socket, AF_UNIX, SOCK_DGRAM  # For socket communication

# Disable SSL warnings when using HTTPS with invalid certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Importing requests module for making HTTP requests
try:
    import requests
    from requests.auth import HTTPBasicAuth  # Optional authentication (not used here)
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global Variables
debug_enabled = True  # Enable or disable debug logging
socket_addr = "/var/ossec/queue/sockets/queue"  # Default path for Wazuh socket communication

# Configure logging
logging.basicConfig(
    filename='/var/ossec/logs/debug.log',  # Path to log file
    level=logging.DEBUG,  # Set log level to DEBUG
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log message format
    datefmt='%a %b %d %H:%M:%S %Z %Y'  # Date format for log entries
)

def main(args):
    """
    Main function to execute the script.
    """
    debug("Starting script execution")

    # Check if required arguments are provided
    if len(args) < 3:
        logging.error("Usage: python script_name.py path_to_alerts.json api_key")
        sys.exit(1)

    # Get input arguments
    alert_file_location = args[1]  # Path to JSON alert file
    api_key = args[2]  # API key for MISP authentication

    # Load and parse the alert file
    debug("Loading and parsing alert file")
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)  # Load JSON content
    except Exception as e:
        logging.error(f"Failed to load or parse the alert file: {str(e)}")
        sys.exit(1)

    debug("Alert loaded successfully")

    # Query MISP for information about the extracted public IPs
    misp_info = request_misp_info(json_alert, api_key)

    # Process and send the received MISP information to Wazuh
    if misp_info:
        process_misp_info(misp_info)

def debug(msg):
    """Log debug messages if debugging is enabled."""
    if debug_enabled:
        logging.debug(msg)

def is_public_ip(ip):
    """Check if an IP address is public."""
    ip_addr = ipaddress.ip_address(ip)  # Convert string to IP address object
    return not ip_addr.is_private  # Return True if the IP is public

def query_misp(ip, ip_type, api_key):
    """Query the MISP server for IP information."""
    url = 'https://Y.Y.Y.Y/attributes/restSearch'  # MISP API endpoint
    headers = {
        'Accept': 'application/json',
        'Authorization': api_key  # API key for authentication
    }
    payload = {
        'returnFormat': 'json',
        'type': ip_type,  # Type of IP query ('ip-src' or 'ip-dst')
        'value': ip  # IP address to query
    }

    try:
        print(f"Sending query to MISP for IP: {ip}, type: {ip_type}")
        response = requests.post(url, headers=headers, json=payload, verify=False)

        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")  # Print response for debugging

        # Check if request was successful
        if response.status_code == 200:
            return response.json()  # Return JSON response
        else:
            debug(f"Error querying MISP: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Failed to query MISP: {str(e)}")
        return None

def request_misp_info(alert, api_key):
    """Extract public IPs from the alert and query MISP."""
    debug("Extracting IPs using regex")
    
    # Regex to find all IPv4 addresses in the alert data
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    alert_str = json.dumps(alert)  # Convert JSON alert to string
    found_ips = re.findall(ip_regex, alert_str)  # Find all IPs using regex

    # Filter only public IPs and remove duplicates
    public_ips = list(set(ip for ip in found_ips if is_public_ip(ip)))
    if not public_ips:
        debug("No public IPs found.")
        return None

    # Query MISP for each public IP
    misp_data = {}
    for ip in public_ips:
        misp_data[ip] = {
            'ip-src': query_misp(ip, 'ip-src', api_key),  # Query IP as source
            'ip-dst': query_misp(ip, 'ip-dst', api_key)   # Query IP as destination
        }
    return misp_data

def process_misp_info(misp_info):
    """
    Process the MISP information and send relevant data to Wazuh.
    """
    debug("Processing received MISP Info")

    # List of excluded IPs (IPs to ignore)
    excluded_ips = ["IPv4_1", "1.1.1.1"]

    # Process each IP and its associated data
    for ip, data in misp_info.items():
        debug(f"Checking data for IP: {ip}")

        for ip_type, response in data.items():  # For 'ip-src' and 'ip-dst'
            if not response:
                debug(f"No response for {ip} ({ip_type})")
                continue

            # Extract 'Attribute' data from the response
            attributes = response.get("response", {}).get("Attribute", [])
            if not attributes:
                debug(f"No valid attributes for {ip} ({ip_type})")
                continue

            # Send each attribute to Wazuh if it's not in the excluded list
            for attribute in attributes:
                if "value" in attribute and attribute["value"] in excluded_ips:
                    debug(f"Skipping event for excluded IP: {attribute['value']}")
                    continue

                debug(f"Sending attribute: {attribute}")
                send_event(attribute)

def send_event(msg, agent=None):
    """
    Sends event data to Wazuh.
    """
    debug("Preparing to send event to Wazuh")
    try:
        # Format the message to send to Wazuh
        if not agent or agent["id"] == "000":
            string = "1:misp:{0}".format(json.dumps(msg))
        else:
            string = "1:[{0}] ({1}) {2}->misp:{3}".format(
                agent["id"],
                agent["name"],
                agent.get("ip", "any"),
                json.dumps(msg)
            )
        debug(f"Formatted event message: {string}")

        # Connect to Wazuh socket and send the message
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        debug(f"Connected to socket: {socket_addr}")
        sock.send(string.encode())  # Send the formatted message
        debug("Message successfully sent to Wazuh socket")
        sock.close()

    except Exception as e:
        debug(f"Failed to send message to Wazuh socket: {str(e)}")

if __name__ == "__main__":
    try:
        main(sys.argv)  # Run the main function with command-line arguments
    except Exception as e:
        debug(str(e))  # Log any unexpected exceptions
