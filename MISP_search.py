#!/var/ossec/framework/python/bin/python3
# Copyright Whysecurity Srl Cellatica 2024.

import json
import sys
import ipaddress
import logging
import re
import urllib3
from socket import socket, AF_UNIX, SOCK_DGRAM
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = True
socket_addr = "/var/ossec/queue/sockets/queue"  # Default Wazuh socket path

# Configure logging
logging.basicConfig(
    filename='/var/ossec/logs/debug.log',  # Log file path
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %H:%M:%S %Z %Y'
)

def main(args):
    """
    Main function to execute the script.
    """
    debug("Starting script execution")

    # Check arguments
    if len(args) < 3:
        logging.error("Usage: python script_name.py path_to_alerts.json api_key")
        sys.exit(1)

    # Getting input arguments
    alert_file_location = args[1]
    api_key = args[2]

    debug("Loading and parsing alert file")
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
    except Exception as e:
        logging.error(f"Failed to load or parse the alert file: {str(e)}")
        sys.exit(1)

    debug("Alert loaded successfully")
    misp_info = request_misp_info(json_alert, api_key)

    if misp_info:
        process_misp_info(misp_info)

def debug(msg):
    """Debug message logger."""
    if debug_enabled:
        logging.debug(msg)

def is_public_ip(ip):
    """Check if the IP is public."""
    ip_addr = ipaddress.ip_address(ip)
    return not ip_addr.is_private

def query_misp(ip, ip_type, api_key):
    """Query the MISP server for IP information."""
    url = 'https://172.16.101.31/attributes/restSearch'
    headers = {'Accept': 'application/json', 'Authorization': api_key}
    payload = {'returnFormat': 'json', 'type': ip_type, 'value': ip}

    try:
        print(f"Sending query to MISP for IP: {ip}, type: {ip_type}")
        response = requests.post(url, headers=headers, json=payload, verify=False)

        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")  # Stampa la risposta completa

        if response.status_code == 200:
            return response.json()
        else:
            debug(f"Error querying MISP: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Failed to query MISP: {str(e)}")
        return None


def request_misp_info(alert, api_key):
    """Extract public IPs from the alert and query MISP."""
    debug("Extracting IPs using regex")
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    alert_str = json.dumps(alert)
    found_ips = re.findall(ip_regex, alert_str)

    public_ips = list(set(ip for ip in found_ips if is_public_ip(ip)))
    if not public_ips:
        debug("No public IPs found.")
        return None

    misp_data = {}
    for ip in public_ips:
        misp_data[ip] = {
            'ip-src': query_misp(ip, 'ip-src', api_key),
            'ip-dst': query_misp(ip, 'ip-dst', api_key)
        }
    return misp_data

def process_misp_info(misp_info):
    """
    Process the MISP information and send relevant data to Wazuh.
    """
    debug("Processing received MISP Info")

    # List of excluded IPs
    excluded_ips = ["204.79.197.203", "1.1.1.1"]

    for ip, data in misp_info.items():
        debug(f"Checking data for IP: {ip}")

        for ip_type, response in data.items():  # ip-src or ip-dst
            if not response:
                debug(f"No response for {ip} ({ip_type})")
                continue

            # Traverse to the 'Attribute' key
            attributes = response.get("response", {}).get("Attribute", [])
            if not attributes:
                debug(f"No valid attributes for {ip} ({ip_type})")
                continue

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
        # Format the message correctly
        if not agent or agent["id"] == "000":
            string = "1:misp:{0}".format(json.dumps(msg))
        else:
            string = "1:[{0}] ({1}) {2}->misp:{3}".format(
                agent["id"],
                agent["name"],
                agent["ip"] if "ip" in agent else "any",
                json.dumps(msg),
            )
        debug(f"Formatted event message: {string}")  # Log the message for verification

        # Send the message to the Wazuh socket
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        debug(f"Connected to socket: {socket_addr}")
        sock.send(string.encode())
        debug("Message successfully sent to Wazuh socket")
        sock.close()

    except Exception as e:
        debug(f"Failed to send message to Wazuh socket: {str(e)}")



if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        debug(str(e))
