#!/var/ossec/framework/python/bin/python3
# Copyright Whysecurity Srl Cellatica 2024.

import json
import sys
import time
import os
import ipaddress
import logging
from socket import socket, AF_UNIX, SOCK_DGRAM

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
    filename='debug.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %H:%M:%S %Z %Y'
)

def main(args):
    debug("Starting script execution")
    
    # Check arguments
    if len(args) < 3:
        logging.error("Usage: python script_name.py path_to_alerts.json api_key")
        sys.exit(1)

    # Getting input arguments by Wazuh 
    alert_file_location = args[1]
    api_key = args[2]

    # Check arguments on CLI environment
    debug(f"File location: {alert_file_location}")
    debug(f"API Key: {api_key}")

    # Load alert. Parse JSON object.
    debug("Loading and parsing alert file")
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    
    debug("Alert loaded and parsed successfully")
    debug(f"Parsed alert: {json.dumps(json_alert, indent=2)}")

    # Request MISP info
    debug("Requesting MISP info")
    misp_info = request_misp_info(json_alert, api_key)

    # If positive match, handle or process the MISP info here
    if misp_info:
        debug("Processing MISP info")
        process_misp_info(misp_info)

def debug(msg):
    if debug_enabled:
        logging.debug(msg)

# Check if the IP is public
def is_public_ip(ip):
    ip_addr = ipaddress.ip_address(ip)
    return not ip_addr.is_private

def query_misp(ip, ip_type, api_key):
    debug(f"Querying MISP for IP: {ip}, type: {ip_type}")
    url = 'https://your-MISP-ip/attributes/restSearch'
    headers = {
        'Accept': 'application/json',
        'Authorization': api_key,
        'Content-Type': 'application/json'
    }
    payload = {
        'returnFormat': 'json',
        'type': ip_type,
        'value': ip
    }
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        debug(f"MISP query successful for IP: {ip}, type: {ip_type}")
        return response.json()
    else:
        debug(f"Error: The MISP encountered an error. Status Code: {response.status_code}")
        sys.exit(1)

# Check if the JSON is correctly formatted
def request_misp_info(alert, api_key):
    debug("Checking if alert contains 'data'")
    if "data" not in alert:
        debug("No data found in the alert.")
        return None

    ip_info = {}

    debug("Extracting IP information from alert data")
    if "srcip" in alert["data"]:
        ip_info["srcip"] = alert["data"]["srcip"]

    if "dstip" in alert["data"]:
        ip_info["dstip"] = alert["data"]["dstip"]

    if "srcPostNAT" in alert["data"]:
        ip_info["srcPostNAT"] = alert["data"]["srcPostNAT"]

    debug("Filtering out private IPs")
    ip_info = {key: value for key, value in ip_info.items() if is_public_ip(value)}

    if not ip_info:
        debug("No relevant public IP information found in the alert.")
        return None

    misp_data = {}
    for key, value in ip_info.items():
        if key == "srcip":
            debug(f"Querying MISP for source IP: {value}")
            misp_data[key] = query_misp(value, 'ip-src', api_key)
        elif key == "dstip":
            debug(f"Querying MISP for destination IP: {value}")
            misp_data[key] = query_misp(value, 'ip-dst', api_key)
        elif key == "srcPostNAT":
            debug(f"Querying MISP for post-NAT source IP: {value}")
            misp_data[f"{key}_ip-src"] = query_misp(value, 'ip-src', api_key)
            misp_data[f"{key}_ip-dst"] = query_misp(value, 'ip-dst', api_key)

    debug(f"MISP data retrieved: {json.dumps(misp_data, indent=2)}")
    return misp_data

def process_misp_info(misp_info):
    debug("Processing received MISP Info")
    debug(f"MISP Info: {json.dumps(misp_info, indent=2)}")
    print(misp_info)
    send_event(misp_info)


def send_event(msg, agent=None):
    """
    Sends event data to Wazuh.
    """
    debug("Sending event to Wazuh")
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
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
        debug("Message sent to Wazuh socket")
    except Exception as e:
        debug(f"Failed to send message to Wazuh socket: {str(e)}")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        debug(str(e))
