#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.

import json
import sys
import time
import os
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

def main(args):
    debug("# Starting")
    
    # Check arguments
    if len(args) < 3:
        print("Usage: python script_name.py path_to_alerts.json api_key")
        sys.exit(1)

    alert_file_location = args[1]
    api_key = args[2]

    debug("# File location")
    debug(alert_file_location)
    debug("# API Key")
    debug(api_key)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    
    debug("# Processing alert")
    debug(json.dumps(json_alert, indent=2))

    # Request MISP info
    misp_info = request_misp_info(json_alert, api_key)

    # If positive match, handle or process the MISP info here
    if misp_info:
        process_misp_info(misp_info)

def debug(msg):
    if debug_enabled:
        now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)

def query_misp(ip, ip_type, api_key):
    url = 'https://my-MISP-url/attributes/restSearch'
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
        return response.json()
    else:
        debug(f"# Error: The MISP encountered an error. Status Code: {response.status_code}")
        sys.exit(1)

def request_misp_info(alert, api_key):
    if "data" not in alert["_source"]:
        debug("# No data found in the alert.")
        return None

    # Initialize a dictionary to hold the IP information
    ip_info = {}

    # Check for "srcip" within "data"
    if "srcip" in alert["_source"]["data"]:
        ip_info["srcip"] = alert["_source"]["data"]["srcip"]

    # Check for "dstip" within "data"
    if "dstip" in alert["_source"]["data"]:
        ip_info["dstip"] = alert["_source"]["data"]["dstip"]

    # Check for "srcPostNAT" within "data"
    if "srcPostNAT" in alert["_source"]["data"]:
        ip_info["srcPostNAT"] = alert["_source"]["data"]["srcPostNAT"]

    # If none of the desired keys are found, return None
    if not ip_info:
        debug("# No relevant IP information found in the alert.")
        return None

    # Request info using MISP API for each found IP
    misp_data = {}
    for key, value in ip_info.items():
        if key == "srcip":
            misp_data[key] = query_misp(value, 'ip-src', api_key)
        elif key == "dstip":
            misp_data[key] = query_misp(value, 'ip-dst', api_key)
        elif key == "srcPostNAT":
            # Query both ip-src and ip-dst for srcPostNAT
            misp_data[f"{key}_ip-src"] = query_misp(value, 'ip-src', api_key)
            misp_data[f"{key}_ip-dst"] = query_misp(value, 'ip-dst', api_key)

    return misp_data

def process_misp_info(misp_info):
    # Example: Print or process MISP info as needed
    debug("Received MISP Info:")
    debug(json.dumps(misp_info, indent=2))
    print(misp_info)
    # Send the MISP info to Wazuh using send_event function
    send_event(misp_info)

def send_event(msg, agent=None):
    """
    Sends event data to Wazuh.
    """
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
        # Main function
        main(sys.argv)
    except Exception as e:
        debug(str(e))
