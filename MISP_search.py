#!/var/ossec/framework/python/bin/python3

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM  # Import necessary modules

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars

debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Socket address for Wazuh
socket_addr = "{0}/queue/sockets/queue".format(pwd)

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
    debug(json_alert)

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

def query_misp(srcip, api_key):
    url = 'https://my-MISP_ip/attributes/restSearch'
    headers = {
        'Accept': 'application/json',
        'Authorization': api_key,
        'Content-Type': 'application/json'
    }
    payload = {
        'returnFormat': 'json',
        'type': 'ip-src',
        'value': srcip
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

    # Now check for "srcip" within "data"
    if "srcip" not in alert["_source"]["data"]:
        debug("# No source IP address found in the alert.")
        return None

    # Request info using MISP API
    data = query_misp(alert["_source"]["data"]["srcip"], api_key)

    return data

def process_misp_info(misp_info):
    # Example: Print or process MISP info as needed
    debug("Received MISP Info:")
    debug(json.dumps(misp_info, indent=2))
    
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
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    try:
        # Main function
        main(sys.argv)
    except Exception as e:
        debug(str(e))
