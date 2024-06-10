import json
import logging
import os
import sys
from socket import socket, AF_UNIX, SOCK_DGRAM
import requests
from requests.exceptions import ConnectionError
from datetime import datetime

# Disable SSL warning verify
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class MISPClient:
    def __init__(self, base_url, api_key):
        """
        Initializes the MISP client with base URL and API key.
        """
        self.base_url = base_url
        self.api_key = api_key

    def search_ip_events(self, ip):
        """
        Searches for events related to the given IP address.
        """
        url = f"{self.base_url}/attributes/restSearch"
        headers = {
            "Authorization": self.api_key,
            "Content-Type": "application/json"  
        }
        data = {
            "type": "ip-src",
            "value": ip
        }
        try:
            response = requests.post(url, headers=headers, json=data, verify=False)
            response.raise_for_status()
            json_data = response.json()
            if json_data.get("response", {}).get("Attribute"):
                return json_data
            else:
                return None
        except (ConnectionError, requests.RequestException) as e:
            logging.error(f"Error connecting to MISP API: {str(e)}")
            return {"error": f"Error connecting to MISP API: {str(e)}"}
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON response from MISP API: {str(e)}")
            return {"error": f"Error decoding JSON response from MISP API: {str(e)}"}

def send_event(msg, socket_addr, agent=None):
    """
    Sends event data to MISP.
    """
    if not agent or agent["id"] == "000":
        string = "1:misp:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->misp:{3}".format(
            agent["id"],
            agent["name"],
            agent.get("ip", "any"),
            json.dumps(msg),
        )
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
    logging.info("Event sent to MISP.")

if __name__ == "__main__":
    # Configuring logging
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "MISP_script.log")
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # MISP configuration
    base_url = "YOUR MISP IP" #ADD YOUR MISP URL
    api_key = "YOUR MISP KEY" #ADD YOUR MISP KEY (Administration ->List Auth Keys ->Add authentication key)
    misp_client = MISPClient(base_url, api_key)

    # Determine the socket address dynamically
    pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    socket_addr = "{0}/queue/sockets/queue".format(pwd)

    # Reading input JSON from sys.argv
    if len(sys.argv) < 2:
        logging.error("Input JSON file path is missing.")
        sys.exit(1)

    input_json_file = sys.argv[1]
    try:
        with open(input_json_file, 'r') as file:
            input_json = file.read()
    except Exception as e:
        logging.error(f"Error reading input JSON file: {str(e)}")
        sys.exit(1)

    try:
        alert = json.loads(input_json)['_source']
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding input JSON: {str(e)}")
        sys.exit(1)

    rule_id = alert.get('rule', {}).get('id')

    if rule_id in ["INSERT_YOUR_RULE_ID", "INSERT_YOUR_RULE_ID_2..."]: #MODIFY THIS LINE
        ip_to_search = alert.get('data', {}).get('srcip')
        if ip_to_search:
            search_result = misp_client.search_ip_events(ip_to_search)
            if search_result:
                print(json.dumps(search_result, indent=4))
                send_event(search_result, socket_addr, alert.get('agent'))
            else:
                logging.info("No matching events found in MISP.")
        else:
            logging.info("Source IP address not found in the alert data.")
    else:
        logging.info("Rule ID does not match the expected values.")
