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
    filename='/var/ossec/logs/debug.log',
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

    # Getting input arguments by Wazuh
    alert_file_location = args[1]
    api_key = args[2]

    # Check arguments on CLI environment
    debug(f"File location: {alert_file_location}")
    # debug(f"API Key: {api_key}")

    # Load alert. Parse JSON object.
    debug("Loading and parsing alert file")
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
    except Exception as e:
        logging.error(f"Failed to load or parse the alert file: {str(e)}")
        sys.exit(1)

    debug("Alert loaded and parsed successfully")
    # debug(f"Parsed alert: {json_alert}")

    # Request MISP info
    debug("Requesting MISP info")
    misp_info = request_misp_info(json_alert, api_key)

    # If positive match, handle or process the MISP info here
    if misp_info:
        debug("Processing MISP info")
        process_misp_info(misp_info)

def debug(msg):
    """
    Debug message logger.
    """
    if debug_enabled:
        logging.debug(msg)

def is_public_ip(ip):
    """
    Check if the IP is public.
    """
    ip_addr = ipaddress.ip_address(ip)
    return not ip_addr.is_private

def query_misp(ip, ip_type, api_key):
    """
    Query the MISP server for information about the IP.
    """
    debug(f"Querying MISP for IP: {ip}, type: {ip_type}")
    url = 'https://172.16.101.31/attributes/restSearch'
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
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.status_code == 200:
            debug(f"MISP query successful for IP: {ip}, type: {ip_type}")
            return response.json()
        else:
            debug(f"Error: The MISP encountered an error. Status Code: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to query MISP: {str(e)}")
        sys.exit(1)

import re
import json


def request_misp_info(alert, api_key):
    """
    Estrae tutti gli indirizzi IP pubblici utilizzando una regex, elimina duplicati
    e interroga MISP.
    """
    debug("Extracting IP addresses using regex")
    ip_info = {}

    # Regex per identificare indirizzi IP
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Converte il JSON dell'alert in stringa per cercare indirizzi IP ovunque
    alert_str = json.dumps(alert)

    # Trova tutti gli indirizzi IP nell'alert
    found_ips = re.findall(ip_regex, alert_str)

    # Filtra solo indirizzi pubblici ed elimina duplicati
    public_ips = list(set(ip for ip in found_ips if is_public_ip(ip)))

    if not public_ips:
        debug("No public IPs found in the alert.")
        return None

    # Costruisce il dizionario ip_info con i tipi di IP raccolti
    for ip in public_ips:
        if ip not in ip_info.values():
            ip_info[ip] = ip

    # MISP data
    misp_data = {}
    for ip in ip_info.values():
        debug(f"Querying MISP for IP: {ip}")
        # Invia la query a MISP per ip-src e ip-dst
        misp_data[ip] = {
            'ip-src': query_misp(ip, 'ip-src', api_key),
            'ip-dst': query_misp(ip, 'ip-dst', api_key)
        }

    debug(f"MISP data retrieved: {json.dumps(misp_data, indent=2)}")
    return misp_data



def process_misp_info(misp_info):
    """
    Process the MISP information and send relevant data to Wazuh.
    """
    debug("Processing received MISP Info")

    # INSERIRE IP CONSIDERATI FALSI POSITIVI QUI
    excluded_ips = ["204.79.197.203", "1.1.1.1"]

    for key, value in misp_info.items():
        if isinstance(value, dict) and 'response' in value and 'Attribute' in value['response']:
            attributes = value['response']['Attribute']

            for attribute in attributes:
                # Controlla se l'attributo contiene un IP escluso
                if "value" in attribute and attribute["value"] in excluded_ips:
                    debug(f"Skipping event for excluded IP: {attribute['value']}")
                    continue

                debug(f"MISP response each: {attribute}")
                send_event(attribute)


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
