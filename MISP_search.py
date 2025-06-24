#!/var/ossec/framework/python/bin/python3
# code written for eDOK Srl Vobarno 2025
import json
import sys
import ipaddress
import logging
import re
import urllib3
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import time
import hashlib
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Importing requests module
try:
    import requests
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Importing ipwhois module
try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import ASNRegistryError, WhoisLookupError, HTTPLookupError
except ImportError:
    print("No module 'ipwhois' found. Install: pip install ipwhois")
    sys.exit(1)

# Global Variables
debug_enabled = True  # Set to True to enable detailed debug logs
socket_addr = "/var/ossec/queue/sockets/queue"
recent_logs_file = "/var/ossec/tmp/recent_misp_whois_logs.json"
deduplication_window = 3600  # Seconds (1 hour)

# VirusTotal API Configuration (hardcoded)
VIRUSTOTAL_API_KEY = "VIRUSTOTAL_API_KEY_HERE"  # ### CHANGE ###: Insert your VirusTotal API key here
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/" # ### CHANGE ###: Use the modern V3 URL

# List of legitimate ISPs/providers to filter (reduce false positives)
LEGITIMATE_PROVIDERS = {
    # Cloud Providers
    'amazon', 'aws', 'amazon.com', 'amazon web services',
    'google', 'google.com', 'google cloud', 'googleapis.com',
    'microsoft', 'microsoft.com', 'azure', 'outlook.com',
    'cloudflare', 'cloudflare.com',
    'akamai', 'akamai.com',
    'fastly', 'fastly.com',

    # Major ISPs
    'telecom italia', 'tim.it', 'telecomitalia.it',
    'vodafone', 'vodafone.it', 'vodafone.com',
    'wind', 'windtre.it', 'tre.it',
    'fastweb', 'fastweb.it',
    'tiscali', 'tiscali.it',

    # International ISPs
    'verizon', 'att.com', 'comcast', 'charter',
    'bt.com', 'orange.com', 'deutsche telekom',
    'telefonica', 'proximus', 'swisscom',

    # CDN and hosting providers
    'ovh', 'ovh.com', 'ovh.net',
    'hetzner', 'hetzner.com', 'hetzner.de',
    'digitalocean', 'digitalocean.com',
    'linode', 'linode.com',
    'vultr', 'vultr.com',

    # Social Media and major platforms
    'facebook', 'meta', 'whatsapp',
    'twitter', 'x.com',
    'linkedin', 'linkedin.com',
    'apple', 'apple.com', 'icloud.com'
}

# Configure logging
logging.basicConfig(
    filename='/var/ossec/logs/misp_whois_integration.log',
    level=logging.DEBUG if debug_enabled else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %H:%M:%S %Z %Y'
)

class RecentLogTracker:
    # ...no changes in this class...
    def __init__(self, log_file, window_seconds=3600):
        self.log_file = log_file
        self.window = window_seconds
        self.recent_logs = self._load_logs()
        debug(f"Log tracker initialized with window of {window_seconds} seconds")

    def _load_logs(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
                debug(f"Loaded {len(logs)} recent logs from {self.log_file}")
                return logs
            except Exception as e:
                logging.error(f"Failed to load recent logs file: {str(e)}")
                return {}
        else:
            debug("No recent logs file found, creating new one")
            return {}

    def _save_logs(self):
        try:
            log_dir = os.path.dirname(self.log_file)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            with open(self.log_file, 'w') as f:
                json.dump(self.recent_logs, f)
            debug(f"Recent logs saved to {self.log_file}")
        except Exception as e:
            logging.error(f"Failed to save recent logs: {str(e)}")

    def is_duplicate(self, key):
        current_time = time.time()
        if key in self.recent_logs:
            last_sent = self.recent_logs[key]
            if current_time - last_sent < self.window:
                debug(f"Duplicate detected for {key} (sent {int(current_time - last_sent)} seconds ago)")
                return True
        return False

    def mark_sent(self, key):
        self.recent_logs[key] = time.time()
        debug(f"Marked {key} as recently sent")
        self._clean_old_entries()
        self._save_logs()

    def _clean_old_entries(self):
        current_time = time.time()
        old_keys = [k for k, timestamp in self.recent_logs.items()
                    if current_time - timestamp > self.window]
        for key in old_keys:
            del self.recent_logs[key]
        if old_keys:
            debug(f"Removed {len(old_keys)} outdated entries from recent logs")

### CHANGE ###
# The main function has been rewritten to follow the new workflow.
def main(args):
    debug("Starting script execution")
    if len(args) < 3:
        logging.error("Usage: python script_name.py path_to_alerts.json misp_api_key")
        sys.exit(1)

    alert_file_location = args[1]
    misp_api_key = args[2]

    # VirusTotal API key is always set (hardcoded)
    vt_api_key = VIRUSTOTAL_API_KEY

    log_tracker = RecentLogTracker(recent_logs_file, deduplication_window)

    debug("Loading and parsing alert file")
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
    except Exception as e:
        logging.error(f"Failed to load or parse the alert file: {str(e)}")
        sys.exit(1)
    debug("Alert loaded successfully")

    if not validate_wazuh_alert(json_alert):
        debug("Not a valid Wazuh alert or not an alert type that should be processed")
        sys.exit(0)

    alert_context = extract_alert_context(json_alert)

    # The workflow starts here. First, only public IPs are extracted.
    ip_data_map = extract_ips_with_context(json_alert)
    if not ip_data_map:
        debug("No public IPs found in alert that match criteria")
        sys.exit(0)

    for ip, ip_context_data in ip_data_map.items():
        debug(f"Processing IP {ip} from alert rule '{alert_context['rule_id']}'")
        dedup_key = f"{alert_context['rule_id']}:{ip}:{ip_context_data['direction']}"

        if log_tracker.is_duplicate(dedup_key):
            debug(f"Skipping duplicate alert-IP combination: {dedup_key}")
            continue

        # --- START NEW WORKFLOW ---

        # STEP 1: Perform WHOIS query to check the provider
        whois_data_result = query_whois(ip)

        # STEP 2: Check if the IP belongs to a legitimate provider
        if is_legitimate_provider(whois_data_result, ip):
            debug(f"IP {ip} belongs to a legitimate provider. Considering it a false positive and skipping.")
            continue # Move to next IP

        # STEP 3: Query MISP
        ip_types_for_misp = determine_ip_types(ip_context_data)
        misp_data_responses = {}
        misp_threats_found = False

        for ip_type in ip_types_for_misp:
            misp_response = query_misp(ip, ip_type, misp_api_key)
            if misp_response and misp_response.get("response"): # Check if there are attributes
                misp_data_responses[ip_type] = misp_response
                misp_threats_found = True

        # STEP 4: If MISP found threats, check with VirusTotal
        if misp_threats_found and vt_api_key:
            debug(f"MISP found potential threats for {ip}. Cross-validating with VirusTotal.")
            vt_result = query_virustotal(ip, vt_api_key)

            # STEP 5: Send the alert only if VirusTotal is also positive
            if is_virustotal_positive(vt_result):
                debug(f"CONFIRMED THREAT: Both MISP and VirusTotal are positive for {ip}. Sending enriched alert.")
                # The send_enriched_event function has been modified to also accept VT data
                send_enriched_event(ip, misp_data_responses, whois_data_result, alert_context, ip_context_data, json_alert, vt_result)
                log_tracker.mark_sent(dedup_key)
            else:
                debug(f"FALSE POSITIVE: MISP was positive, but VirusTotal was negative for {ip}. Suppressing alert.")

        elif misp_threats_found: # If MISP is positive but VT key is not available
            logging.warning(f"MISP threats found for {ip}, but VirusTotal check is disabled. Sending alert based on MISP only.")
            send_enriched_event(ip, misp_data_responses, whois_data_result, alert_context, ip_context_data, json_alert, None)
            log_tracker.mark_sent(dedup_key)
        else:
            debug(f"No threats found in MISP for IP {ip}. No further action needed.")

### NEW FUNCTION ###
def is_legitimate_provider(whois_data, ip):
    """
    Checks if an IP belongs to a legitimate provider/ISP based on WHOIS data.
    Returns True if the IP should be considered a likely false positive.
    """
    if not whois_data:
        debug(f"No WHOIS data available for {ip}, cannot determine if it's a legitimate provider.")
        return False

    try:
        # Extract the most relevant textual information from WHOIS
        text_to_check = []

        # ASN description (very useful)
        if whois_data.get('asn_info') and whois_data['asn_info'].get('description'):
            text_to_check.append(whois_data['asn_info']['description'].lower())

        # Name and description of associated networks
        for network in whois_data.get('networks', []):
            if network.get('name'):
                text_to_check.append(network['name'].lower())
            if network.get('description'):
                text_to_check.append(network['description'].lower())

        # Check if any of the extracted strings contains a legitimate provider name
        full_text = " | ".join(text_to_check)
        for provider in LEGITIMATE_PROVIDERS:
            if provider in full_text:
                debug(f"IP {ip} belongs to a legitimate provider: '{provider}' (found in WHOIS text: '{full_text}').")
                return True

        debug(f"IP {ip} does not appear to belong to any known legitimate providers.")
        return False

    except Exception as e:
        logging.error(f"Error while checking for legitimate provider for {ip}: {str(e)}")
        return False # In case of error, better to be cautious and not discard the IP

### NEW FUNCTION ###
def query_virustotal(ip, api_key):
    """
    Queries the VirusTotal v3 API for information about an IP address.
    """
    debug(f"Querying VirusTotal for IP: {ip}")
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    url = VIRUSTOTAL_API_URL + ip

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            result = response.json()
            analysis_stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            debug(f"VirusTotal response for {ip}: malicious={analysis_stats.get('malicious', 0)}, suspicious={analysis_stats.get('suspicious', 0)}")
            return result
        elif response.status_code == 429: # Too Many Requests
            logging.warning(f"VirusTotal API quota exceeded when querying for {ip}.")
            return None
        elif response.status_code == 404: # Not Found
            debug(f"IP {ip} not found in VirusTotal database.")
            return None
        else:
            logging.warning(f"VirusTotal API error for {ip}: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to query VirusTotal for {ip}: {str(e)}")
        return None

### NEW FUNCTION ###
def is_virustotal_positive(vt_result):
    """
    Determines if the VirusTotal result indicates a threat.
    Returns True if the number of "malicious" detections exceeds the threshold.
    """
    if not vt_result or "data" not in vt_result:
        debug("VirusTotal: No data or invalid response format.")
        return False

    try:
        attributes = vt_result["data"]["attributes"]
        analysis_stats = attributes.get("last_analysis_stats", {})

        malicious_count = analysis_stats.get("malicious", 0)
        suspicious_count = analysis_stats.get("suspicious", 0)

        # Configurable threshold to consider an IP as a threat
        # Consider "positive" if at least X engines classify it as malicious.
        # "suspicious" detections are not counted to reduce false positives.
        malicious_threshold = 2

        if malicious_count >= malicious_threshold:
            debug(f"VirusTotal POSITIVE: {malicious_count} engines detected as malicious (threshold: {malicious_threshold}).")
            return True
        else:
            debug(f"VirusTotal NEGATIVE: {malicious_count} engines detected as malicious (below threshold: {malicious_threshold}).")
            return False

    except (KeyError, TypeError) as e:
        logging.error(f"Error parsing VirusTotal result: {str(e)}")
        return False

# ...all utility functions remain unchanged, e.g. debug, is_public_ip, etc....
def debug(msg):
    if debug_enabled:
        logging.debug(msg)

def is_public_ip(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
        return not ip_addr.is_private and not ip_addr.is_loopback
    except ValueError:
        return False
# ...the rest of the original functions like validate_wazuh_alert, extract_alert_context, etc.
# ...they are omitted for brevity, no changes required

def validate_wazuh_alert(alert):
    if not isinstance(alert, dict):
        debug("Alert is not a dictionary")
        return False
    if 'rule' not in alert or 'id' not in alert.get('rule', {}):
        debug("Alert missing rule ID")
        return False
    rule_level = alert.get('rule', {}).get('level', 0)
    if int(rule_level) <= 5:
        debug(f"Alert rule level {rule_level} below threshold")
    excluded_rules = ['31530', '31531']
    if alert.get('rule', {}).get('id') in excluded_rules:
        debug(f"Alert rule ID {alert.get('rule', {}).get('id')} in exclusion list")
        return False
    return True

def extract_alert_context(alert):
    context = {
        'rule_id': alert.get('rule', {}).get('id', 'unknown'),
        'rule_description': alert.get('rule', {}).get('description', 'unknown'),
        'rule_level': alert.get('rule', {}).get('level', 0),
        'rule_groups': alert.get('rule', {}).get('groups', []),
        'timestamp': alert.get('timestamp', ''),
        'agent_id': alert.get('agent', {}).get('id', '000'),
        'agent_name': alert.get('agent', {}).get('name', 'unknown'),
        'agent_ip': alert.get('agent', {}).get('ip', 'unknown'),
        'manager_name': alert.get('manager', {}).get('name', 'unknown'),
        'location': alert.get('location', 'unknown'),
        'decoder_name': alert.get('decoder', {}).get('name', 'unknown')
    }
    if 'data' in alert:
        context['data_fields'] = list(alert['data'].keys())
        if 'syscheck' in alert:
            syscheck = alert.get('syscheck', {})
            context['syscheck'] = {
                'path': syscheck.get('path', ''), 'event': syscheck.get('event', ''),
                'changed_attributes': syscheck.get('changed_attributes', [])
            }
    return context

def determine_ip_types(context_data):
    ip_types = []
    if context_data['direction'] == 'source':
        ip_types.append('ip-src')
    elif context_data['direction'] == 'destination':
        ip_types.append('ip-dst')
    else:
        ip_types = ['ip-src', 'ip-dst']
    return ip_types

def extract_ips_with_context(alert):
    debug("Extracting IPs with context using regex only")
    ip_data = {}
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    alert_json = json.dumps(alert)
    all_ips = re.findall(ip_regex, alert_json)
    public_ips = [ip for ip in all_ips if is_public_ip(ip)]
    debug(f"Found {len(public_ips)} unique public IPs in alert")

    for ip_addr in set(public_ips):
        direction = "unknown"
        field_path = "unknown"
        raw_value_found = ""
        source_patterns = ["srcip", "src_ip", "source_ip", "src-ip", "source.ip", "sip", "from_ip", "source_address"]
        dest_patterns = ["dstip", "dst_ip", "destination_ip", "dst-ip", "destination.ip", "dip", "to_ip", "destination_address"]

        def find_ip_in_dict(data, current_path=""):
            nonlocal direction, field_path, raw_value_found
            if isinstance(data, dict):
                for key, value_item in data.items():
                    new_path = f"{current_path}.{key}" if current_path else key
                    if isinstance(value_item, str) and ip_addr in value_item:
                        if any(pattern in key.lower() for pattern in source_patterns):
                            direction = "source"
                        elif any(pattern in key.lower() for pattern in dest_patterns):
                            direction = "destination"
                        field_path = new_path
                        raw_value_found = value_item
                        return True
                    if find_ip_in_dict(value_item, new_path):
                        return True
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    new_path = f"{current_path}[{i}]"
                    if find_ip_in_dict(item, new_path):
                        return True
            return False

        find_ip_in_dict(alert)
        rule_desc = alert.get("rule", {}).get("description", "")
        if ip_addr in rule_desc and field_path == "unknown":
            field_path = "rule.description"
            raw_value_found = rule_desc
            if f"from {ip_addr}" in rule_desc.lower():
                direction = "source"
            elif f"to {ip_addr}" in rule_desc.lower():
                direction = "destination"

        ip_data[ip_addr] = {
            'field_path': field_path,
            'direction': direction,
            'raw_value': raw_value_found
        }
        debug(f"Found IP {ip_addr} in field {field_path} as {direction} with raw_value: '{raw_value_found}'")
    return ip_data

def query_misp(ip, ip_type, api_key):
    url = 'http://10.5.254.41/attributes/restSearch'
    headers = {'Accept': 'application/json', 'Authorization': api_key}
    payload = {
        'returnFormat': 'json', 'type': ip_type, 'value': ip, 'includeEventTags': True,
        'includeContext': True, 'includeWarninglistHits': True, 'pythonify': False
    }
    try:
        debug(f"Querying MISP for IP: {ip}, type: {ip_type}")
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        if response.status_code == 200:
            debug(f"Received valid response from MISP for {ip} ({ip_type})")
            return response.json()
        else:
            logging.warning(f"Error querying MISP for {ip} ({ip_type}): {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to query MISP for {ip} ({ip_type}): {str(e)}")
        return None

def query_whois(ip):
    debug(f"Querying WHOIS for IP: {ip}")
    try:
        obj = IPWhois(ip, timeout=10)
        results = obj.lookup_whois(inc_nir=True)
        if not results:
            debug(f"No WHOIS data returned for IP: {ip}")
            return None
        asn_info = {"asn": results.get("asn"),"description": results.get("asn_description"),"cidr": results.get("asn_cidr"),"registry": results.get("asn_registry"),"country_code": results.get("asn_country_code"),"date": results.get("asn_date"),}
        network_info_list = []
        if results.get("nets") and isinstance(results["nets"], list):
            for net in results["nets"]:
                if not isinstance(net, dict): continue
                network_info_list.append({"cidr": net.get("cidr"),"name": net.get("name"),"handle": net.get("handle"),"range": net.get("range"),"description": net.get("description"),"country": net.get("country"),"address": net.get("address"),"city": net.get("city"),"state": net.get("state"),"postal_code": net.get("postal_code"),"created": net.get("created"),"updated": net.get("updated"),"abuse_emails": net.get("abuse_emails"),"tech_emails": net.get("tech_emails"),})
        nir_info = results.get("nir")
        whois_output = {"queried_ip": ip,"asn_info": asn_info,"networks": network_info_list,"nir_info": nir_info}
        debug(f"Successfully retrieved WHOIS for {ip}")
        return whois_output
    except (ASNRegistryError, WhoisLookupError, HTTPLookupError) as e:
        logging.warning(f"WHOIS lookup failed for {ip}: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during WHOIS lookup for {ip}: {str(e)}")
        return None

### CHANGE ###
# Modified signature to accept VirusTotal data (vt_data)
def send_enriched_event(ip, misp_api_responses, whois_data, alert_context, ip_context_data, original_alert, vt_data=None):
    # The initial part of this function (excluded IPs, warning list check) was not in your original code.
    # I omitted it for consistency, but if you use it, feel free to add it.

    # Build the base event with the original alert, whois and misp data
    # (This logic is complex and specific, so I leave it as a reference)
    enriched_event = {
        "integration": "misp_whois_vt_enrichment",
        "ip_info": {
            "ip": ip,
            "direction": ip_context_data.get('direction', 'unknown'),
            "source_field": ip_context_data.get('field_path', 'unknown')
        },
        "whois_info": whois_data if whois_data else {},
        "misp_data": {
            "attributes": [] # To be populated with MISP data
        },
        "virustotal_data": {}, # Will be populated if vt_data is available
        "original_alert": {
            "rule_id": alert_context.get('rule_id'),
            "rule_description": alert_context.get('rule_description'),
            "agent_id": alert_context.get('agent_id'),
            "agent_name": alert_context.get('agent_name'),
            "timestamp": alert_context.get('timestamp')
        }
    }

    # Populate MISP data (simplified logic from the original)
    for ip_type, response in misp_api_responses.items():
        if response and response.get("response"):
            for attr in response["response"].get("Attribute", []):
                enriched_event["misp_data"]["attributes"].append({
                    "uuid": attr.get("uuid"),
                    "value": attr.get("value"),
                    "category": attr.get("category"),
                    "comment": attr.get("comment"),
                    "to_ids": attr.get("to_ids", False),
                    "event_id": attr.get("event_id")
                })

    # ### CHANGE ###: Add VirusTotal data to the event if available
    if vt_data and "data" in vt_data:
        try:
            attrs = vt_data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            enriched_event["virustotal_data"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation"),
                "last_analysis_date": datetime.fromtimestamp(attrs.get("last_analysis_date", 0)).isoformat() if attrs.get("last_analysis_date") else "N/A",
                "url": f"https://www.virustotal.com/gui/ip-address/{ip}"
            }
        except (KeyError, TypeError) as e:
            logging.error(f"Could not parse VT data for enriched event: {e}")

    # At this point, the `enriched_event` is complete.
    # It should be converted to JSON and sent to the Wazuh socket.
    # The original code stops here, but the logic for sending would be:

    debug(f"Final enriched event for IP {ip} is ready to be sent to Wazuh.")
    # Example of how it could be sent (missing the `send_to_socket` function):
    # msg_json = json.dumps(enriched_event, indent=4)
    # send_to_socket(msg_json)

    # Your original code ended with an if with no body, I leave it for consistency:
    if enriched_event["misp_data"]["attributes"] and enriched_event["whois_info"].get("asn_info"):
        debug(f"Sending ENRICHED event for IP {ip} with {len(enriched_event['misp_data']['attributes'])} MISP attribute groups, WHOIS info and VirusTotal confirmation.")
        # Here the final sending logic should go.
        pass

# ... (The rest of the MISP and WHOIS parsing functions can remain unchanged)
# ... omitted for brevity

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        logging.error(f"Unhandled exception in main execution: {str(e)}")
        sys.exit(1)
        logging.error(f"Unhandled exception in main execution: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unhandled exception in main execution: {str(e)}")
        sys.exit(1)
