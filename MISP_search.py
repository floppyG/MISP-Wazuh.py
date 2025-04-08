#!/var/ossec/framework/python/bin/python3
# Copyright eDOK Srl Vobarno 2025.

import json
import sys
import ipaddress
import logging
import re
import urllib3
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Importing requests module
try:
    import requests
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global Variables
debug_enabled = False
socket_addr = "/var/ossec/queue/sockets/queue"
recent_logs_file = "/var/ossec/tmp/recent_misp_logs.json"
deduplication_window = 3600  # Seconds (1 hour)

# Configure logging
logging.basicConfig(
    filename='/var/ossec/logs/misp_integration.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %H:%M:%S %Z %Y'
)

class RecentLogTracker:
    """Class to track recently sent logs to prevent duplicates"""

    def __init__(self, log_file, window_seconds=3600):
        """Initialize with file path and deduplication window"""
        self.log_file = log_file
        self.window = window_seconds
        self.recent_logs = self._load_logs()
        debug(f"Log tracker initialized with window of {window_seconds} seconds")

    def _load_logs(self):
        """Load recently sent logs from file if exists"""
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
        """Save recent logs to file"""
        try:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(self.log_file)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            with open(self.log_file, 'w') as f:
                json.dump(self.recent_logs, f)
            debug(f"Recent logs saved to {self.log_file}")
        except Exception as e:
            logging.error(f"Failed to save recent logs: {str(e)}")

    def is_duplicate(self, key):
        """Check if this event was recently sent"""
        current_time = time.time()

        # Check if we have this key and it's within our window
        if key in self.recent_logs:
            last_sent = self.recent_logs[key]
            if current_time - last_sent < self.window:
                debug(f"Duplicate detected for {key} (sent {int(current_time - last_sent)} seconds ago)")
                return True
        return False

    def mark_sent(self, key):
        """Mark this event as recently sent"""
        self.recent_logs[key] = time.time()
        debug(f"Marked {key} as recently sent")
        self._clean_old_entries()
        self._save_logs()

    def _clean_old_entries(self):
        """Remove entries older than the window"""
        current_time = time.time()
        old_keys = [k for k, timestamp in self.recent_logs.items()
                    if current_time - timestamp > self.window]

        for key in old_keys:
            del self.recent_logs[key]

        if old_keys:
            debug(f"Removed {len(old_keys)} outdated entries from recent logs")

def main(args):
    """Main function to execute the script."""
    debug("Starting script execution")

    # Check arguments
    if len(args) < 3:
        logging.error("Usage: python script_name.py path_to_alerts.json api_key")
        sys.exit(1)

    alert_file_location = args[1]
    api_key = args[2]

    # Initialize recent logs tracker
    log_tracker = RecentLogTracker(recent_logs_file, deduplication_window)

    # Load and parse the alert file
    debug("Loading and parsing alert file")
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
    except Exception as e:
        logging.error(f"Failed to load or parse the alert file: {str(e)}")
        sys.exit(1)

    debug("Alert loaded successfully")

    # Validate that this is a legitimate Wazuh alert
    if not validate_wazuh_alert(json_alert):
        debug("Not a valid Wazuh alert or not an alert type that should be processed")
        sys.exit(0)

    # Extract relevant alert context for better tracking/correlation
    alert_context = extract_alert_context(json_alert)
    debug(f"Processing alert: {alert_context}")

    # Extract IPs with specifics about where exactly they were found
    ip_data = extract_ips_with_context(json_alert)
    if not ip_data:
        debug("No public IPs found in alert that match criteria")
        sys.exit(0)

    # Process each IP with its context
    for ip, context in ip_data.items():
        debug(f"Processing IP {ip} with context: {context['field_path']}")

        # Create deduplication key including alert and IP context
        dedup_key = f"{alert_context['rule_id']}:{ip}:{context['direction']}"

        # Check if this exact alert-IP combination was recently processed
        if log_tracker.is_duplicate(dedup_key):
            debug(f"Skipping duplicate alert-IP combination: {dedup_key}")
            continue

        # Determine direction based on context
        ip_types = determine_ip_types(context)

        # Query MISP for this IP
        misp_data = {}
        for ip_type in ip_types:
            misp_response = query_misp(ip, ip_type, api_key)
            if misp_response:
                misp_data[ip_type] = misp_response

        # Process the MISP data for this IP
        if misp_data:
            send_enriched_event(ip, misp_data, alert_context, context)
            # Mark as processed
            log_tracker.mark_sent(dedup_key)
        else:
            debug(f"No MISP data found for IP {ip}")

def debug(msg):
    """Log debug messages if debugging is enabled."""
    if debug_enabled:
        logging.debug(msg)

def is_public_ip(ip):
    """Check if an IP address is public."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        return not ip_addr.is_private and not ip_addr.is_loopback
    except ValueError:
        return False

def validate_wazuh_alert(alert):
    """Validate this is a legitimate Wazuh alert that should be processed."""
    # Check if the alert has the expected structure
    if not isinstance(alert, dict):
        debug("Alert is not a dictionary")
        return False

    # Check for required fields
    if 'rule' not in alert or 'id' not in alert.get('rule', {}):
        debug("Alert missing rule ID")
        return False

    # Optionally, filter by specific rule IDs or levels
    rule_id = alert.get('rule', {}).get('id')
    rule_level = alert.get('rule', {}).get('level', 0)

    # Example: Only process alerts with level > 5
    if int(rule_level) <= 5:
        debug(f"Alert rule level {rule_level} below threshold")
        return False

    # Example: Skip certain rule types
    excluded_rules = ['31530', '31531']  # Example rule IDs to exclude
    if rule_id in excluded_rules:
        debug(f"Alert rule ID {rule_id} in exclusion list")
        return False

    return True

def extract_alert_context(alert):
    """Extract relevant alert context for correlation."""
    context = {
        'rule_id': alert.get('rule', {}).get('id', 'unknown'),
        'rule_description': alert.get('rule', {}).get('description', 'unknown'),
        'timestamp': alert.get('timestamp', ''),
        'agent_id': alert.get('agent', {}).get('id', '000'),
        'agent_name': alert.get('agent', {}).get('name', 'unknown')
    }

    # Add more specific fields based on rule type
    if 'data' in alert:
        context['data_fields'] = list(alert['data'].keys())

    return context

def determine_ip_types(context):
    """Determine what MISP IP types to query based on context."""
    ip_types = []

    # Use the direction from context
    if context['direction'] == 'source':
        ip_types.append('ip-src')
    elif context['direction'] == 'destination':
        ip_types.append('ip-dst')
    else:
        # If direction unclear, check both
        ip_types = ['ip-src', 'ip-dst']

    return ip_types

def extract_ips_with_context(alert):
    """Extract IPs with contextual information using only regex."""
    debug("Extracting IPs with context using regex only")

    ip_data = {}
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Convert alert to JSON string to search everywhere
    alert_json = json.dumps(alert)

    # Find all IPs in the entire alert
    all_ips = re.findall(ip_regex, alert_json)

    # Filter to only public IPs
    public_ips = [ip for ip in all_ips if is_public_ip(ip)]
    debug(f"Found {len(public_ips)} unique public IPs in alert")

    # For each IP, determine context by searching where it appears in the alert
    for ip in public_ips:
        # Try to determine the context/direction of the IP
        direction = "unknown"
        field_path = "unknown"
        raw_value = ""

        # Common field patterns that might indicate direction
        source_patterns = ["srcip", "src_ip", "source_ip"]
        dest_patterns = ["dstip", "dst_ip", "destination_ip"]

        # Helper function to search for IP in a nested dict
        def find_ip_in_dict(data, path=""):
            nonlocal direction, field_path, raw_value

            if isinstance(data, dict):
                for key, value in data.items():
                    new_path = f"{path}.{key}" if path else key

                    # If value is string and contains our IP
                    if isinstance(value, str) and ip in value:
                        # Determine direction based on field name
                        if any(pattern in key.lower() for pattern in source_patterns):
                            direction = "source"
                        elif any(pattern in key.lower() for pattern in dest_patterns):
                            direction = "destination"
                        field_path = new_path
                        raw_value = value
                        return True

                    # Recursively search deeper
                    if find_ip_in_dict(value, new_path):
                        return True

            elif isinstance(data, list):
                for i, item in enumerate(data):
                    new_path = f"{path}[{i}]"
                    if find_ip_in_dict(item, new_path):
                        return True

            return False

        # Search through the alert to find context
        find_ip_in_dict(alert)

        # Add to our results
        ip_data[ip] = {
            'field_path': field_path,
            'direction': direction,
            'raw_value': raw_value
        }
        debug(f"Found IP {ip} in field {field_path} as {direction}")

    return ip_data

def query_misp(ip, ip_type, api_key):
    """Query the MISP server for IP information."""
    url = 'https://10.5.254.41/attributes/restSearch'
    headers = {
        'Accept': 'application/json',
        'Authorization': api_key
    }
    payload = {
        'returnFormat': 'json',
        'type': ip_type,
        'value': ip
    }

    try:
        debug(f"Querying MISP for IP: {ip}, type: {ip_type}")
        response = requests.post(url, headers=headers, json=payload, verify=False)

        if response.status_code == 200:
            debug(f"Received valid response for {ip} ({ip_type})")
            return response.json()
        else:
            debug(f"Error querying MISP: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Failed to query MISP: {str(e)}")
        return None

def send_enriched_event(ip, misp_data, alert_context, ip_context):
    """Send enriched event back to Wazuh with alert context."""
    debug(f"Processing MISP data for IP: {ip}")

    # Excluded IPs
    excluded_ips = ["IPv4_1", "1.1.1.1"]
    if ip in excluded_ips:
        debug(f"Skipping excluded IP: {ip}")
        return

    # Build enriched event with alert context
    enriched_event = {
        "misp_ip": ip,
        "misp_attributes": [],
        "misp_events": [],
        # Add Wazuh context for correlation
        "wazuh_context": {
            "rule_id": alert_context["rule_id"],
            "rule_description": alert_context["rule_description"],
            "ip_field": ip_context["field_path"],
            "ip_direction": ip_context["direction"]
        }
    }

    event_ids = set()

    # Process all responses for this IP
    for ip_type, response in misp_data.items():
        attributes = response.get("response", {}).get("Attribute", [])
        if not attributes:
            continue

        for attribute in attributes:
            # Skip if the attribute is for excluded IPs
            if "value" in attribute and attribute["value"] in excluded_ips:
                continue

            # Add basic attribute info
            attr_info = {
                "type": attribute.get("type"),
                "value": attribute.get("value"),
                "category": attribute.get("category")
            }

            if attr_info not in enriched_event["misp_attributes"]:
                enriched_event["misp_attributes"].append(attr_info)

            # Track unique events
            if "event_id" in attribute and attribute["event_id"] not in event_ids:
                event_ids.add(attribute["event_id"])
                enriched_event["misp_events"].append({
                    "id": attribute["event_id"],
                    "info": attribute.get("Event", {}).get("info", "No info available")
                })

    # Send event if we have attributes
    if enriched_event["misp_attributes"]:
        debug(f"Sending enriched event for IP {ip} with {len(enriched_event['misp_attributes'])} attributes")
        send_event(enriched_event)
    else:
        debug(f"No relevant MISP data found for IP {ip}")

def send_event(msg, agent=None):
    """Sends event data to Wazuh."""
    try:
        # Format the message
        if not agent or agent["id"] == "000":
            string = "1:misp:{0}".format(json.dumps(msg))
        else:
            string = "1:[{0}] ({1}) {2}->misp:{3}".format(
                agent["id"],
                agent["name"],
                agent.get("ip", "any"),
                json.dumps(msg)
            )

        # Send via socket
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
        debug("Event successfully sent to Wazuh")

    except Exception as e:
        logging.error(f"Failed to send message to Wazuh: {str(e)}")

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)
