#!/var/ossec/framework/python/bin/python3
#code written for eDOK Srl Vobarno 2025
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

# Global Variables
debug_enabled = False  # Set to True to enable detailed debug logs
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
            send_enriched_event(ip, misp_data, alert_context, context, json_alert)
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

    # Add more specific fields based on rule type
    if 'data' in alert:
        context['data_fields'] = list(alert['data'].keys())

        # Extract common syscheck fields if present
        if 'syscheck' in alert:
            syscheck = alert.get('syscheck', {})
            context['syscheck'] = {
                'path': syscheck.get('path', ''),
                'event': syscheck.get('event', ''),
                'changed_attributes': syscheck.get('changed_attributes', [])
            }

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
        source_patterns = ["srcip", "src_ip", "source_ip", "src-ip", "source.ip", "sip", "from_ip"]
        dest_patterns = ["dstip", "dst_ip", "destination_ip", "dst-ip", "destination.ip", "dip", "to_ip"]

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
    url = 'https://Y.Y.Y.Y/attributes/restSearch'
    headers = {
        'Accept': 'application/json',
        'Authorization': api_key
    }
    payload = {
        'returnFormat': 'json',
        'type': ip_type,
        'value': ip,
        'includeEventTags': True,
        'includeContext': True,
        'includeWarninglistHits': True,
        'pythonify': False
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

def extract_tags_from_misp(attribute):
    """Extract tags from MISP attribute and event."""
    tags = []

    # Extract attribute tags
    if "Tag" in attribute:
        for tag in attribute.get("Tag", []):
            if "name" in tag:
                tags.append({
                    "name": tag["name"],
                    "color": tag.get("colour", "#ffffff"),
                    "level": "attribute"
                })

    # Extract event tags if available
    if "Event" in attribute and "Tag" in attribute["Event"]:
        for tag in attribute["Event"].get("Tag", []):
            if "name" in tag:
                tag_info = {
                    "name": tag["name"],
                    "color": tag.get("colour", "#ffffff"),
                    "level": "event"
                }
                if tag_info not in tags:
                    tags.append(tag_info)

    return tags

def calculate_threat_score(attribute, tags):
    """Calculate a threat score based on MISP data."""
    base_score = 0

    # Base score from attribute type/category
    if attribute.get("category") == "External analysis":
        base_score += 5
    if attribute.get("category") == "Network activity":
        base_score += 3

    # Score based on tags
    for tag in tags:
        tag_name = tag["name"].lower()

        # Check for TLP tags and adjust score
        if "tlp:red" in tag_name:
            base_score += 8
        elif "tlp:amber" in tag_name:
            base_score += 5
        elif "tlp:green" in tag_name:
            base_score += 2

        # Check for threat intel tags
        if "malware" in tag_name:
            base_score += 7
        if "ransomware" in tag_name:
            base_score += 9
        if "apt" in tag_name:
            base_score += 8
        if "botnet" in tag_name:
            base_score += 6
        if "phishing" in tag_name:
            base_score += 5
        if "scan" in tag_name:
            base_score += 3
        if "suspicious" in tag_name:
            base_score += 4

    # Cap at 10
    return min(base_score, 10)

def extract_related_attributes(attribute):
    """Extract related attributes from MISP."""
    related = []

    if "RelatedAttribute" in attribute:
        for rel_attr in attribute.get("RelatedAttribute", []):
            if isinstance(rel_attr, dict):
                related.append({
                    "type": rel_attr.get("type", "unknown"),
                    "value": rel_attr.get("value", ""),
                    "category": rel_attr.get("category", ""),
                    "relation": rel_attr.get("relation_type", "related-to")
                })

    return related

def extract_sightings_info(attribute):
    """Extract sightings information from MISP attribute."""
    sightings = {
        "count": 0,
        "first_seen": None,
        "last_seen": None,
        "sources": []
    }

    if "Sighting" in attribute:
        sighting_list = attribute.get("Sighting", [])
        sightings["count"] = len(sighting_list)

        dates = []
        for sighting in sighting_list:
            if "date_sighting" in sighting:
                dates.append(int(sighting["date_sighting"]))

            # Collect source organizations
            if "Organisation" in sighting and "name" in sighting["Organisation"]:
                org_name = sighting["Organisation"]["name"]
                if org_name not in sightings["sources"]:
                    sightings["sources"].append(org_name)

        if dates:
            sightings["first_seen"] = min(dates)
            sightings["last_seen"] = max(dates)

    return sightings

def send_enriched_event(ip, misp_data, alert_context, ip_context, original_alert):
    """Send enriched event back to Wazuh with detailed alert context."""
    debug(f"Processing MISP data for IP: {ip}")

    # Excluded IPs
    excluded_ips = ["IPv4_1", "1.1.1.1"]
    if ip in excluded_ips:
        debug(f"Skipping excluded IP: {ip}")
        return

    # Generate event ID for tracking
    event_id = hashlib.md5(f"{ip}:{alert_context['rule_id']}:{time.time()}".encode()).hexdigest()

    # Get current timestamp in ISO format
    timestamp = datetime.now().isoformat()

    # Build detailed enriched event
    enriched_event = {
        "integration": "misp",
        "event_id": event_id,
        "timestamp": timestamp,
        "detected_ip": {
            "value": ip,
            "direction": ip_context["direction"],
            "field_path": ip_context["field_path"],
            "raw_context": ip_context["raw_value"]
        },
        "misp_data": {
            "attributes": [],
            "events": [],
            "summary": {
                "total_attributes": 0,
                "total_events": 0,
                "earliest_event": None,
                "latest_event": None,
                "attribution": [],
                "threat_types": [],
                "max_threat_score": 0
            }
        }
    }

    # Add flattened wazuh_context data with preserved hierarchy
    enriched_event["rule"] = {
        "id": alert_context["rule_id"],
        "description": alert_context["rule_description"],
        "level": alert_context["rule_level"],
        "groups": alert_context["rule_groups"]
    }
    
    enriched_event["agent"] = {
        "id": alert_context["agent_id"],
        "name": alert_context["agent_name"],
        "ip": alert_context["agent_ip"]
    }
    
    enriched_event["manager"] = {
        "name": alert_context["manager_name"]
    }
    
    enriched_event["location"] = alert_context["location"]
    enriched_event["timestamp"] = alert_context["timestamp"]
    
    enriched_event["decoder"] = {
        "name": alert_context["decoder_name"]
    }

    # Include flattened original_data fields
    if "data" in original_alert:
        for key, value in original_alert["data"].items():
            enriched_event[key] = value

    unique_event_ids = set()
    max_score = 0
    event_dates = []
    threat_types = set()
    attribution = set()

    # Process all responses for this IP
    for ip_type, response in misp_data.items():
        attributes = response.get("response", {}).get("Attribute", [])
        if not attributes:
            continue

        for attribute in attributes:
            # Skip if the attribute is for excluded IPs
            if "value" in attribute and attribute["value"] in excluded_ips:
                continue

            # Extract tags
            tags = extract_tags_from_misp(attribute)

            # Calculate threat score
            threat_score = calculate_threat_score(attribute, tags)
            max_score = max(max_score, threat_score)

            # Extract related attributes
            related_attrs = extract_related_attributes(attribute)

            # Extract sightings
            sightings = extract_sightings_info(attribute)

            # Get event info
            event_info = attribute.get("Event", {}).get("info", "No info available")
            event_date = attribute.get("Event", {}).get("date", "")
            event_id = attribute.get("event_id", "")

            # Track event dates for summary
            if event_date:
                event_dates.append(event_date)

            # Extract threat types and attribution from tags
            for tag in tags:
                tag_name = tag["name"].lower()

                # Extract threat types
                for threat_type in ["malware", "ransomware", "apt", "botnet", "phishing", "ddos", "scan"]:
                    if threat_type in tag_name and threat_type not in threat_types:
                        threat_types.add(threat_type)

                # Extract attribution
                if tag_name.startswith("misp-galaxy:threat-actor") or tag_name.startswith("threat-actor"):
                    # Extract attribution name
                    parts = tag_name.split("=")
                    if len(parts) > 1:
                        actor = parts[1].strip('"')
                        attribution.add(actor)

            # Add detailed attribute info
            attr_info = {
                "type": attribute.get("type"),
                "value": attribute.get("value"),
                "category": attribute.get("category"),
                "to_ids": attribute.get("to_ids", False),
                "threat_score": threat_score,
                "tags": tags,
                "timestamp": attribute.get("timestamp", ""),
                "related_attributes": related_attrs,
                "sightings": sightings,
                "event_id": event_id
            }

            enriched_event["misp_data"]["attributes"].append(attr_info)

            # Track unique events
            if event_id and event_id not in unique_event_ids:
                unique_event_ids.add(event_id)
                enriched_event["misp_data"]["events"].append({
                    "id": event_id,
                    "info": event_info,
                    "date": event_date,
                    "analysis": attribute.get("Event", {}).get("analysis", ""),
                    "threat_level_id": attribute.get("Event", {}).get("threat_level_id", ""),
                    "org_name": attribute.get("Event", {}).get("Orgc", {}).get("name", "Unknown")
                })

    # Update summary information
    enriched_event["misp_data"]["summary"]["total_attributes"] = len(enriched_event["misp_data"]["attributes"])
    enriched_event["misp_data"]["summary"]["total_events"] = len(enriched_event["misp_data"]["events"])
    enriched_event["misp_data"]["summary"]["max_threat_score"] = max_score
    enriched_event["misp_data"]["summary"]["threat_types"] = list(threat_types)
    enriched_event["misp_data"]["summary"]["attribution"] = list(attribution)

    if event_dates:
        enriched_event["misp_data"]["summary"]["earliest_event"] = min(event_dates)
        enriched_event["misp_data"]["summary"]["latest_event"] = max(event_dates)

    # Add recommendations based on threat score
    if max_score >= 8:
        enriched_event["recommendations"] = {
            "priority": "high",
            "actions": [
                "Block this IP immediately at the firewall level",
                "Investigate all systems that communicated with this IP",
                "Preserve forensic evidence for possible incident response",
                "Escalate to security team immediately"
            ]
        }
    elif max_score >= 5:
        enriched_event["recommendations"] = {
            "priority": "medium",
            "actions": [
                "Monitor all traffic to/from this IP more closely",
                "Consider temporary blocking if behavior is suspicious",
                "Review logs for any suspicious activity involving this IP"
            ]
        }
    elif max_score > 0:
        enriched_event["recommendations"] = {
            "priority": "low",
            "actions": [
                "Monitor for unusual patterns of communication",
                "Add to watchlist for increased logging"
            ]
        }

    # Send event if we have attributes
    if enriched_event["misp_data"]["attributes"]:
        debug(f"Sending enriched event for IP {ip} with {len(enriched_event['misp_data']['attributes'])} attributes")
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
