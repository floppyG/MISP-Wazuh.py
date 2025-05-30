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
    level=logging.DEBUG if debug_enabled else logging.INFO, # Adjusted based on debug_enabled
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
        misp_data_responses = {} # Changed name to avoid conflict
        for ip_type in ip_types:
            misp_response = query_misp(ip, ip_type, api_key)
            if misp_response:
                misp_data_responses[ip_type] = misp_response

        # Process the MISP data for this IP
        if misp_data_responses:
            send_enriched_event(ip, misp_data_responses, alert_context, context, json_alert)
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
    if int(rule_level) <= 5: # As per example log, level is 6, so this is fine
        debug(f"Alert rule level {rule_level} below threshold")
        # return False # Keep processing for now, or adjust threshold if needed

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
    for ip in set(public_ips): # Use set to process unique IPs once
        # Try to determine the context/direction of the IP
        direction = "unknown"
        field_path = "unknown"
        raw_value_found = "" # Renamed to avoid confusion with 'value' key in dict

        # Common field patterns that might indicate direction
        source_patterns = ["srcip", "src_ip", "source_ip", "src-ip", "source.ip", "sip", "from_ip", "source_address"]
        dest_patterns = ["dstip", "dst_ip", "destination_ip", "dst-ip", "destination.ip", "dip", "to_ip", "destination_address"]

        # Helper function to search for IP in a nested dict
        def find_ip_in_dict(data, current_path=""):
            nonlocal direction, field_path, raw_value_found
            found_in_recursion = False

            if isinstance(data, dict):
                for key, value_item in data.items(): # Renamed value to value_item
                    new_path = f"{current_path}.{key}" if current_path else key
                    if isinstance(value_item, str) and ip in value_item:
                        if any(pattern in key.lower() for pattern in source_patterns):
                            direction = "source"
                        elif any(pattern in key.lower() for pattern in dest_patterns):
                            direction = "destination"
                        field_path = new_path
                        raw_value_found = value_item
                        return True # Found, stop searching this branch

                    if find_ip_in_dict(value_item, new_path):
                        found_in_recursion = True # Propagate found status
                        # if field_path != "unknown": return True # If specific path found, propagate

            elif isinstance(data, list):
                for i, item in enumerate(data):
                    new_path = f"{current_path}[{i}]"
                    if find_ip_in_dict(item, new_path):
                        found_in_recursion = True # Propagate found status
                        # if field_path != "unknown": return True

            return found_in_recursion

        # Search through the alert to find context
        find_ip_in_dict(alert)
        
        # Default to rule.description if specific field not found but IP is in rule.description
        # (as seen in example log's detected_ip.field_path)
        rule_desc = alert.get("rule", {}).get("description", "")
        if ip in rule_desc and field_path == "unknown":
            field_path = "rule.description"
            raw_value_found = rule_desc
            # Try to infer direction from rule description (simple check)
            if f"from {ip}" in rule_desc.lower():
                direction = "source"
            elif f"to {ip}" in rule_desc.lower():
                direction = "destination"


        ip_data[ip] = {
            'field_path': field_path,
            'direction': direction,
            'raw_value': raw_value_found
        }
        debug(f"Found IP {ip} in field {field_path} as {direction} with raw_value: '{raw_value_found}'")

    return ip_data


def query_misp(ip, ip_type, api_key):
    """Query the MISP server for IP information."""
    url = 'https://Y.Y.Y.Y/attributes/restSearch' # MISP URL from User
    headers = {
        'Accept': 'application/json',
        'Authorization': api_key
    }
    payload = {
        'returnFormat': 'json',
        'type': ip_type,
        'value': ip,
        'includeEventTags': True,
        'includeContext': True, # includeContext is for attribute context, not full event
        'includeWarninglistHits': True,
        'pythonify': False # Keep as False to get standard JSON
    }

    try:
        debug(f"Querying MISP for IP: {ip}, type: {ip_type}")
        response = requests.post(url, headers=headers, json=payload, verify=False) # verify=False for self-signed certs

        if response.status_code == 200:
            debug(f"Received valid response for {ip} ({ip_type})")
            return response.json()
        else:
            logging.warning(f"Error querying MISP for {ip} ({ip_type}): {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e: # More specific exception
        logging.error(f"Failed to query MISP for {ip} ({ip_type}): {str(e)}")
        return None

def extract_tags_from_misp(attribute_misp_data): # Renamed for clarity
    """Extract tags from MISP attribute and event."""
    tags = []
    seen_tags = set() # To avoid duplicate tags if they appear in both attribute and event

    # Extract attribute tags
    if "Tag" in attribute_misp_data:
        for tag_data in attribute_misp_data.get("Tag", []): # Renamed for clarity
            if "name" in tag_data:
                tag_tuple = (tag_data["name"], tag_data.get("colour", "#ffffff"), "attribute")
                if tag_tuple not in seen_tags:
                    tags.append({
                        "name": tag_data["name"],
                        "color": tag_data.get("colour", "#ffffff"),
                        "level": "attribute"
                    })
                    seen_tags.add(tag_tuple)

    # Extract event tags if available
    # The MISP response has Event data nested within each Attribute if includeEventData or similar is used
    # Or if the API call fetches full event. restSearch with includeEventTags might not provide full Event.Tag
    # The example log suggests event tags are indeed available.
    if "Event" in attribute_misp_data and "Tag" in attribute_misp_data["Event"]:
        for tag_data in attribute_misp_data["Event"].get("Tag", []):
            if "name" in tag_data:
                tag_tuple = (tag_data["name"], tag_data.get("colour", "#ffffff"), "event")
                if tag_tuple not in seen_tags: # Check if this exact tag (name, color, level) was already added
                    tags.append({
                        "name": tag_data["name"],
                        "color": tag_data.get("colour", "#ffffff"),
                        "level": "event"
                    })
                    seen_tags.add(tag_tuple)
    return tags

def calculate_threat_score(attribute_misp_data, tags): # Renamed for clarity
    """Calculate a threat score based on MISP data."""
    base_score = 0

    # Base score from attribute type/category
    if attribute_misp_data.get("category") == "External analysis":
        base_score += 5
    if attribute_misp_data.get("category") == "Network activity":
        base_score += 3

    # Score based on tags
    for tag in tags:
        tag_name = tag["name"].lower()

        # Check for TLP tags and adjust score
        if "tlp:red" in tag_name: base_score += 8
        elif "tlp:amber" in tag_name: base_score += 5
        elif "tlp:green" in tag_name: base_score += 2

        # Check for threat intel tags
        if "malware" in tag_name: base_score += 7
        if "ransomware" in tag_name: base_score += 9
        if "apt" in tag_name: base_score += 8
        if "botnet" in tag_name: base_score += 6
        if "phishing" in tag_name: base_score += 5
        if "scan" in tag_name: base_score += 3
        if "suspicious" in tag_name: base_score += 4
    
    # Score from to_ids (Indicator of Compromise)
    if attribute_misp_data.get("to_ids", False):
        base_score += 2 # Generally, an IDS flag means it's considered more actionable

    return min(base_score, 10) # Cap at 10

def extract_related_attributes(attribute_misp_data): # Renamed for clarity
    """Extract related attributes from MISP."""
    related = []
    # MISP's restSearch for attributes might not directly include 'RelatedAttribute'
    # This usually comes when fetching an Event or a full Attribute object.
    # Assuming it might be present based on original code.
    if "RelatedAttribute" in attribute_misp_data:
        for rel_attr_data in attribute_misp_data.get("RelatedAttribute", []): # Renamed for clarity
            if isinstance(rel_attr_data, dict):
                related.append({
                    "type": rel_attr_data.get("type", "unknown"),
                    "value": rel_attr_data.get("value", ""),
                    "category": rel_attr_data.get("category", ""),
                    # The key "relation_type" is not standard in MISP's RelatedAttribute.
                    # Common fields are 'object_relation', 'event_id', etc.
                    # Using 'comment' or a custom field if MISP is modified.
                    # For now, sticking to original structure if it worked for the user.
                    "relation": rel_attr_data.get("relation_type", rel_attr_data.get("comment", "related-to"))
                })
    return related

def extract_sightings_info(attribute_misp_data): # Renamed for clarity
    """Extract sightings information from MISP attribute."""
    sightings = {
        "count": 0,
        "first_seen": None,
        "last_seen": None,
        "sources": []
    }

    # Sightings are usually per-attribute.
    if "Sighting" in attribute_misp_data and isinstance(attribute_misp_data["Sighting"], list):
        sighting_list = attribute_misp_data.get("Sighting", [])
        sightings["count"] = len(sighting_list)

        dates = []
        sources_seen = set() # To keep sources unique
        for sighting_data in sighting_list: # Renamed for clarity
            if "date_sighting" in sighting_data:
                try:
                    dates.append(int(sighting_data["date_sighting"]))
                except ValueError:
                    debug(f"Invalid date_sighting format: {sighting_data['date_sighting']}")


            # Collect source organizations
            # MISP sightings can have 'org_id' or 'source' field. 'Organisation' is for event org.
            org_name_from_sighting = sighting_data.get("Organisation", {}).get("name") # If full org object is there
            if not org_name_from_sighting:
                 org_name_from_sighting = sighting_data.get("source") # Simpler source string

            if org_name_from_sighting and org_name_from_sighting not in sources_seen:
                sightings["sources"].append(org_name_from_sighting)
                sources_seen.add(org_name_from_sighting)
        
        if dates:
            sightings["first_seen"] = min(dates)
            sightings["last_seen"] = max(dates)
    return sightings

def send_enriched_event(ip, misp_api_responses, alert_context, ip_context, original_alert): # Renamed misp_data
    """Send enriched event back to Wazuh with detailed alert context."""
    debug(f"Processing MISP data for IP: {ip}")

    excluded_ips = ["IPv4_1", "1.1.1.1"] # Example, from original code
    if ip in excluded_ips:
        debug(f"Skipping excluded IP: {ip}")
        return

    event_id_hash_input = f"{ip}:{alert_context['rule_id']}:{alert_context['timestamp']}:{time.time()}"
    event_id = hashlib.md5(event_id_hash_input.encode()).hexdigest()
    
    # Timestamp for the enriched event itself
    current_iso_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "+0000"


    enriched_event = {
        "integration": "misp",
        "event_id": event_id, # Unique ID for this enriched log event
        "timestamp": current_iso_timestamp, # Timestamp of enrichment
        "detected_ip": {
            "value": ip,
            "direction": ip_context["direction"],
            "field_path": ip_context["field_path"],
            "raw_context": ip_context["raw_value"]
        },
        "misp_data": {
            "attributes": [], # Will be populated by aggregated attributes
            "events": [],     # Will be populated by unique MISP event details
            "summary": {
                "total_attributes": 0,
                "total_events": 0,
                "earliest_event_date": None,
                "latest_event_date": None,
                "attribution": [],
                "threat_types": [],
                "max_threat_score": 0
            }
        }
    }

    # Add Wazuh alert context (flattened original alert fields)
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
    enriched_event["manager"] = {"name": alert_context["manager_name"]}
    enriched_event["location"] = alert_context["location"]
    # Use the original Wazuh alert timestamp for a field like 'wazuh_alert_timestamp'
    enriched_event["wazuh_alert_timestamp"] = alert_context["timestamp"] 
    enriched_event["decoder"] = {"name": alert_context["decoder_name"]}

    if "data" in original_alert:
        for key, value in original_alert["data"].items():
            if key not in enriched_event: # Avoid overwriting top-level keys like 'timestamp'
                 enriched_event[key] = value

    # --- Aggregation Logic ---
    aggregated_attributes_map = {} # Stores {aggregation_key: aggregated_attribute_object}
    processed_misp_event_info = {} # Stores {misp_event_id: misp_event_details}
    
    # Helper for creating comparable tag representation for aggregation key
    def get_comparable_tag_tuple(tag_dict):
        return (tag_dict.get('name'), tag_dict.get('color'), tag_dict.get('level'))

    # Helper for creating comparable related attributes representation
    def get_comparable_related_attr(rel_attr_dict):
        return (
            rel_attr_dict.get("type"),
            rel_attr_dict.get("value"),
            rel_attr_dict.get("category"),
            rel_attr_dict.get("relation") 
        )

    for ip_type_queried, response in misp_api_responses.items(): # Renamed from misp_data
        if not response or "response" not in response or "Attribute" not in response["response"]:
            continue
        
        misp_attributes_list = response["response"]["Attribute"]
        if not isinstance(misp_attributes_list, list): # MISP might return a single dict if only one attr
            misp_attributes_list = [misp_attributes_list]

        for misp_attribute_data in misp_attributes_list:
            if "value" in misp_attribute_data and misp_attribute_data["value"] in excluded_ips:
                continue

            tags = extract_tags_from_misp(misp_attribute_data)
            threat_score = calculate_threat_score(misp_attribute_data, tags)
            related_attrs = extract_related_attributes(misp_attribute_data)
            sightings = extract_sightings_info(misp_attribute_data)
            
            misp_event_id_from_attr = misp_attribute_data.get("event_id", "")
            attribute_timestamp = misp_attribute_data.get("timestamp", "")

            # Create aggregation key
            comparable_tags = tuple(sorted(get_comparable_tag_tuple(t) for t in tags))
            comparable_related_attrs = tuple(sorted(get_comparable_related_attr(ra) for ra in related_attrs))
            
            # Sightings structure for key:
            # Make sure sightings sources are sorted for consistent key
            sorted_sightings_sources = tuple(sorted(sightings.get("sources", [])))
            comparable_sightings = (
                sightings.get("count", 0),
                sightings.get("first_seen"),
                sightings.get("last_seen"),
                sorted_sightings_sources
            )

            aggregation_key = (
                misp_attribute_data.get("type"),
                misp_attribute_data.get("value"), # Should be the IP we are processing
                misp_attribute_data.get("category"),
                misp_attribute_data.get("to_ids", False),
                threat_score, # Already calculated
                comparable_tags,
                comparable_related_attrs,
                comparable_sightings
            )

            if aggregation_key not in aggregated_attributes_map:
                aggregated_attributes_map[aggregation_key] = {
                    "type": misp_attribute_data.get("type"),
                    "value": misp_attribute_data.get("value"),
                    "category": misp_attribute_data.get("category"),
                    "to_ids": misp_attribute_data.get("to_ids", False),
                    "threat_score": threat_score,
                    "tags": tags, # Store the original list of dicts for tags
                    "related_attributes": related_attrs,
                    "sightings": sightings,
                    "associated_misp_event_ids": [misp_event_id_from_attr] if misp_event_id_from_attr else [],
                    "attribute_timestamps": [attribute_timestamp] if attribute_timestamp else []
                }
            else:
                # Attribute group exists, append event_id and timestamp
                if misp_event_id_from_attr and misp_event_id_from_attr not in aggregated_attributes_map[aggregation_key]["associated_misp_event_ids"]:
                    aggregated_attributes_map[aggregation_key]["associated_misp_event_ids"].append(misp_event_id_from_attr)
                if attribute_timestamp and attribute_timestamp not in aggregated_attributes_map[aggregation_key]["attribute_timestamps"]:
                     aggregated_attributes_map[aggregation_key]["attribute_timestamps"].append(attribute_timestamp)
                     aggregated_attributes_map[aggregation_key]["attribute_timestamps"].sort() # Keep them sorted


            # Store unique MISP event information
            if misp_event_id_from_attr and misp_event_id_from_attr not in processed_misp_event_info:
                event_data = misp_attribute_data.get("Event", {})
                processed_misp_event_info[misp_event_id_from_attr] = {
                    "id": misp_event_id_from_attr,
                    "info": event_data.get("info", "No info available"),
                    "date": event_data.get("date", ""),
                    "analysis": event_data.get("analysis", ""),
                    "threat_level_id": event_data.get("threat_level_id", ""),
                    "org_name": event_data.get("Orgc", {}).get("name", event_data.get("org_name", "Unknown")) # org_name as fallback
                }
    
    enriched_event["misp_data"]["attributes"] = list(aggregated_attributes_map.values())
    enriched_event["misp_data"]["events"] = list(processed_misp_event_info.values())

    # --- Update Summary ---
    summary = enriched_event["misp_data"]["summary"]
    summary["total_attributes"] = len(enriched_event["misp_data"]["attributes"])
    summary["total_events"] = len(enriched_event["misp_data"]["events"])

    all_event_dates = [ev_info["date"] for ev_info in enriched_event["misp_data"]["events"] if ev_info.get("date")]
    if all_event_dates:
        summary["earliest_event_date"] = min(all_event_dates)
        summary["latest_event_date"] = max(all_event_dates)

    max_calculated_score = 0
    current_threat_types = set()
    current_attribution = set()

    for agg_attr in enriched_event["misp_data"]["attributes"]:
        max_calculated_score = max(max_calculated_score, agg_attr.get("threat_score", 0))
        for tag in agg_attr.get("tags", []):
            tag_name = tag["name"].lower()
            for tt in ["malware", "ransomware", "apt", "botnet", "phishing", "ddos", "scan"]:
                if tt in tag_name: current_threat_types.add(tt)
            if tag_name.startswith("misp-galaxy:threat-actor") or tag_name.startswith("threat-actor"):
                parts = tag_name.split("=")
                if len(parts) > 1: current_attribution.add(parts[1].strip('"'))
            elif "tlp:" in tag_name : # Example of capturing TLP as a threat type for summary
                current_threat_types.add(tag_name.split(":")[1])


    summary["max_threat_score"] = max_calculated_score
    summary["threat_types"] = sorted(list(current_threat_types))
    summary["attribution"] = sorted(list(current_attribution))

    # Add recommendations based on the final max_threat_score
    if summary["max_threat_score"] >= 8:
        enriched_event["recommendations"] = {
            "priority": "high", "actions": [
                "Block this IP immediately at the firewall level",
                "Investigate all systems that communicated with this IP",
                "Preserve forensic evidence for possible incident response",
                "Escalate to security team immediately"
            ]}
    elif summary["max_threat_score"] >= 5:
        enriched_event["recommendations"] = {
            "priority": "medium", "actions": [
                "Monitor all traffic to/from this IP more closely",
                "Consider temporary blocking if behavior is suspicious",
                "Review logs for any suspicious activity involving this IP"
            ]}
    elif summary["max_threat_score"] > 0:
        enriched_event["recommendations"] = {
            "priority": "low", "actions": [
                "Monitor for unusual patterns of communication",
                "Add to watchlist for increased logging"
            ]}

    if enriched_event["misp_data"]["attributes"]:
        debug(f"Sending ENRICHED event for IP {ip} with {summary['total_attributes']} aggregated attribute groups and {summary['total_events']} MISP events.")
        send_event(enriched_event, agent=alert_context) # Pass agent context if needed by send_event
    else:
        debug(f"No relevant MISP data (after aggregation) found for IP {ip}")


def send_event(msg, agent=None): # agent parameter added to match call
    """Sends event data to Wazuh."""
    try:
        # Format the message
        # The original send_event took agent from json_alert.get('agent', {})
        # Here, agent is passed as alert_context which has agent_id, agent_name, agent_ip
        
        # Ensure agent is a dict with expected keys, or default
        agent_details = {
            "id": "000", 
            "name": "UnknownAgent", 
            "ip": "any"
        }
        if agent and isinstance(agent, dict):
            agent_details["id"] = agent.get("agent_id", "000")
            agent_details["name"] = agent.get("agent_name", "UnknownAgent")
            agent_details["ip"] = agent.get("agent_ip", "any")


        if agent_details["id"] == "000": # Default or system agent
            string = f"1:misp:{json.dumps(msg)}"
        else:
            string = f"1:[{agent_details['id']}] ({agent_details['name']}) {agent_details['ip']}->misp:{json.dumps(msg)}"
        
        debug(f"Sending to Wazuh socket: {string[:200]}...") # Log snippet

        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
        debug("Event successfully sent to Wazuh")

    except Exception as e:
        logging.error(f"Failed to send message to Wazuh: {str(e)}")
        # Optionally, log the full message that failed if small enough or to a separate error log
        # logging.debug(f"Failed message content: {json.dumps(msg)}")


if __name__ == "__main__":
    # For testing, you might want to enable debug_enabled
    # debug_enabled = True 
    # logging.getLogger().setLevel(logging.DEBUG if debug_enabled else logging.INFO)

    try:
        main(sys.argv)
    except Exception as e:
        logging.exception(f"Unexpected error in main execution: {str(e)}") # Use logging.exception for stack trace
        sys.exit(1)
