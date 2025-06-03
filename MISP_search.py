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

# Importing ipwhois module
try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import ASNRegistryError, WhoisLookupError, HTTPLookupError
except ImportError:
    print("No module 'ipwhois' found. Install: pip install ipwhois")
    sys.exit(1)


# Global Variables
debug_enabled = False  # Set to True to enable detailed debug logs
socket_addr = "/var/ossec/queue/sockets/queue"
recent_logs_file = "/var/ossec/tmp/recent_misp_whois_logs.json" # Updated
deduplication_window = 3600  # Seconds (1 hour)

# Configure logging
logging.basicConfig(
    filename='/var/ossec/logs/misp_whois_integration.log', # Updated
    level=logging.DEBUG if debug_enabled else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %H:%M:%S %Z %Y'
)

class RecentLogTracker:
    # ... (Classe RecentLogTracker come prima) ...
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


def main(args):
    debug("Starting script execution")
    if len(args) < 3:
        logging.error("Usage: python script_name.py path_to_alerts.json misp_api_key")
        sys.exit(1)

    alert_file_location = args[1]
    misp_api_key = args[2]

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
    debug(f"Processing alert: {alert_context}")

    ip_data_map = extract_ips_with_context(json_alert)
    if not ip_data_map:
        debug("No public IPs found in alert that match criteria")
        sys.exit(0)

    for ip, ip_context_data in ip_data_map.items():
        debug(f"Processing IP {ip} with context: {ip_context_data['field_path']}")
        dedup_key = f"{alert_context['rule_id']}:{ip}:{ip_context_data['direction']}"

        if log_tracker.is_duplicate(dedup_key):
            debug(f"Skipping duplicate alert-IP combination: {dedup_key}")
            continue

        # Query MISP
        ip_types_for_misp = determine_ip_types(ip_context_data)
        misp_data_responses = {}
        for ip_type in ip_types_for_misp:
            misp_response = query_misp(ip, ip_type, misp_api_key)
            if misp_response:
                misp_data_responses[ip_type] = misp_response

        # Query WHOIS
        whois_data_result = query_whois(ip) # Renamed for clarity

        if misp_data_responses or whois_data_result: # If we have data from MISP or WHOIS
            send_enriched_event(ip, misp_data_responses, whois_data_result, alert_context, ip_context_data, json_alert)
            log_tracker.mark_sent(dedup_key)
        else:
            debug(f"No MISP or WHOIS data found for IP {ip}")

def debug(msg):
    if debug_enabled:
        logging.debug(msg)

def is_public_ip(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
        return not ip_addr.is_private and not ip_addr.is_loopback
    except ValueError:
        return False

def validate_wazuh_alert(alert):
    # ... (implementazione come prima) ...
    if not isinstance(alert, dict):
        debug("Alert is not a dictionary")
        return False
    if 'rule' not in alert or 'id' not in alert.get('rule', {}):
        debug("Alert missing rule ID")
        return False
    rule_level = alert.get('rule', {}).get('level', 0)
    if int(rule_level) <= 5: # Example threshold
        debug(f"Alert rule level {rule_level} below threshold")
    excluded_rules = ['31530', '31531']
    if alert.get('rule', {}).get('id') in excluded_rules:
        debug(f"Alert rule ID {alert.get('rule', {}).get('id')} in exclusion list")
        return False
    return True


def extract_alert_context(alert):
    # ... (implementazione come prima) ...
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
    # ... (implementazione come prima) ...
    ip_types = []
    if context_data['direction'] == 'source': ip_types.append('ip-src')
    elif context_data['direction'] == 'destination': ip_types.append('ip-dst')
    else: ip_types = ['ip-src', 'ip-dst']
    return ip_types

def extract_ips_with_context(alert):
    # ... (implementazione come prima) ...
    debug("Extracting IPs with context using regex only")
    ip_data = {}
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    alert_json = json.dumps(alert)
    all_ips = re.findall(ip_regex, alert_json)
    public_ips = [ip for ip in all_ips if is_public_ip(ip)]
    debug(f"Found {len(public_ips)} unique public IPs in alert")

    for ip_addr in set(public_ips): # Renamed loop variable
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
                        if any(pattern in key.lower() for pattern in source_patterns): direction = "source"
                        elif any(pattern in key.lower() for pattern in dest_patterns): direction = "destination"
                        field_path = new_path
                        raw_value_found = value_item
                        return True
                    if find_ip_in_dict(value_item, new_path): return True # Propagate found
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    new_path = f"{current_path}[{i}]"
                    if find_ip_in_dict(item, new_path): return True # Propagate found
            return False

        find_ip_in_dict(alert)
        rule_desc = alert.get("rule", {}).get("description", "")
        if ip_addr in rule_desc and field_path == "unknown":
            field_path = "rule.description"
            raw_value_found = rule_desc
            if f"from {ip_addr}" in rule_desc.lower(): direction = "source"
            elif f"to {ip_addr}" in rule_desc.lower(): direction = "destination"

        ip_data[ip_addr] = {'field_path': field_path, 'direction': direction, 'raw_value': raw_value_found}
        debug(f"Found IP {ip_addr} in field {field_path} as {direction} with raw_value: '{raw_value_found}'")
    return ip_data

def query_misp(ip, ip_type, api_key):
    # ... (implementazione come prima) ...
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
    """Query WHOIS information for an IP address using ipwhois."""
    debug(f"Querying WHOIS for IP: {ip}")
    try:
        # Using a timeout for the WHOIS lookup
        obj = IPWhois(ip, timeout=10)
        # lookup_whois tries RDAP first by default, then legacy whois.
        # allow_permutations is for domains, not IPs.
        # asn_alts can be used to specify ASN lookup methods if needed.
        results = obj.lookup_whois(inc_nir=True) # inc_nir for National Internet Registry data

        if not results:
            debug(f"No WHOIS data returned for IP: {ip}")
            return None

        # Extract relevant information
        # ASN details
        asn_info = {
            "asn": results.get("asn"),
            "description": results.get("asn_description"),
            "cidr": results.get("asn_cidr"),
            "registry": results.get("asn_registry"),
            "country_code": results.get("asn_country_code"),
            "date": results.get("asn_date"),
        }

        # Network details (ipwhois puts most info under 'nets')
        # We'll take the first network block, or provide a summary.
        # 'nets' is a list of dictionaries.
        network_info_list = []
        if results.get("nets") and isinstance(results["nets"], list):
            for net in results["nets"]:
                if not isinstance(net, dict): continue
                network_info_list.append({
                    "cidr": net.get("cidr"),
                    "name": net.get("name"),
                    "handle": net.get("handle"),
                    "range": net.get("range"),
                    "description": net.get("description"),
                    "country": net.get("country"),
                    "address": net.get("address"),
                    "city": net.get("city"),
                    "state": net.get("state"),
                    "postal_code": net.get("postal_code"),
                    "created": net.get("created"),
                    "updated": net.get("updated"),
                    "abuse_emails": net.get("abuse_emails"), # Could be a string or list
                    "tech_emails": net.get("tech_emails"),
                })

        # NIR information (if available and inc_nir=True)
        nir_info = results.get("nir") # This will be a dictionary if present

        whois_output = {
            "queried_ip": ip,
            "asn_info": asn_info,
            "networks": network_info_list, # List of network blocks
            "nir_info": nir_info # National Internet Registry specific data
            # Consider adding raw output if needed, but it can be very verbose:
            # "raw": results.get("raw")
        }
        debug(f"Successfully retrieved WHOIS for {ip}")
        return whois_output

    except (ASNRegistryError, WhoisLookupError, HTTPLookupError) as e:
        logging.warning(f"WHOIS lookup failed for {ip}: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during WHOIS lookup for {ip}: {str(e)}")
        return None


def extract_tags_from_misp(attribute_misp_data):
    # ... (implementazione come prima) ...
    tags, seen_tags = [], set()
    if "Tag" in attribute_misp_data:
        for tag_data in attribute_misp_data.get("Tag", []):
            if "name" in tag_data:
                tag_tuple = (tag_data["name"], tag_data.get("colour", "#ffffff"), "attribute")
                if tag_tuple not in seen_tags:
                    tags.append({"name": tag_data["name"], "color": tag_data.get("colour", "#ffffff"), "level": "attribute"})
                    seen_tags.add(tag_tuple)
    if "Event" in attribute_misp_data and "Tag" in attribute_misp_data["Event"]:
        for tag_data in attribute_misp_data["Event"].get("Tag", []):
            if "name" in tag_data:
                tag_tuple = (tag_data["name"], tag_data.get("colour", "#ffffff"), "event")
                if tag_tuple not in seen_tags:
                    tags.append({"name": tag_data["name"], "color": tag_data.get("colour", "#ffffff"), "level": "event"})
                    seen_tags.add(tag_tuple)
    return tags

def calculate_threat_score(attribute_misp_data, tags):
    # ... (implementazione come prima) ...
    base_score = 0
    if attribute_misp_data.get("category") == "External analysis": base_score += 5
    if attribute_misp_data.get("category") == "Network activity": base_score += 3
    for tag in tags:
        tag_name = tag["name"].lower()
        if "tlp:red" in tag_name: base_score += 8
        elif "tlp:amber" in tag_name: base_score += 5
        # ... other tag scores
    if attribute_misp_data.get("to_ids", False): base_score += 2
    return min(base_score, 10)

def extract_related_attributes(attribute_misp_data):
    # ... (implementazione come prima) ...
    related = []
    if "RelatedAttribute" in attribute_misp_data:
        for rel_attr_data in attribute_misp_data.get("RelatedAttribute", []):
            if isinstance(rel_attr_data, dict):
                related.append({
                    "type": rel_attr_data.get("type", "unknown"),
                    "value": rel_attr_data.get("value", ""),
                    "category": rel_attr_data.get("category", ""),
                    "relation": rel_attr_data.get("relation_type", rel_attr_data.get("comment", "related-to"))
                })
    return related

def extract_sightings_info(attribute_misp_data):
    # ... (implementazione come prima) ...
    sightings = {"count": 0, "first_seen": None, "last_seen": None, "sources": []}
    if "Sighting" in attribute_misp_data and isinstance(attribute_misp_data["Sighting"], list):
        sighting_list = attribute_misp_data.get("Sighting", [])
        sightings["count"] = len(sighting_list)
        dates = []
        sources_seen = set()
        for sighting_data in sighting_list:
            if "date_sighting" in sighting_data:
                try: dates.append(int(sighting_data["date_sighting"]))
                except ValueError: debug(f"Invalid date_sighting format: {sighting_data['date_sighting']}")
            org_name_from_sighting = sighting_data.get("Organisation", {}).get("name")
            if not org_name_from_sighting: org_name_from_sighting = sighting_data.get("source")
            if org_name_from_sighting and org_name_from_sighting not in sources_seen:
                sightings["sources"].append(org_name_from_sighting)
                sources_seen.add(org_name_from_sighting)
        if dates:
            sightings["first_seen"] = min(dates)
            sightings["last_seen"] = max(dates)
    return sightings

def send_enriched_event(ip, misp_api_responses, whois_data, alert_context, ip_context_data, original_alert): # Added whois_data
    debug(f"Processing MISP and WHOIS data for IP: {ip}")
    # Read excluded IPs from file
    excluded_ips = []
    try:
        with open('/var/ossec/integrations/excluded_ips.txt', 'r') as f:
            content = f.read().strip()
            if content:
                excluded_ips = [ip.strip() for ip in content.split(',') if ip.strip()]
        debug(f"Loaded {len(excluded_ips)} IPs from exclusion list")
    except FileNotFoundError:
        logging.warning("excluded_ips.txt not found - no IPs will be excluded")
    except Exception as e:
        logging.error(f"Error reading excluded_ips.txt: {str(e)}")
    if ip in excluded_ips:
        debug(f"Skipping excluded IP: {ip}")
        return

    event_id_hash_input = f"{ip}:{alert_context['rule_id']}:{alert_context['timestamp']}:{time.time()}"
    event_id = hashlib.md5(event_id_hash_input.encode()).hexdigest()
    current_iso_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "+0000"

    enriched_event = {
        "integration": "misp_whois_enrichment", # Updated integration name
        "event_id": event_id, "timestamp": current_iso_timestamp,
        "detected_ip": {
            "value": ip, "direction": ip_context_data["direction"],
            "field_path": ip_context_data["field_path"], "raw_context": ip_context_data["raw_value"]
        },
        "misp_data": { # Initialize MISP structure
            "attributes": [], "events": [],
            "summary": {
                "total_attributes": 0, "total_events": 0, "earliest_event_date": None,
                "latest_event_date": None, "attribution": [], "threat_types": [], "max_threat_score": 0
            }
        },
        "whois_info": whois_data if whois_data else {"queried_ip": ip, "message": "No WHOIS data found or error during lookup"} # Add WHOIS data
    }

    # Add Wazuh alert context
    enriched_event["rule"] = {"id": alert_context["rule_id"], "description": alert_context["rule_description"], "level": alert_context["rule_level"], "groups": alert_context["rule_groups"]}
    enriched_event["agent"] = {"id": alert_context["agent_id"], "name": alert_context["agent_name"], "ip": alert_context["agent_ip"]}
    enriched_event["manager"] = {"name": alert_context["manager_name"]}
    enriched_event["location"] = alert_context["location"]
    enriched_event["wazuh_alert_timestamp"] = alert_context["timestamp"]
    enriched_event["decoder"] = {"name": alert_context["decoder_name"]}
    if "data" in original_alert:
        for key, value in original_alert["data"].items():
            if key not in enriched_event: enriched_event[key] = value

    # --- MISP Data Processing (Aggregated) ---
    if misp_api_responses:
        # ... (La logica di aggregazione MISP come prima, assicurati che sia completa e corretta) ...
        aggregated_attributes_map = {}
        processed_misp_event_info = {}
        def get_comparable_tag_tuple(tag_dict): return (tag_dict.get('name'), tag_dict.get('color'), tag_dict.get('level'))
        def get_comparable_related_attr(rel_attr_dict): return (rel_attr_dict.get("type"), rel_attr_dict.get("value"), rel_attr_dict.get("category"), rel_attr_dict.get("relation"))

        for ip_type_queried, response in misp_api_responses.items():
            if not response or "response" not in response or "Attribute" not in response["response"]: continue
            misp_attributes_list = response["response"]["Attribute"]
            if not isinstance(misp_attributes_list, list): misp_attributes_list = [misp_attributes_list]

            for misp_attribute_data in misp_attributes_list:
                if "value" in misp_attribute_data and misp_attribute_data["value"] in excluded_ips: continue
                tags = extract_tags_from_misp(misp_attribute_data)
                threat_score = calculate_threat_score(misp_attribute_data, tags)
                related_attrs = extract_related_attributes(misp_attribute_data)
                sightings = extract_sightings_info(misp_attribute_data)
                misp_event_id_from_attr = misp_attribute_data.get("event_id", "")
                attribute_timestamp = misp_attribute_data.get("timestamp", "")
                comparable_tags = tuple(sorted(get_comparable_tag_tuple(t) for t in tags))
                comparable_related_attrs = tuple(sorted(get_comparable_related_attr(ra) for ra in related_attrs))
                sorted_sightings_sources = tuple(sorted(sightings.get("sources", [])))
                comparable_sightings = (sightings.get("count", 0), sightings.get("first_seen"), sightings.get("last_seen"), sorted_sightings_sources)

                aggregation_key = (
                    misp_attribute_data.get("type"), misp_attribute_data.get("value"), misp_attribute_data.get("category"),
                    misp_attribute_data.get("to_ids", False), threat_score, comparable_tags, comparable_related_attrs, comparable_sightings
                )
                if aggregation_key not in aggregated_attributes_map:
                    aggregated_attributes_map[aggregation_key] = {
                        "type": misp_attribute_data.get("type"), "value": misp_attribute_data.get("value"),
                        "category": misp_attribute_data.get("category"), "to_ids": misp_attribute_data.get("to_ids", False),
                        "threat_score": threat_score, "tags": tags, "related_attributes": related_attrs, "sightings": sightings,
                        "associated_misp_event_ids": [misp_event_id_from_attr] if misp_event_id_from_attr else [],
                        "attribute_timestamps": [attribute_timestamp] if attribute_timestamp else []
                    }
                else:
                    if misp_event_id_from_attr and misp_event_id_from_attr not in aggregated_attributes_map[aggregation_key]["associated_misp_event_ids"]:
                        aggregated_attributes_map[aggregation_key]["associated_misp_event_ids"].append(misp_event_id_from_attr)
                    if attribute_timestamp and attribute_timestamp not in aggregated_attributes_map[aggregation_key]["attribute_timestamps"]:
                        aggregated_attributes_map[aggregation_key]["attribute_timestamps"].append(attribute_timestamp)
                        aggregated_attributes_map[aggregation_key]["attribute_timestamps"].sort()

                if misp_event_id_from_attr and misp_event_id_from_attr not in processed_misp_event_info:
                    event_data = misp_attribute_data.get("Event", {})
                    processed_misp_event_info[misp_event_id_from_attr] = {
                        "id": misp_event_id_from_attr, "info": event_data.get("info", "No info available"), "date": event_data.get("date", ""),
                        "analysis": event_data.get("analysis", ""), "threat_level_id": event_data.get("threat_level_id", ""),
                        "org_name": event_data.get("Orgc", {}).get("name", event_data.get("org_name", "Unknown"))
                    }

        enriched_event["misp_data"]["attributes"] = list(aggregated_attributes_map.values())
        enriched_event["misp_data"]["events"] = list(processed_misp_event_info.values())
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
                elif "tlp:" in tag_name : current_threat_types.add(tag_name.split(":")[1])
        summary["max_threat_score"] = max_calculated_score
        summary["threat_types"] = sorted(list(current_threat_types))
        summary["attribution"] = sorted(list(current_attribution))

    # Add recommendations
    misp_max_score = enriched_event["misp_data"]["summary"].get("max_threat_score", 0)
    recommendations = {"priority": "low", "actions": ["Monitor for unusual patterns"]}
    if misp_max_score >= 8:
        recommendations = {"priority": "high", "actions": ["Block IP", "Investigate", "Preserve evidence", "Escalate"]}
    elif misp_max_score >= 5:
        recommendations = {"priority": "medium", "actions": ["Monitor IP closely", "Consider temporary block", "Review logs"]}
    enriched_event["recommendations"] = recommendations

    if enriched_event["misp_data"]["attributes"] or enriched_event["whois_info"].get("asn_info"): # Check if we have MISP or some WHOIS ASN info
        misp_attr_count = len(enriched_event["misp_data"]["attributes"])
        whois_present = "data present" if enriched_event["whois_info"].get("asn_info") else "no data"
        debug(f"Sending ENRICHED event for IP {ip} with {misp_attr_count} MISP attribute groups and WHOIS info: {whois_present}.")
        send_event(enriched_event, agent=alert_context)
    else:
        debug(f"No relevant MISP or WHOIS data found for IP {ip}")

def send_event(msg, agent=None):
    try:
        agent_details = {"id": "000", "name": "UnknownAgent", "ip": "any"}
        if agent and isinstance(agent, dict):
            agent_details["id"] = agent.get("agent_id", "000")
            agent_details["name"] = agent.get("agent_name", "UnknownAgent")
            agent_details["ip"] = agent.get("agent_ip", "any")

        program_name = "misp_whois" # Updated program name for Wazuh log
        if agent_details["id"] == "000":
            string = f"1:{program_name}:{json.dumps(msg)}"
        else:
            string = f"1:[{agent_details['id']}] ({agent_details['name']}) {agent_details['ip']}->{program_name}:{json.dumps(msg)}"

        debug(f"Sending to Wazuh socket: {string[:300]}...")
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
        debug("Event successfully sent to Wazuh")
    except Exception as e:
        logging.error(f"Failed to send message to Wazuh: {str(e)}")

if __name__ == "__main__":
    # logging.info("Script started with __main__")
    try:
        main(sys.argv)
    except Exception as e:
        logging.exception(f"Unexpected error in main execution: {str(e)}")
        sys.exit(1)
