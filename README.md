🧩 Overview

This Python script performs the following tasks:

    Parses a Wazuh alert JSON file.

    Extracts public IP addresses from the alert.

    Queries MISP for each IP to check for any related threat intelligence.

    Sends enriched data back to Wazuh, avoiding duplicate processing using a deduplication mechanism.

🔧 Imports and Setup

    Standard libraries like json, sys, logging, os, and time.

    Networking and parsing tools: ipaddress, re, urllib3, socket.

    Third-party: requests for HTTP requests to MISP API.

    SSL warnings are suppressed with urllib3.disable_warnings.

🧪 Global Variables

    debug_enabled: Enables debug logging if set to True.

    socket_addr: Wazuh UNIX socket path for sending events.

    recent_logs_file: JSON file to keep track of recently processed logs.

    deduplication_window: Time window (1 hour) to skip duplicate alerts.

📚 Logging Setup

Logs to /var/ossec/logs/misp_integration.log with timestamps and debug level.
📦 Class: RecentLogTracker

Handles deduplication of alert-IP combinations to avoid reprocessing.
Key Methods:

    _load_logs(): Loads recent logs from JSON file.

    _save_logs(): Saves current log state back to file.

    is_duplicate(key): Checks if the same alert-IP was processed recently.

    mark_sent(key): Marks a log as recently sent.

    _clean_old_entries(): Purges old entries outside the deduplication window.

🚀 Function: main(args)

The entry point of the script.
Steps:

    Reads command-line args: expects alert file path and MISP API key.

    Initializes the deduplication tracker.

    Parses the alert JSON file.

    Validates the alert structure and type.

    Extracts context and relevant public IPs.

    For each IP:

        Checks deduplication.

        Determines if it's a source or destination.

        Queries MISP using appropriate type (ip-src, ip-dst).

        Sends enriched data back to Wazuh if threat intelligence is found.

🔍 Function: debug(msg)

Logs debug messages to the log file if debug_enabled is True.
🌐 Function: is_public_ip(ip)

Checks if an IP is public (i.e., not private or loopback).
✅ Function: validate_wazuh_alert(alert)

Ensures the alert:

    Is a dictionary.

    Has a rule.id.

    Has a severity rule.level > 5.

    Is not excluded (e.g., rule IDs 31530, 31531).

🧠 Function: extract_alert_context(alert)

Extracts contextual info from the alert:

    Rule ID, description, timestamp, agent ID/name, and optional data fields.

🔁 Function: determine_ip_types(context)

Based on direction (source, destination), chooses which MISP IP types to query:

    ip-src, ip-dst, or both.

🕵️ Function: extract_ips_with_context(alert)

Uses regex and recursive dictionary search to:

    Extract all IPs from the alert JSON.

    Identify public IPs only.

    Determine context (field_path, direction) by searching field names (e.g., srcip, dstip).

🔗 Function: query_misp(ip, ip_type, api_key)

Sends a POST request to the MISP server:

    Uses /attributes/restSearch endpoint.

    Authenticates with API key.

    Returns JSON data with relevant attributes/events.

🎁 Function: send_enriched_event(ip, misp_data, alert_context, ip_context)

Builds a structured enriched alert that includes:

    MISP attributes (e.g., threat tags, values, categories).

    Related MISP events (with event_id, info).

    Original Wazuh alert context.

Also:

    Skips specific excluded IPs like 1.1.1.1.

    Only sends enriched alerts with actual MISP data.

📤 Function: send_event(msg, agent=None)

Formats the final message string for Wazuh:

    If agent is unknown (id == 000), sends as general manager message.

    Else, formats it with agent details.

    Uses UNIX domain socket to send to Wazuh.

🔚 Entry Point: if __name__ == "__main__"

Executes the script:

    Wraps main() in a try-except block.

    Logs any unexpected errors.
