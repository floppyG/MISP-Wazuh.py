# Wazuh-MISP Integration Script
## Overview
This Python script integrates Wazuh with MISP (Malware Information Sharing Platform). It processes alerts in JSON format, extracts public IP addresses, queries the MISP API for threat intelligence, and sends relevant findings back to the Wazuh socket for further analysis.

# Explanation
Script Purpose:

Processes Wazuh alert JSON files to extract public IP addresses.
Queries a MISP server for IP-related threat intelligence using the MISP API.
Filters the received data and sends relevant findings to the Wazuh socket for further analysis.
Key Components:

- `is_public_ip(ip)`: Checks if an IP address is public.
- `query_misp(ip, ip_type, api_key)`: Queries the MISP server for IP intelligence.
- `request_misp_info(alert, api_key)`: Extracts public IPs from the alert JSON and queries MISP.
- `process_misp_info(misp_info)`: Processes the MISP response and excludes certain IPs if necessary.
- `send_event(msg)`: Sends processed data to the Wazuh socket.
# Error Handling:

Logs errors and exits on failure to parse input JSON or communicate with MISP.
Dependencies:

Requires requests library. Install it via pip install requests.
# Usage
Run the script with:

## bash
copy code <br>
python script_name.py path_to_alerts.json api_key
Example: <br>
**python3 misp_integration.py /tmp/alerts.json YOUR_API_KEY**
## Logs 
Logs are stored in: **/var/ossec/logs/debug.log** <br>
Enable or disable debugging by modifying debug_enabled variable.

## Requirements
- Python 3.x
- requests module
- Access to MISP API
- Wazuh installed and configured
