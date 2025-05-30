    Alert Ingestion & IP Gleaning:

        It kicks off when Wazuh feeds it an alert, typically as a JSON file (think active response).

        The script first sanity-checks if it's a legit Wazuh alert it cares about (e.g., based on rule ID or level).

        Then, it regex-parses the entire alert payload to sniff out any public IP addresses. It's not just grabbing IPs; it tries to figure out their direction (source/destination) and field_path (where in the alert JSON it found the IP) for context.

    Deduplication Fu (Alert-Level):

        To avoid hammering MISP or creating alert storms in Wazuh, it maintains a local JSON file (recent_misp_logs.json) as a poor man's state cache.

        It generates a unique key for an alert-IP combo (e.g., rule_id:ip:direction). If this combo has been processed within a defined deduplication_window (e.g., 1 hour), it bails out for that specific IP in that specific alert context.

    MISP API Hustle:

        For each unique, non-deduplicated public IP, it fires off API calls to the configured MISP instance using the /attributes/restSearch endpoint.

        It queries for both ip-src and ip-dst types (or just one if the direction was confidently determined earlier). The API key is, of course, a must-have.

    JSON Munging & Intel Distillation:

        If MISP coughs up some data (a JSON response), the script gets down to data wrangling:

            It iterates through the returned MISP attributes.

            It extracts key intel: attribute type, value, category, to_ids flag, tags (both attribute-level and event-level), related attributes, and sighting information.

            It calculates a custom threat_score based on attribute category, tags (giving more weight to things like "malware," "apt," TLP levels), and the to_ids flag.

            It also pulls out details of the MISP events associated with these attributes (ID, info, date, org).

    Smart Aggregation (The Noise Reduction Bit):

        This is a key improvement: Instead of just dumping every single MISP attribute found (which can be super repetitive if the same IP is in many MISP events with similar flagging), it intelligently aggregates them.

        It creates an "aggregation key" based on the core characteristics of an attribute (type, value, category, to_ids, calculated threat_score, tags, related attributes, and sightings).

        Attributes sharing the same aggregation key are rolled up. The final enriched log will contain one representative entry for this group, but with a list of all associated_misp_event_ids and attribute_timestamps it originally came from. This drastically cuts down on log verbosity.

    Crafting the Enriched Event:

        The script constructs a new, beefed-up JSON payload. This "enriched event" includes:

            An integration: "misp" marker.

            A unique event_id for this enriched log entry (MD5 hash).

            A timestamp for when the enrichment happened.

            The detected_ip details (value, direction, where it was found).

            The misp_data block, now containing:

                attributes: The list of aggregated MISP attribute objects.

                events: A list of unique MISP event details encountered.

                summary: A neat summary including total (aggregated) attributes, total unique MISP events, earliest/latest MISP event dates, unique threat types observed, attribution (if any), and the max threat_score.

            Crucially, it flattens and re-embeds a lot of the original Wazuh alert's context (rule details, agent info, manager, location, decoder, and fields from the original alert's data section).

            It also tacks on some recommendations (e.g., "Block this IP," "Monitor closely") based on the calculated max_threat_score.

    Feeding Back to Wazuh:

        Finally, this enriched JSON event is injected back into the Wazuh manager via a Unix domain socket (/var/ossec/queue/sockets/queue).

        This allows Wazuh to process this new, context-rich event, potentially triggering further rules, alerts, or visualizations.
