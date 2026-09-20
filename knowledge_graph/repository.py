from __future__ import annotations

import json
from typing import Any

from correlation.schema import Incident, SecurityEvent
from knowledge_graph.client import Neo4jClient


class Neo4jGraphRepository:
    """
    Repository for storing cybersecurity incidents, security events,
    and their graph relationships in Neo4j.

    Graph model:

        (:Incident)-[:CONTAINS]->(:SecurityEvent)

        (:SecurityEvent)-[:ORIGINATES_FROM]->(:IP)
        (:SecurityEvent)-[:TARGETS]->(:IP)

        (:SecurityEvent)-[:USES_SOURCE_PORT]->(:Port)
        (:SecurityEvent)-[:USES_DESTINATION_PORT]->(:Port)

        (:SecurityEvent)-[:USES_PROTOCOL]->(:Protocol)
    """

    def __init__(self, client: Neo4jClient | None = None) -> None:
        self.client = client if client is not None else Neo4jClient()

    def create_incident(self, incident: Incident) -> None:
        """Create or update an Incident node."""

        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident.")

        if incident.start_time is None:
            raise ValueError("incident.start_time cannot be None.")

        if incident.end_time is None:
            raise ValueError("incident.end_time cannot be None.")

        query = """
        MERGE (i:Incident {incident_id: $incident_id})
        SET
            i.start_time = $start_time,
            i.end_time = $end_time,
            i.severity = $severity,
            i.primary_family = $primary_family,
            i.confidence = $confidence,
            i.event_count = $event_count,
            i.source_ips = $source_ips,
            i.destination_ips = $destination_ips,
            i.destination_ports = $destination_ports,
            i.protocols = $protocols,
            i.family_distribution = $family_distribution
        """

        parameters = {
            "incident_id": incident.incident_id,
            "start_time": incident.start_time.isoformat(),
            "end_time": incident.end_time.isoformat(),
            "severity": incident.severity,
            "primary_family": incident.primary_attack_family,
            "confidence": float(incident.confidence),
            "event_count": len(incident.events),
            "source_ips": list(incident.src_ips),
            "destination_ips": list(incident.dst_ips),
            "destination_ports": list(incident.dst_ports),
            "protocols": list(incident.protocols),
            "family_distribution": json.dumps(
                incident.family_distribution,
                sort_keys=True,
            ),
        }

        self.client.execute(query, parameters)

    def create_event(self, event: SecurityEvent) -> None:
        """Create or update a SecurityEvent node."""

        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")

        query = """
        MERGE (e:SecurityEvent {event_id: $event_id})
        SET
            e.timestamp = $timestamp,
            e.src_ip = $src_ip,
            e.dst_ip = $dst_ip,
            e.src_port = $src_port,
            e.dst_port = $dst_port,
            e.protocol = $protocol,
            e.protocol_name = $protocol_name,
            e.binary_prediction = $binary_prediction,
            e.attack_family = $attack_family,
            e.confidence = $confidence,
            e.source_file = $source_file,
            e.true_label = $true_label,
            e.true_attack_family = $true_attack_family,
            e.event_type = $event_type,
            e.windows_event_id = $windows_event_id,
            e.username = $username,
            e.domain = $domain,
            e.process_name = $process_name,
            e.firewall_action = $firewall_action,
            e.raw_log = $raw_log
        """

        parameters = {
            "event_id": str(event.event_id),
            "timestamp": event.timestamp.isoformat(),
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "protocol_name": event.protocol_name,
            "binary_prediction": int(event.binary_prediction),
            "attack_family": event.attack_family,
            "confidence": float(event.confidence),
            "source_file": event.source_file,
            "true_label": event.true_label,
            "true_attack_family": event.true_attack_family,
            "event_type": event.event_type,
            "windows_event_id": event.windows_event_id,
            "username": event.username,
            "domain": event.domain,
            "process_name": event.process_name,
            "firewall_action": event.firewall_action,
            "raw_log": event.raw_log,
        }

        self.client.execute(query, parameters)

    def create_ip_node(self, ip_address: str) -> None:
        """Create or reuse an IP node."""

        if not isinstance(ip_address, str):
            raise TypeError("ip_address must be a string.")

        if not ip_address.strip():
            raise ValueError("ip_address cannot be empty.")

        query = """
        MERGE (ip:IP {address: $address})
        """

        self.client.execute(
            query,
            {"address": ip_address.strip()},
        )

    def link_event_to_source_ip(self, event: SecurityEvent) -> None:
        """Create (:SecurityEvent)-[:ORIGINATES_FROM]->(:IP)."""

        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")

        if event.src_ip is None or not event.src_ip.strip():
            return

        self.create_ip_node(event.src_ip)

        query = """
        MATCH (e:SecurityEvent {event_id: $event_id})
        MATCH (ip:IP {address: $ip_address})
        MERGE (e)-[:ORIGINATES_FROM]->(ip)
        """

        self.client.execute(
            query,
            {
                "event_id": str(event.event_id),
                "ip_address": event.src_ip.strip(),
            },
        )

    def link_event_to_destination_ip(self, event: SecurityEvent) -> None:
        """Create (:SecurityEvent)-[:TARGETS]->(:IP)."""

        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")

        if event.dst_ip is None or not event.dst_ip.strip():
            return

        self.create_ip_node(event.dst_ip)

        query = """
        MATCH (e:SecurityEvent {event_id: $event_id})
        MATCH (ip:IP {address: $ip_address})
        MERGE (e)-[:TARGETS]->(ip)
        """

        self.client.execute(
            query,
            {
                "event_id": str(event.event_id),
                "ip_address": event.dst_ip.strip(),
            },
        )

    def create_port_node(self, port: int) -> None:
        """Create or reuse a Port node."""

        if isinstance(port, bool) or not isinstance(port, int):
            raise TypeError("port must be an integer.")

        if port < 0 or port > 65535:
            raise ValueError("port must be between 0 and 65535.")

        query = """
        MERGE (p:Port {number: $port})
        """

        self.client.execute(
            query,
            {"port": port},
        )

    def link_event_to_source_port(self, event: SecurityEvent) -> None:
        """Create (:SecurityEvent)-[:USES_SOURCE_PORT]->(:Port)."""

        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")

        if event.src_port is None:
            return

        self.create_port_node(event.src_port)

        query = """
        MATCH (e:SecurityEvent {event_id: $event_id})
        MATCH (p:Port {number: $port})
        MERGE (e)-[:USES_SOURCE_PORT]->(p)
        """

        self.client.execute(
            query,
            {
                "event_id": str(event.event_id),
                "port": event.src_port,
            },
        )

    def link_event_to_destination_port(self, event: SecurityEvent) -> None:
        """Create (:SecurityEvent)-[:USES_DESTINATION_PORT]->(:Port)."""

        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")

        if event.dst_port is None:
            return

        self.create_port_node(event.dst_port)

        query = """
        MATCH (e:SecurityEvent {event_id: $event_id})
        MATCH (p:Port {number: $port})
        MERGE (e)-[:USES_DESTINATION_PORT]->(p)
        """

        self.client.execute(
            query,
            {
                "event_id": str(event.event_id),
                "port": event.dst_port,
            },
        )

    def create_protocol_node(
        self,
        protocol: int,
        protocol_name: str | None = None,
    ) -> None:
        """Create or update a Protocol node."""

        if isinstance(protocol, bool) or not isinstance(protocol, int):
            raise TypeError("protocol must be an integer.")

        if protocol < 0:
            raise ValueError("protocol must be non-negative.")

        if protocol_name is not None and not isinstance(protocol_name, str):
            raise TypeError("protocol_name must be a string or None.")

        query = """
        MERGE (p:Protocol {number: $protocol})
        SET p.name = $protocol_name
        """

        self.client.execute(
            query,
            {
                "protocol": protocol,
                "protocol_name": protocol_name,
            },
        )

    def link_event_to_protocol(self, event: SecurityEvent) -> None:
        """Create (:SecurityEvent)-[:USES_PROTOCOL]->(:Protocol)."""

        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")

        if event.protocol is None:
            return

        self.create_protocol_node(
            event.protocol,
            event.protocol_name,
        )

        query = """
        MATCH (e:SecurityEvent {event_id: $event_id})
        MATCH (p:Protocol {number: $protocol})
        MERGE (e)-[:USES_PROTOCOL]->(p)
        """

        self.client.execute(
            query,
            {
                "event_id": str(event.event_id),
                "protocol": event.protocol,
            },
        )

    def link_event_to_incident(
        self,
        incident: Incident,
        event: SecurityEvent,
    ) -> None:
        """Create (:Incident)-[:CONTAINS]->(:SecurityEvent)."""

        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident.")

        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent.")

        query = """
        MATCH (i:Incident {incident_id: $incident_id})
        MATCH (e:SecurityEvent {event_id: $event_id})
        MERGE (i)-[:CONTAINS]->(e)
        """

        self.client.execute(
            query,
            {
                "incident_id": incident.incident_id,
                "event_id": str(event.event_id),
            },
        )

    def save_incident(self, incident: Incident) -> None:
        """
        Persist an incident, its events, and graph relationships.
        """

        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident.")

        self.create_incident(incident)

        for event in incident.events:
            self.create_event(event)
            self.link_event_to_incident(incident, event)
            self.link_event_to_source_ip(event)
            self.link_event_to_destination_ip(event)
            self.link_event_to_source_port(event)
            self.link_event_to_destination_port(event)
            self.link_event_to_protocol(event)

    def get_incident(
        self,
        incident_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve an incident and its contained events."""

        if not isinstance(incident_id, str):
            raise TypeError("incident_id must be a string.")

        if not incident_id.strip():
            raise ValueError("incident_id cannot be empty.")

        query = """
        MATCH (i:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (i)-[:CONTAINS]->(e:SecurityEvent)
        RETURN
            i AS incident,
            collect(e) AS events
        """

        rows = self.client.execute(
            query,
            {"incident_id": incident_id},
        )

        if not rows:
            return None

        row = rows[0]
        incident_data = dict(row["incident"])

        events = []

        for event_node in row["events"]:
            if event_node is not None:
                events.append(dict(event_node))

        incident_data["events"] = events

        return incident_data

    def delete_incident(self, incident_id: str) -> None:
        """
        Delete an incident, its contained events, and orphaned
        IP, Port, and Protocol nodes.
        """

        if not isinstance(incident_id, str):
            raise TypeError("incident_id must be a string.")

        if not incident_id.strip():
            raise ValueError("incident_id cannot be empty.")

        query = """
        MATCH (i:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (i)-[:CONTAINS]->(e:SecurityEvent)
        OPTIONAL MATCH (e)-[:ORIGINATES_FROM|TARGETS]->(ip:IP)
        OPTIONAL MATCH (e)-[:USES_SOURCE_PORT|USES_DESTINATION_PORT]->(port:Port)
        OPTIONAL MATCH (e)-[:USES_PROTOCOL]->(protocol:Protocol)

        WITH
            i,
            collect(DISTINCT e) AS events,
            collect(DISTINCT ip) AS ips,
            collect(DISTINCT port) AS ports,
            collect(DISTINCT protocol) AS protocols

        FOREACH (event IN events | DETACH DELETE event)
        DETACH DELETE i

        WITH ips, ports, protocols

        UNWIND ips AS ip
        WITH ip, ports, protocols
        WHERE ip IS NOT NULL AND NOT (ip)--()
        DELETE ip

        WITH ports, protocols
        UNWIND ports AS port
        WITH port, protocols
        WHERE port IS NOT NULL AND NOT (port)--()
        DELETE port

        WITH protocols
        UNWIND protocols AS protocol
        WITH protocol
        WHERE protocol IS NOT NULL AND NOT (protocol)--()
        DELETE protocol
        """

        self.client.execute(
            query,
            {"incident_id": incident_id},
        )

    def close(self) -> None:
        """Close the underlying Neo4j client."""

        self.client.close()
