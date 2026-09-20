from datetime import datetime, timezone

import pytest

from correlation.schema import Incident, SecurityEvent
from knowledge_graph.client import Neo4jClient
from knowledge_graph.repository import Neo4jGraphRepository


TEST_INCIDENT_ID = "INC-KG-TEST-000001"
TEST_EVENT_ID = "KG-EVENT-000001"


def create_test_event() -> SecurityEvent:
    return SecurityEvent(
        event_id=TEST_EVENT_ID,
        timestamp=datetime(
            2026,
            9,
            16,
            12,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=49152,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.95,
        event_type="network_flow",
    )


def create_test_incident() -> Incident:
    event = create_test_event()

    incident = Incident(
        incident_id=TEST_INCIDENT_ID,
        severity="high",
        primary_attack_family="Brute Force",
        confidence=0.95,
    )

    incident.add_event(event)

    return incident


@pytest.fixture
def repository():
    client = Neo4jClient()
    repository = Neo4jGraphRepository(client)

    repository.delete_incident(TEST_INCIDENT_ID)

    yield repository

    repository.delete_incident(TEST_INCIDENT_ID)
    repository.close()


def test_create_incident(repository):
    incident = create_test_incident()

    repository.create_incident(incident)

    result = repository.get_incident(TEST_INCIDENT_ID)

    assert result is not None
    assert result["incident_id"] == TEST_INCIDENT_ID
    assert result["severity"] == "high"
    assert result["primary_family"] == "Brute Force"
    assert result["event_count"] == 1


def test_create_event(repository):
    event = create_test_event()

    repository.create_event(event)

    rows = repository.client.execute(
        """
        MATCH (e:SecurityEvent {event_id: $event_id})
        RETURN e
        """,
        {"event_id": TEST_EVENT_ID},
    )

    assert len(rows) == 1

    event_data = dict(rows[0]["e"])

    assert event_data["event_id"] == TEST_EVENT_ID
    assert event_data["src_ip"] == "10.0.0.10"
    assert event_data["dst_ip"] == "10.0.0.20"
    assert event_data["attack_family"] == "Brute Force"


def test_create_ip_node(repository):
    repository.create_ip_node("10.0.0.10")

    rows = repository.client.execute(
        """
        MATCH (ip:IP {address: $address})
        RETURN count(ip) AS count
        """,
        {"address": "10.0.0.10"},
    )

    assert rows[0]["count"] == 1


def test_create_ip_node_is_idempotent(repository):
    repository.create_ip_node("10.0.0.10")
    repository.create_ip_node("10.0.0.10")

    rows = repository.client.execute(
        """
        MATCH (ip:IP {address: $address})
        RETURN count(ip) AS count
        """,
        {"address": "10.0.0.10"},
    )

    assert rows[0]["count"] == 1


def test_link_event_to_source_ip(repository):
    event = create_test_event()

    repository.create_event(event)
    repository.link_event_to_source_ip(event)

    rows = repository.client.execute(
        """
        MATCH (e:SecurityEvent {event_id: $event_id})
              -[:ORIGINATES_FROM]->
              (ip:IP {address: $ip_address})
        RETURN count(*) AS count
        """,
        {
            "event_id": TEST_EVENT_ID,
            "ip_address": "10.0.0.10",
        },
    )

    assert rows[0]["count"] == 1


def test_link_event_to_destination_ip(repository):
    event = create_test_event()

    repository.create_event(event)
    repository.link_event_to_destination_ip(event)

    rows = repository.client.execute(
        """
        MATCH (e:SecurityEvent {event_id: $event_id})
              -[:TARGETS]->
              (ip:IP {address: $ip_address})
        RETURN count(*) AS count
        """,
        {
            "event_id": TEST_EVENT_ID,
            "ip_address": "10.0.0.20",
        },
    )

    assert rows[0]["count"] == 1


def test_link_event_to_incident(repository):
    incident = create_test_incident()
    event = create_test_event()

    repository.create_incident(incident)
    repository.create_event(event)
    repository.link_event_to_incident(incident, event)

    rows = repository.client.execute(
        """
        MATCH (i:Incident {incident_id: $incident_id})
              -[:CONTAINS]->
              (e:SecurityEvent {event_id: $event_id})
        RETURN count(*) AS relationship_count
        """,
        {
            "incident_id": TEST_INCIDENT_ID,
            "event_id": TEST_EVENT_ID,
        },
    )

    assert rows[0]["relationship_count"] == 1


def test_save_incident_creates_complete_graph(repository):
    incident = create_test_incident()

    repository.save_incident(incident)

    rows = repository.client.execute(
        """
        MATCH (i:Incident {incident_id: $incident_id})
              -[:CONTAINS]->
              (e:SecurityEvent {event_id: $event_id})
              -[:ORIGINATES_FROM]->
              (source:IP {address: $source_ip})
        MATCH (e)-[:TARGETS]->
              (destination:IP {address: $destination_ip})
        RETURN count(*) AS count
        """,
        {
            "incident_id": TEST_INCIDENT_ID,
            "event_id": TEST_EVENT_ID,
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.20",
        },
    )

    assert rows[0]["count"] == 1


def test_save_incident_is_idempotent(repository):
    incident = create_test_incident()

    repository.save_incident(incident)
    repository.save_incident(incident)

    rows = repository.client.execute(
        """
        MATCH (i:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (i)-[:CONTAINS]->(e:SecurityEvent)
        OPTIONAL MATCH (e)-[:ORIGINATES_FROM]->(source:IP)
        OPTIONAL MATCH (e)-[:TARGETS]->(destination:IP)
        RETURN
            count(DISTINCT i) AS incident_count,
            count(DISTINCT e) AS event_count,
            count(DISTINCT source) AS source_ip_count,
            count(DISTINCT destination) AS destination_ip_count
        """,
        {"incident_id": TEST_INCIDENT_ID},
    )

    assert rows[0]["incident_count"] == 1
    assert rows[0]["event_count"] == 1
    assert rows[0]["source_ip_count"] == 1
    assert rows[0]["destination_ip_count"] == 1


def test_get_missing_incident(repository):
    result = repository.get_incident(
        "INC-KG-DOES-NOT-EXIST"
    )

    assert result is None


def test_delete_incident(repository):
    incident = create_test_incident()

    repository.save_incident(incident)

    assert repository.get_incident(TEST_INCIDENT_ID) is not None

    repository.delete_incident(TEST_INCIDENT_ID)

    assert repository.get_incident(TEST_INCIDENT_ID) is None

    rows = repository.client.execute(
        """
        MATCH (e:SecurityEvent {event_id: $event_id})
        RETURN count(e) AS event_count
        """,
        {"event_id": TEST_EVENT_ID},
    )

    assert rows[0]["event_count"] == 0


def test_invalid_incident_type(repository):
    with pytest.raises(
        TypeError,
        match="incident must be an Incident",
    ):
        repository.create_incident(None)


def test_invalid_event_type(repository):
    with pytest.raises(
        TypeError,
        match="event must be a SecurityEvent",
    ):
        repository.create_event(None)


def test_invalid_ip_type(repository):
    with pytest.raises(
        TypeError,
        match="ip_address must be a string",
    ):
        repository.create_ip_node(None)


def test_invalid_ip_value(repository):
    with pytest.raises(
        ValueError,
        match="ip_address cannot be empty",
    ):
        repository.create_ip_node("")


def test_invalid_incident_id(repository):
    with pytest.raises(
        ValueError,
        match="incident_id cannot be empty",
    ):
        repository.get_incident("")


def test_invalid_incident_id_type(repository):
    with pytest.raises(
        TypeError,
        match="incident_id must be a string",
    ):
        repository.get_incident(None)
