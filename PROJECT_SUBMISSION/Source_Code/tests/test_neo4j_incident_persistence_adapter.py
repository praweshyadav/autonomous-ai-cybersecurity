from datetime import datetime, timezone

import pytest

from correlation.schema import Incident, SecurityEvent
from knowledge_graph.client import Neo4jClient
from knowledge_graph.repository import Neo4jGraphRepository
from persistence.neo4j_incident_persistence_adapter import (
    Neo4jIncidentPersistenceAdapter,
)


TEST_INCIDENT_ID = "INC-NEO4J-ADAPTER-000001"
TEST_EVENT_ID = "NEO4J-ADAPTER-EVENT-000001"
TEST_INCIDENT_ID_2 = "INC-NEO4J-ADAPTER-000002"
TEST_EVENT_ID_2 = "NEO4J-ADAPTER-EVENT-000002"


def create_test_event(
    event_id: str = TEST_EVENT_ID,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(
            2026,
            9,
            16,
            12,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        src_ip="10.20.0.10",
        dst_ip="10.20.0.20",
        src_port=49152,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.95,
        event_type="network_flow",
    )


def create_test_incident(
    incident_id: str = TEST_INCIDENT_ID,
    event_id: str = TEST_EVENT_ID,
) -> Incident:
    event = create_test_event(event_id)

    incident = Incident(
        incident_id=incident_id,
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
    repository.delete_incident(TEST_INCIDENT_ID_2)

    yield repository

    repository.delete_incident(TEST_INCIDENT_ID)
    repository.delete_incident(TEST_INCIDENT_ID_2)
    repository.close()


@pytest.fixture
def adapter(repository):
    return Neo4jIncidentPersistenceAdapter(repository)


def test_process_persists_incident(adapter, repository):
    incident = create_test_incident()

    adapter.process(incident)

    result = repository.get_incident(TEST_INCIDENT_ID)

    assert result is not None
    assert result["incident_id"] == TEST_INCIDENT_ID
    assert result["severity"] == "high"
    assert len(result["events"]) == 1


def test_call_persists_incident(adapter, repository):
    incident = create_test_incident()

    adapter(incident)

    result = repository.get_incident(TEST_INCIDENT_ID)

    assert result is not None
    assert result["incident_id"] == TEST_INCIDENT_ID


def test_process_creates_complete_graph(adapter, repository):
    incident = create_test_incident()

    adapter.process(incident)

    rows = repository.client.execute(
        """
        MATCH (i:Incident {incident_id: $incident_id})
              -[:CONTAINS]->
              (e:SecurityEvent {event_id: $event_id})
        MATCH (e)-[:ORIGINATES_FROM]->
              (source:IP {address: $source_ip})
        MATCH (e)-[:TARGETS]->
              (destination:IP {address: $destination_ip})
        MATCH (e)-[:USES_SOURCE_PORT]->
              (source_port:Port {number: $source_port})
        MATCH (e)-[:USES_DESTINATION_PORT]->
              (destination_port:Port {number: $destination_port})
        MATCH (e)-[:USES_PROTOCOL]->
              (protocol:Protocol {number: $protocol})
        RETURN count(*) AS count
        """,
        {
            "incident_id": TEST_INCIDENT_ID,
            "event_id": TEST_EVENT_ID,
            "source_ip": "10.20.0.10",
            "destination_ip": "10.20.0.20",
            "source_port": 49152,
            "destination_port": 22,
            "protocol": 6,
        },
    )

    assert rows[0]["count"] == 1


def test_process_is_idempotent(adapter, repository):
    incident = create_test_incident()

    adapter.process(incident)
    adapter.process(incident)

    rows = repository.client.execute(
        """
        MATCH (i:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (i)-[:CONTAINS]->(e:SecurityEvent)
        OPTIONAL MATCH (e)-[:USES_SOURCE_PORT]->(source_port:Port)
        OPTIONAL MATCH (e)-[:USES_DESTINATION_PORT]->(destination_port:Port)
        OPTIONAL MATCH (e)-[:USES_PROTOCOL]->(protocol:Protocol)
        RETURN
            count(DISTINCT i) AS incidents,
            count(DISTINCT e) AS events,
            count(DISTINCT source_port) AS source_ports,
            count(DISTINCT destination_port) AS destination_ports,
            count(DISTINCT protocol) AS protocols
        """,
        {"incident_id": TEST_INCIDENT_ID},
    )

    assert rows[0]["incidents"] == 1
    assert rows[0]["events"] == 1
    assert rows[0]["source_ports"] == 1
    assert rows[0]["destination_ports"] == 1
    assert rows[0]["protocols"] == 1


def test_process_batch_persists_multiple_incidents(
    adapter,
    repository,
):
    incident_one = create_test_incident(
        incident_id=TEST_INCIDENT_ID,
        event_id=TEST_EVENT_ID,
    )

    incident_two = create_test_incident(
        incident_id=TEST_INCIDENT_ID_2,
        event_id=TEST_EVENT_ID_2,
    )

    result = adapter.process_batch(
        [incident_one, incident_two]
    )

    assert result == [None, None]

    assert (
        repository.get_incident(TEST_INCIDENT_ID)
        is not None
    )

    assert (
        repository.get_incident(TEST_INCIDENT_ID_2)
        is not None
    )


def test_invalid_incident(adapter):
    with pytest.raises(
        TypeError,
        match="incident must be an Incident",
    ):
        adapter.process(None)


def test_invalid_batch_type(adapter):
    with pytest.raises(
        TypeError,
        match="incidents must be a list",
    ):
        adapter.process_batch(None)


def test_invalid_batch_item(adapter):
    with pytest.raises(
        TypeError,
        match="all items in incidents must be Incident objects",
    ):
        adapter.process_batch([None])


def test_empty_batch(adapter):
    result = adapter.process_batch([])

    assert result == []


def test_close():
    client = Neo4jClient()
    repository = Neo4jGraphRepository(client)

    try:
        repository.delete_incident(TEST_INCIDENT_ID)

        adapter = Neo4jIncidentPersistenceAdapter(repository)

        adapter.close()

        with pytest.raises(Exception):
            repository.get_incident(TEST_INCIDENT_ID)

    finally:
        # The adapter already closed the repository/client.
        # Nothing else should attempt to use the closed driver.
        pass
