from datetime import datetime, timedelta, timezone

from correlation.incident_window import IncidentWindow
from correlation.correlator import IncidentCorrelator
from correlation.incident_manager import IncidentManager
from correlation.schema import SecurityEvent

from persistence.incident_persistence_adapter import (
    IncidentPersistenceAdapter,
)
from persistence.neo4j_incident_persistence_adapter import (
    Neo4jIncidentPersistenceAdapter,
)
from persistence.incident_persistence_service import (
    IncidentPersistenceService,
)
from persistence.combined_incident_persistence_adapter import (
    CombinedIncidentPersistenceAdapter,
)
from persistence.incident_repository import IncidentRepository

from knowledge_graph.client import Neo4jClient
from knowledge_graph.repository import Neo4jGraphRepository


DATABASE_URL = (
    "postgresql://cybersecurity:"
    "cybersecurity_dev_password@localhost:5432/"
    "cybersecurity"
)


def make_event(event_id, timestamp):
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_ip="10.10.10.10",
        dst_ip="192.168.1.10",
        src_port=4444,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.95,
    )


def test_incident_manager_persists_to_postgres_and_neo4j():
    postgres_service = IncidentPersistenceService(
        database_url=DATABASE_URL
    )

    postgres_adapter = IncidentPersistenceAdapter(
        persistence_service=postgres_service
    )

    postgres_repository = IncidentRepository(
        database_url=DATABASE_URL
    )

    neo4j_client = Neo4jClient()

    neo4j_repository = Neo4jGraphRepository(
        client=neo4j_client
    )

    neo4j_adapter = Neo4jIncidentPersistenceAdapter(
        repository=neo4j_repository
    )

    combined_adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres_adapter,
        neo4j_adapter=neo4j_adapter,
    )

    window = IncidentWindow(
        window_seconds=60
    )

    correlator = IncidentCorrelator(
        time_window_seconds=60,
        correlation_threshold=4,
    )

    manager = IncidentManager(
        window=window,
        correlator=correlator,
        persistence_adapter=combined_adapter,
    )

    timestamp = datetime.now(timezone.utc)

    events = [
        make_event(
            "11111111-1111-4111-8111-111111111111",
            timestamp,
        ),
        make_event(
            "22222222-2222-4222-8222-222222222222",
            timestamp + timedelta(seconds=1),
        ),
        make_event(
            "33333333-3333-4333-8333-333333333333",
            timestamp + timedelta(seconds=2),
        ),
        make_event(
            "44444444-4444-4444-8444-444444444444",
            timestamp + timedelta(seconds=3),
        ),
    ]

    incident = None

    try:
        for event in events:
            manager.process_event(event)

        incidents = manager.flush()

        assert len(incidents) == 1

        incident = incidents[0]

        assert incident.incident_id.startswith("INC-")
        assert len(incident.events) == 4

        # ---------------------------------------------------------
        # Verify PostgreSQL persistence.
        # ---------------------------------------------------------
        postgres_incident = postgres_repository.get_by_id(
            incident.incident_id
        )

        assert postgres_incident is not None
        assert postgres_incident.incident_id == incident.incident_id
        assert postgres_incident.start_time is not None
        assert postgres_incident.end_time is not None
        assert postgres_incident.severity == incident.severity
        assert postgres_incident.primary_attack_family == (
            incident.primary_attack_family
        )
        assert postgres_incident.confidence == incident.confidence

        # ---------------------------------------------------------
        # Verify Neo4j incident node.
        # ---------------------------------------------------------
        neo4j_incident = neo4j_repository.get_incident(
            incident.incident_id
        )

        assert neo4j_incident is not None
        assert neo4j_incident["incident_id"] == incident.incident_id

        # ---------------------------------------------------------
        # Verify Neo4j event relationships directly.
        #
        # The repository does not expose get_incident_events(),
        # so use the existing Neo4j client interface.
        # ---------------------------------------------------------
        event_relationships = neo4j_client.execute(
            """
            MATCH (i:Incident {incident_id: $incident_id})
                  -[:CONTAINS]->(e:SecurityEvent)
            RETURN e.event_id AS event_id
            ORDER BY e.event_id
            """,
            {
                "incident_id": incident.incident_id
            },
        )

        persisted_event_ids = {
            row["event_id"]
            for row in event_relationships
        }

        expected_event_ids = {
            event.event_id
            for event in events
        }

        assert persisted_event_ids == expected_event_ids
        assert len(persisted_event_ids) == 4

    finally:
        if incident is not None:
            postgres_repository.delete(
                incident.incident_id
            )

            neo4j_repository.delete_incident(
                incident.incident_id
            )

        combined_adapter.close()
