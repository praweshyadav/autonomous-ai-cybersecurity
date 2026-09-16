import uuid
from datetime import datetime, timezone

import pytest

from correlation.schema import Incident, SecurityEvent
from persistence.incident_repository import IncidentRepository


DATABASE_URL = "postgresql://cybersecurity:cybersecurity_dev_password@localhost:5432/cybersecurity"


def create_incident():
    event_time = datetime.now(timezone.utc)

    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=event_time,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=54321,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.91,
        source_file="test.csv",
        event_type="network_flow",
    )

    return Incident(
        incident_id=str(uuid.uuid4()),
        events=[event],
        start_time=event_time,
        end_time=event_time,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force", "DoS"],
        family_distribution={
            "Brute Force": 8,
            "DoS": 2,
        },
        confidence=0.91,
        src_ips=["192.168.1.10", "192.168.1.11"],
        dst_ips=["10.0.0.5"],
        dst_ports=[22, 80],
        protocols=[6],
    )


@pytest.fixture
def repository():
    repo = IncidentRepository(DATABASE_URL)

    # Keep repository tests isolated.
    with repo._connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM incidents")

    yield repo

    with repo._connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM incidents")


def test_repository_initializes():
    repository = IncidentRepository(DATABASE_URL)
    assert repository is not None


def test_save_and_get_by_id(repository):
    incident = create_incident()

    repository.save(incident)

    loaded = repository.get_by_id(incident.incident_id)

    assert loaded is not None
    assert loaded.incident_id == incident.incident_id
    assert loaded.start_time == incident.start_time
    assert loaded.end_time == incident.end_time
    assert loaded.severity == incident.severity
    assert loaded.primary_attack_family == incident.primary_attack_family
    assert loaded.confidence == incident.confidence
    assert loaded.src_ips == incident.src_ips
    assert loaded.dst_ips == incident.dst_ips
    assert loaded.dst_ports == incident.dst_ports
    assert loaded.protocols == incident.protocols
    assert loaded.family_distribution == incident.family_distribution


def test_get_by_id_missing_incident(repository):
    result = repository.get_by_id(str(uuid.uuid4()))

    assert result is None


def test_save_updates_existing_incident(repository):
    incident = create_incident()

    repository.save(incident)

    incident.severity = "critical"
    incident.confidence = 0.99

    repository.save(incident)

    loaded = repository.get_by_id(incident.incident_id)

    assert loaded is not None
    assert loaded.severity == "critical"
    assert loaded.confidence == 0.99


def test_save_batch(repository):
    incidents = [
        create_incident()
        for _ in range(3)
    ]

    repository.save_batch(incidents)

    assert repository.count() == 3

    for incident in incidents:
        assert repository.get_by_id(incident.incident_id) is not None


def test_save_batch_empty(repository):
    repository.save_batch([])

    assert repository.count() == 0


def test_list_recent(repository):
    incidents = [
        create_incident()
        for _ in range(3)
    ]

    repository.save_batch(incidents)

    results = repository.list_recent(limit=2)

    assert len(results) == 2


def test_count(repository):
    assert repository.count() == 0

    repository.save(create_incident())

    assert repository.count() == 1

    repository.save(create_incident())

    assert repository.count() == 2


def test_delete(repository):
    incident = create_incident()

    repository.save(incident)

    assert repository.get_by_id(incident.incident_id) is not None

    deleted = repository.delete(incident.incident_id)

    assert deleted is True
    assert repository.get_by_id(incident.incident_id) is None


def test_delete_missing_incident(repository):
    deleted = repository.delete(str(uuid.uuid4()))

    assert deleted is False


def test_invalid_database_url():
    with pytest.raises((ValueError, TypeError)):
        IncidentRepository("")


def test_invalid_database_url_type():
    with pytest.raises((ValueError, TypeError)):
        IncidentRepository(None)


def test_save_invalid_incident(repository):
    with pytest.raises((ValueError, TypeError)):
        repository.save(None)


def test_save_batch_invalid_input(repository):
    with pytest.raises((ValueError, TypeError)):
        repository.save_batch(None)


def test_save_batch_invalid_item(repository):
    with pytest.raises((ValueError, TypeError)):
        repository.save_batch([None])


def test_list_recent_invalid_limit(repository):
    with pytest.raises((ValueError, TypeError)):
        repository.list_recent(limit=0)

    with pytest.raises((ValueError, TypeError)):
        repository.list_recent(limit=-1)


def test_get_by_id_invalid_type(repository):
    with pytest.raises((ValueError, TypeError)):
        repository.get_by_id(None)


def test_delete_invalid_type(repository):
    with pytest.raises((ValueError, TypeError)):
        repository.delete(None)
