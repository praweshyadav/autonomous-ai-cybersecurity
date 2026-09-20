from correlation.schema import Incident, SecurityEvent
from persistence.combined_incident_persistence_adapter import (
    CombinedIncidentPersistenceAdapter,
)


class FakePersistenceAdapter:
    def __init__(self):
        self.calls = []
        self.closed = False

    def process_batch(self, incidents):
        self.calls.append(list(incidents))
        return [None] * len(incidents)

    def close(self):
        self.closed = True


def make_incident(incident_id="INC-000001"):
    event = SecurityEvent(
        event_id="evt-001",
        timestamp=__import__("datetime").datetime.now(),
        attack_family="Brute Force",
        binary_prediction=1,
        confidence=0.95,
    )

    return Incident(
        incident_id=incident_id,
        events=[event],
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 1},
        confidence=0.95,
        severity="high",
    )


def test_process_batch_sends_incidents_to_both_adapters():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    incident = make_incident()

    result = adapter.process_batch([incident])

    assert result == [None]
    assert postgres.calls == [[incident]]
    assert neo4j.calls == [[incident]]


def test_process_sends_single_incident_to_both():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    incident = make_incident()

    result = adapter.process(incident)

    assert result is None
    assert postgres.calls == [[incident]]
    assert neo4j.calls == [[incident]]


def test_call_operator_works():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    incident = make_incident()

    adapter(incident)

    assert postgres.calls == [[incident]]
    assert neo4j.calls == [[incident]]


def test_multiple_incidents_are_sent_to_both():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    incidents = [
        make_incident("INC-000001"),
        make_incident("INC-000002"),
        make_incident("INC-000003"),
    ]

    result = adapter.process_batch(incidents)

    assert result == [None, None, None]
    assert postgres.calls == [incidents]
    assert neo4j.calls == [incidents]


def test_empty_batch_does_not_call_adapters():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    result = adapter.process_batch([])

    assert result == []
    assert postgres.calls == []
    assert neo4j.calls == []


def test_invalid_constructor_adapter_is_rejected():
    neo4j = FakePersistenceAdapter()

    try:
        CombinedIncidentPersistenceAdapter(
            postgres_adapter=object(),
            neo4j_adapter=neo4j,
        )
        assert False
    except TypeError as exc:
        assert "process_batch" in str(exc)


def test_invalid_incident_is_rejected():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    try:
        adapter.process("not an incident")
        assert False
    except TypeError as exc:
        assert "Incident" in str(exc)


def test_invalid_batch_is_rejected():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    try:
        adapter.process_batch("not a list")
        assert False
    except TypeError as exc:
        assert "list" in str(exc)


def test_invalid_batch_item_is_rejected():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    try:
        adapter.process_batch([make_incident(), "invalid"])
        assert False
    except TypeError as exc:
        assert "Incident" in str(exc)


def test_close_closes_both_adapters():
    postgres = FakePersistenceAdapter()
    neo4j = FakePersistenceAdapter()

    adapter = CombinedIncidentPersistenceAdapter(
        postgres_adapter=postgres,
        neo4j_adapter=neo4j,
    )

    adapter.close()

    assert postgres.closed is True
    assert neo4j.closed is True
