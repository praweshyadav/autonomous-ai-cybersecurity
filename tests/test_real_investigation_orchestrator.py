from datetime import datetime, timezone

from correlation.schema import Incident, SecurityEvent
from agent.investigation_orchestrator import InvestigationOrchestrator


def make_realistic_incident():
    timestamp = datetime.now(timezone.utc)

    events = []

    for index in range(5):
        events.append(
            SecurityEvent(
                event_id=f"11111111-1111-4111-8111-{index:012d}",
                timestamp=timestamp,
                src_ip="10.10.10.50",
                dst_ip="192.168.1.20",
                src_port=40000 + index,
                dst_port=22,
                protocol=6,
                protocol_name="TCP",
                binary_prediction=1,
                attack_family="Brute Force",
                confidence=0.95,
            )
        )

    return Incident(
        incident_id="INC-REAL-RAG-001",
        events=events,
        start_time=timestamp,
        end_time=timestamp,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 5},
        confidence=0.95,
        src_ips=["10.10.10.50"],
        dst_ips=["192.168.1.20"],
        dst_ports=[22],
        protocols=[6],
    )


def test_real_deterministic_investigation():
    incident = make_realistic_incident()

    orchestrator = InvestigationOrchestrator()

    try:
        result = orchestrator.investigate_deterministic(
            incident=incident,
            top_k=3,
        )

        assert result.incident_id == "INC-REAL-RAG-001"

        assert result.context.incident_id == (
            "INC-REAL-RAG-001"
        )

        assert result.rag_result.incident_id == (
            "INC-REAL-RAG-001"
        )

        assert len(result.rag_result.results) > 0

        assert result.investigation.incident_id == (
            "INC-REAL-RAG-001"
        )

        assert result.investigation.confidence >= 0.0
        assert result.investigation.confidence <= 1.0

        assert result.llm_output is None

        assert result.metadata["llm_used"] is False

        print("\nReal RAG results:")

        for item in result.rag_result.results:
            print(item)

        print(
            "\nInvestigation summary:",
            result.investigation.summary,
        )

        print(
            "\nThreat assessment:",
            result.investigation.threat_assessment,
        )

        print(
            "\nConfidence:",
            result.investigation.confidence,
        )

    finally:
        orchestrator.close()
