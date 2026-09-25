from datetime import datetime, timezone

from correlation.schema import Incident, SecurityEvent

from agent.investigation_orchestrator import (
    InvestigationOrchestrator,
)
from agent.llm_investigation_agent import (
    LLMInvestigationAgent,
)
from agent.mock_llm_provider import (
    MockLLMProvider,
)


def make_incident():
    timestamp = datetime.now(timezone.utc)

    events = []

    for index in range(5):
        events.append(
            SecurityEvent(
                event_id=(
                    f"33333333-3333-4333-8333-{index:012d}"
                ),
                timestamp=timestamp,
                src_ip="10.10.10.60",
                dst_ip="192.168.1.30",
                src_port=45000 + index,
                dst_port=22,
                protocol=6,
                protocol_name="TCP",
                binary_prediction=1,
                attack_family="Brute Force",
                confidence=0.95,
            )
        )

    return Incident(
        incident_id="INC-LLM-INTEGRATION-001",
        events=events,
        start_time=timestamp,
        end_time=timestamp,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 5},
        confidence=0.95,
        src_ips=["10.10.10.60"],
        dst_ips=["192.168.1.30"],
        dst_ports=[22],
        protocols=[6],
    )


def test_real_rag_investigation_with_mock_llm():
    incident = make_incident()

    llm_agent = LLMInvestigationAgent(
        provider=MockLLMProvider(),
    )

    orchestrator = InvestigationOrchestrator(
        llm_agent=llm_agent,
    )

    try:
        result = orchestrator.investigate_with_llm(
            incident=incident,
            top_k=3,
        )

        assert result.incident_id == (
            "INC-LLM-INTEGRATION-001"
        )

        assert result.context.incident_id == (
            "INC-LLM-INTEGRATION-001"
        )

        assert result.rag_result.incident_id == (
            "INC-LLM-INTEGRATION-001"
        )

        assert len(result.rag_result.results) > 0

        assert result.investigation.incident_id == (
            "INC-LLM-INTEGRATION-001"
        )

        assert result.llm_output is not None

        assert result.llm_output.incident_id == (
            "INC-LLM-INTEGRATION-001"
        )

        assert result.llm_output.summary

        assert result.llm_output.threat_assessment == (
            "High"
        )

        assert result.llm_output.confidence == 0.80

        assert result.llm_output.metadata["provider"] == (
            "mock"
        )

        assert result.metadata["llm_used"] is True

        assert result.metadata["rag_result_count"] == 3

        print("\n=== REAL RAG RESULTS ===")

        for item in result.rag_result.results:
            print(
                f"{item.title} | "
                f"score={item.score:.4f}"
            )

        print("\n=== DETERMINISTIC INVESTIGATION ===")

        print(
            "Summary:",
            result.investigation.summary,
        )

        print(
            "Threat:",
            result.investigation.threat_assessment,
        )

        print(
            "Confidence:",
            result.investigation.confidence,
        )

        print("\n=== LLM OUTPUT ===")

        print(
            "Summary:",
            result.llm_output.summary,
        )

        print(
            "Threat:",
            result.llm_output.threat_assessment,
        )

        print(
            "Confidence:",
            result.llm_output.confidence,
        )

        print(
            "Provider:",
            result.llm_output.metadata["provider"],
        )

    finally:
        orchestrator.close()
