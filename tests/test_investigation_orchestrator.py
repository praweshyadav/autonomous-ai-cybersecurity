from datetime import datetime, timezone

import pytest

from correlation.schema import Incident, SecurityEvent

from agent.context_builder import (
    IncidentContext,
    IncidentContextBuilder,
)
from agent.incident_rag import (
    IncidentRAGResult,
)
from agent.investigation import (
    InvestigationResult,
)
from agent.investigation_orchestrator import (
    InvestigationOrchestrator,
    InvestigationOrchestrationResult,
)
from agent.llm_contract import (
    LLMInvestigationOutput,
)


class FakeIncidentRAG:
    def __init__(self):
        self.calls = []
        self.closed = False

    def investigate(self, context, top_k=5):
        self.calls.append(
            {
                "context": context,
                "top_k": top_k,
            }
        )

        return IncidentRAGResult(
            incident_id=context.incident_id,
            query="fake investigation query",
            results=[],
        )

    def close(self):
        self.closed = True


class FakeInvestigationEngine:
    def __init__(self):
        self.calls = []

    def investigate(self, context, rag_result):
        self.calls.append(
            {
                "context": context,
                "rag_result": rag_result,
            }
        )

        return InvestigationResult(
            incident_id=context.incident_id,
            summary="Fake investigation summary",
            threat_assessment="High",
            attack_families=context.attack_families,
            confidence=0.90,
            recommended_actions=[
                "Review the affected service."
            ],
        )


class FakeLLMAgent:
    def __init__(self):
        self.calls = []

    def investigate(
        self,
        context,
        investigation,
        rag_result,
    ):
        self.calls.append(
            {
                "context": context,
                "investigation": investigation,
                "rag_result": rag_result,
            }
        )

        return LLMInvestigationOutput(
            incident_id=context.incident_id,
            summary="Fake LLM summary",
            threat_assessment="High",
            confidence=0.92,
        )


def make_incident():
    timestamp = datetime.now(timezone.utc)

    event = SecurityEvent(
        event_id="11111111-1111-4111-8111-111111111111",
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

    return Incident(
        incident_id="INC-000001",
        events=[event],
        start_time=timestamp,
        end_time=timestamp,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 1},
        confidence=0.95,
        src_ips=["10.10.10.10"],
        dst_ips=["192.168.1.10"],
        dst_ports=[22],
        protocols=[6],
    )


def test_deterministic_investigation_pipeline():
    incident = make_incident()

    rag = FakeIncidentRAG()
    engine = FakeInvestigationEngine()

    orchestrator = InvestigationOrchestrator(
        incident_rag=rag,
        investigation_engine=engine,
    )

    result = orchestrator.investigate_deterministic(
        incident
    )

    assert isinstance(
        result,
        InvestigationOrchestrationResult,
    )

    assert result.incident_id == "INC-000001"

    assert result.context.incident_id == "INC-000001"

    assert result.rag_result.incident_id == "INC-000001"

    assert result.investigation.incident_id == (
        "INC-000001"
    )

    assert result.llm_output is None

    assert result.metadata["rag_result_count"] == 0
    assert result.metadata["llm_used"] is False

    assert len(rag.calls) == 1
    assert rag.calls[0]["top_k"] == 5

    assert len(engine.calls) == 1


def test_custom_top_k_is_forwarded_to_rag():
    incident = make_incident()

    rag = FakeIncidentRAG()
    engine = FakeInvestigationEngine()

    orchestrator = InvestigationOrchestrator(
        incident_rag=rag,
        investigation_engine=engine,
    )

    orchestrator.investigate(
        incident=incident,
        top_k=7,
        use_llm=False,
    )

    assert rag.calls[0]["top_k"] == 7


def test_llm_is_not_called_in_deterministic_mode():
    incident = make_incident()

    rag = FakeIncidentRAG()
    engine = FakeInvestigationEngine()
    llm = FakeLLMAgent()

    orchestrator = InvestigationOrchestrator(
        incident_rag=rag,
        investigation_engine=engine,
        llm_agent=llm,
    )

    result = orchestrator.investigate(
        incident=incident,
        use_llm=False,
    )

    assert result.llm_output is None
    assert llm.calls == []


def test_llm_stage_is_called_when_enabled():
    incident = make_incident()

    rag = FakeIncidentRAG()
    engine = FakeInvestigationEngine()
    llm = FakeLLMAgent()

    orchestrator = InvestigationOrchestrator(
        incident_rag=rag,
        investigation_engine=engine,
        llm_agent=llm,
    )

    result = orchestrator.investigate_with_llm(
        incident
    )

    assert result.llm_output is not None

    assert (
        result.llm_output.incident_id
        == incident.incident_id
    )

    assert result.metadata["llm_used"] is True

    assert len(llm.calls) == 1

    assert (
        llm.calls[0]["context"].incident_id
        == incident.incident_id
    )

    assert (
        llm.calls[0]["investigation"].incident_id
        == incident.incident_id
    )

    assert (
        llm.calls[0]["rag_result"].incident_id
        == incident.incident_id
    )


def test_llm_requires_configured_agent():
    incident = make_incident()

    rag = FakeIncidentRAG()
    engine = FakeInvestigationEngine()

    orchestrator = InvestigationOrchestrator(
        incident_rag=rag,
        investigation_engine=engine,
    )

    with pytest.raises(RuntimeError):
        orchestrator.investigate_with_llm(
            incident
        )


def test_invalid_incident_is_rejected():
    orchestrator = InvestigationOrchestrator(
        incident_rag=FakeIncidentRAG(),
        investigation_engine=FakeInvestigationEngine(),
    )

    with pytest.raises(TypeError):
        orchestrator.investigate(
            incident="invalid",
            use_llm=False,
        )


def test_invalid_top_k_type_is_rejected():
    incident = make_incident()

    orchestrator = InvestigationOrchestrator(
        incident_rag=FakeIncidentRAG(),
        investigation_engine=FakeInvestigationEngine(),
    )

    with pytest.raises(TypeError):
        orchestrator.investigate(
            incident=incident,
            top_k="5",
        )


def test_invalid_top_k_value_is_rejected():
    incident = make_incident()

    orchestrator = InvestigationOrchestrator(
        incident_rag=FakeIncidentRAG(),
        investigation_engine=FakeInvestigationEngine(),
    )

    with pytest.raises(ValueError):
        orchestrator.investigate(
            incident=incident,
            top_k=0,
        )


def test_invalid_use_llm_type_is_rejected():
    incident = make_incident()

    orchestrator = InvestigationOrchestrator(
        incident_rag=FakeIncidentRAG(),
        investigation_engine=FakeInvestigationEngine(),
    )

    with pytest.raises(TypeError):
        orchestrator.investigate(
            incident=incident,
            use_llm="yes",
        )


def test_close_closes_owned_rag_component():
    rag = FakeIncidentRAG()

    orchestrator = InvestigationOrchestrator(
        incident_rag=rag,
        investigation_engine=FakeInvestigationEngine(),
    )

    orchestrator.close()

    assert rag.closed is True
