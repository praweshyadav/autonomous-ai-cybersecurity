from datetime import datetime, timezone

from correlation.schema import Incident, SecurityEvent

from agent.context_builder import IncidentContextBuilder
from agent.incident_rag import IncidentRAGResult
from agent.investigation import InvestigationResult
from agent.investigation_engine import InvestigationEngine
from agent.llm_contract import LLMInvestigationOutput
from agent.llm_input_builder import LLMInputBuilder
from agent.llm_investigation_agent import LLMInvestigationAgent
from agent.mock_llm_provider import MockLLMProvider


def make_incident():
    timestamp = datetime.now(timezone.utc)

    event = SecurityEvent(
        event_id="22222222-2222-4222-8222-222222222222",
        timestamp=timestamp,
        src_ip="10.10.10.50",
        dst_ip="192.168.1.20",
        src_port=45000,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.95,
    )

    return Incident(
        incident_id="INC-LLM-001",
        events=[event],
        start_time=timestamp,
        end_time=timestamp,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 1},
        confidence=0.95,
        src_ips=["10.10.10.50"],
        dst_ips=["192.168.1.20"],
        dst_ports=[22],
        protocols=[6],
    )


def test_llm_investigation_agent_with_mock_provider():
    incident = make_incident()

    context_builder = IncidentContextBuilder()

    context = context_builder.build(incident)

    rag_result = IncidentRAGResult(
        incident_id=incident.incident_id,
        query="Brute Force SSH investigation",
        results=[],
    )

    investigation_engine = InvestigationEngine()

    investigation = investigation_engine.investigate(
        context=context,
        rag_result=rag_result,
    )

    provider = MockLLMProvider()

    agent = LLMInvestigationAgent(
        provider=provider,
        input_builder=LLMInputBuilder(),
    )

    result = agent.investigate(
        context=context,
        investigation=investigation,
        rag_result=rag_result,
    )

    assert isinstance(
        result,
        LLMInvestigationOutput,
    )

    assert result.incident_id == incident.incident_id

    assert result.summary

    assert result.threat_assessment == "High"

    assert result.confidence == 0.80

    assert result.metadata["provider"] == "mock"

    assert len(result.hypotheses) == 1

    assert "Brute Force" in (
        result.hypotheses[0].hypothesis
    )

    assert result.hypotheses[0].confidence == 0.80

    assert result.evidence_gaps

    assert result.next_investigation_steps

    assert result.recommended_actions

    assert result.uncertainty


def test_llm_agent_uses_evidence_ids_from_controlled_input():
    incident = make_incident()

    context = IncidentContextBuilder().build(incident)

    rag_result = IncidentRAGResult(
        incident_id=incident.incident_id,
        query="Brute Force investigation",
        results=[],
    )

    investigation = InvestigationResult(
        incident_id=incident.incident_id,
        summary="Observed brute force activity.",
        threat_assessment="High",
        attack_families=["Brute Force"],
        confidence=0.90,
    )

    agent = LLMInvestigationAgent(
        provider=MockLLMProvider(),
    )

    result = agent.investigate(
        context=context,
        investigation=investigation,
        rag_result=rag_result,
    )

    assert isinstance(
        result,
        LLMInvestigationOutput,
    )

    assert result.incident_id == incident.incident_id

    assert len(result.hypotheses) == 1

    # No raw traffic or arbitrary event objects are passed
    # directly to the provider output.
    assert isinstance(
        result.hypotheses[0].supporting_evidence_ids,
        list,
    )


def test_llm_agent_preserves_identified_mitre_techniques():
    incident = make_incident()

    context = IncidentContextBuilder().build(incident)

    rag_result = IncidentRAGResult(
        incident_id=incident.incident_id,
        query="Brute Force investigation",
        results=[],
    )

    investigation = InvestigationResult(
        incident_id=incident.incident_id,
        summary="Brute force behavior observed.",
        threat_assessment="High",
        attack_families=["Brute Force"],
        confidence=0.90,
        mitre_techniques=[],
    )

    agent = LLMInvestigationAgent(
        provider=MockLLMProvider(),
    )

    result = agent.investigate(
        context=context,
        investigation=investigation,
        rag_result=rag_result,
    )

    assert result.technique_assessments == []
