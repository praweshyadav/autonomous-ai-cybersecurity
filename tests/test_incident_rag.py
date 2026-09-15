from agent.context_builder import IncidentContext
from agent.incident_rag import IncidentRAG


class FakeQueryEngine:
    """
    Fake RAG query engine used to test IncidentRAG
    without opening Qdrant.
    """

    def __init__(self):
        self.last_query = None
        self.last_top_k = None

    def query(
        self,
        query: str,
        top_k: int = 5,
    ):
        self.last_query = query
        self.last_top_k = top_k

        return [
            {
                "document_id": "T1110.001",
                "title": "T1110.001 - Password Guessing",
                "score": 0.91,
            }
        ]


def make_context():
    return IncidentContext(
        incident_id="INC-000001",
        start_time="2018-02-14T10:33:26",
        end_time="2018-02-14T10:38:24",
        duration_seconds=298.0,
        severity="critical",
        primary_attack_family="Brute Force",
        event_count=9904,
        confidence=0.8123,
        attack_families=[
            "Brute Force",
            "DoS",
        ],
        family_distribution={
            "Brute Force": 9057,
            "DoS": 847,
        },
        protocols=[6],
        destination_ports=[21],
        source_ips=[],
        destination_ips=[],
    )


def test_build_query_contains_security_context():
    fake_engine = FakeQueryEngine()

    incident_rag = IncidentRAG(
        query_engine=fake_engine
    )

    context = make_context()

    query = incident_rag.build_query(
        context
    )

    assert "Brute Force" in query
    assert "DoS" in query
    assert "9057" in query
    assert "847" in query
    assert "6" in query
    assert "21" in query


def test_investigate_calls_query_engine():
    fake_engine = FakeQueryEngine()

    incident_rag = IncidentRAG(
        query_engine=fake_engine
    )

    context = make_context()

    result = incident_rag.investigate(
        context=context,
        top_k=3,
    )

    assert result.incident_id == "INC-000001"

    assert result.query == fake_engine.last_query

    assert fake_engine.last_top_k == 3

    assert len(result.results) == 1

    assert (
        result.results[0]["document_id"]
        == "T1110.001"
    )