import pytest

from rag.retriever.query_engine import RAGQueryEngine


@pytest.fixture
def engine():
    engine = RAGQueryEngine(
        collection_name="mitre_attack",
        qdrant_path="rag/index/qdrant",
        vector_size=384,
    )

    yield engine

    engine.close()


def test_query_returns_results(engine):
    results = engine.query(
        "An attacker uses PowerShell to execute malicious commands.",
        top_k=3,
    )

    assert len(results) == 3

    for result in results:
        assert result.chunk_id
        assert result.document_id
        assert result.title
        assert result.content
        assert isinstance(result.score, float)


def test_query_finds_powershell_technique(engine):
    results = engine.query(
        "An attacker uses PowerShell to execute malicious commands.",
        top_k=3,
    )

    document_ids = [
        result.document_id
        for result in results
    ]

    assert "T1059.001" in document_ids


def test_query_dict_returns_dictionaries(engine):
    results = engine.query_dict(
        "An attacker uses PowerShell to execute malicious commands.",
        top_k=3,
    )

    assert len(results) == 3

    assert isinstance(results[0], dict)

    required_keys = {
        "chunk_id",
        "document_id",
        "title",
        "source",
        "content",
        "score",
    }

    assert required_keys.issubset(
        results[0].keys()
    )


def test_empty_query_rejected(engine):
    with pytest.raises(ValueError):
        engine.query("")


def test_invalid_top_k_rejected(engine):
    with pytest.raises(ValueError):
        engine.query(
            "PowerShell attack",
            top_k=0,
        )