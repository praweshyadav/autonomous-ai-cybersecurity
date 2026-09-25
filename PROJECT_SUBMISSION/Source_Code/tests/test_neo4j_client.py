import pytest

from knowledge_graph.client import Neo4jClient


def test_neo4j_client_connects():
    client = Neo4jClient()

    try:
        client.verify_connectivity()
    finally:
        client.close()


def test_neo4j_client_execute():
    client = Neo4jClient()

    try:
        result = client.execute(
            "RETURN 1 AS value"
        )

        assert result == [
            {"value": 1}
        ]
    finally:
        client.close()


def test_neo4j_client_rejects_empty_query():
    client = Neo4jClient()

    try:
        with pytest.raises(
            ValueError,
            match="query cannot be empty",
        ):
            client.execute("")
    finally:
        client.close()


def test_neo4j_client_rejects_non_string_query():
    client = Neo4jClient()

    try:
        with pytest.raises(
            TypeError,
            match="query must be a string",
        ):
            client.execute(None)
    finally:
        client.close()


def test_neo4j_client_rejects_non_dictionary_parameters():
    client = Neo4jClient()

    try:
        with pytest.raises(
            TypeError,
            match="parameters must be a dictionary",
        ):
            client.execute(
                "RETURN 1",
                parameters=[],
            )
    finally:
        client.close()


def test_neo4j_client_context_manager():
    with Neo4jClient() as client:
        client.verify_connectivity()
