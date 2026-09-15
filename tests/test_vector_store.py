import numpy as np

from rag.documents.chunker import DocumentChunk
from rag.index.vector_store import VectorStore


def test_vector_store_stores_and_searches_chunks(tmp_path):
    store = VectorStore(
        path=str(tmp_path / "qdrant"),
        collection_name="test_collection",
        vector_size=3,
    )

    chunks = [
        DocumentChunk(
            chunk_id="doc-0001",
            document_id="doc",
            title="Brute Force",
            source="test.md",
            content="Brute force attacks repeatedly attempt authentication.",
        ),
        DocumentChunk(
            chunk_id="doc-0002",
            document_id="doc",
            title="DoS",
            source="test.md",
            content="Denial of service attacks overwhelm a target.",
        ),
    ]

    embeddings = np.array(
        [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
        ],
        dtype=np.float32,
    )

    store.add_chunks(
        chunks,
        embeddings,
    )

    assert store.count() == 2

    results = store.search(
        np.array(
            [1.0, 0.0, 0.0],
            dtype=np.float32,
        ),
        limit=1,
    )

    assert len(results) == 1
    assert results[0]["payload"]["chunk_id"] == "doc-0001"
    assert results[0]["payload"]["title"] == "Brute Force"
    assert results[0]["score"] > 0.99


def test_vector_store_rejects_wrong_embedding_dimension(tmp_path):
    store = VectorStore(
        path=str(tmp_path / "qdrant"),
        collection_name="test_collection",
        vector_size=3,
    )

    chunks = [
        DocumentChunk(
            chunk_id="doc-0001",
            document_id="doc",
            title="Test",
            source="test.md",
            content="Test content.",
        )
    ]

    embeddings = np.array(
        [[1.0, 0.0]],
        dtype=np.float32,
    )

    try:
        store.add_chunks(chunks, embeddings)
        assert False
    except ValueError:
        pass


def test_vector_store_preserves_multiple_batches(tmp_path):
    store = VectorStore(
        path=str(tmp_path / "qdrant"),
        collection_name="batch_test",
        vector_size=3,
    )

    first_chunk = DocumentChunk(
        chunk_id="document-chunk-0001",
        document_id="document",
        title="First",
        source="test.md",
        content="First chunk.",
    )

    second_chunk = DocumentChunk(
        chunk_id="document-chunk-0002",
        document_id="document",
        title="Second",
        source="test.md",
        content="Second chunk.",
    )

    embeddings = np.array(
        [[1.0, 0.0, 0.0]],
        dtype=np.float32,
    )

    store.add_chunks(
        [first_chunk],
        embeddings,
    )

    store.add_chunks(
        [second_chunk],
        embeddings,
    )

    assert store.count() == 2