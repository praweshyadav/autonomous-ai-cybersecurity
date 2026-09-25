from pathlib import Path

from rag.documents.chunker import DocumentChunker
from rag.documents.loader import KnowledgeDocument


def test_document_chunker_creates_overlapping_chunks():
    content = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
    )

    document = KnowledgeDocument(
        document_id="test-document",
        title="Test Document",
        source="test.md",
        content=content,
    )

    chunker = DocumentChunker(
        chunk_size=30,
        chunk_overlap=10,
    )

    chunks = chunker.chunk_document(document)

    assert len(chunks) > 1

    assert chunks[0].chunk_id == "test-document-chunk-0000"
    assert chunks[1].chunk_id == "test-document-chunk-0001"

    assert chunks[0].document_id == "test-document"
    assert chunks[0].title == "Test Document"
    assert chunks[0].source == "test.md"

    assert len(chunks[0].content) <= 30
    assert len(chunks[1].content) <= 30

    # The end of the first chunk should overlap
    # with the beginning of the second chunk.
    assert chunks[0].content[-10:] == chunks[1].content[:10]


def test_empty_document_produces_no_chunks():
    document = KnowledgeDocument(
        document_id="empty",
        title="Empty",
        source="empty.md",
        content="",
    )

    chunker = DocumentChunker()

    chunks = chunker.chunk_document(document)

    assert chunks == []


def test_invalid_chunk_configuration_is_rejected():
    try:
        DocumentChunker(
            chunk_size=100,
            chunk_overlap=100,
        )
        assert False
    except ValueError:
        pass