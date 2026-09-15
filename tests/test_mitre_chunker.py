from rag.documents.loader import KnowledgeDocument
from rag.documents.mitre_chunker import MitreChunker


def test_mitre_chunk_preserves_identity():

    document = KnowledgeDocument(
        document_id="T1003.002",
        title="T1003.002 - Security Account Manager",
        source="test",
        content=(
            "Technique ID: T1003.002\n"
            "Technique Name: Security Account Manager\n\n"
            "Description: Adversaries may attempt to "
            "extract credential material from the SAM database. "
            "This is an example description."
        ),
    )

    chunker = MitreChunker(
        chunk_size=300,
        chunk_overlap=50,
    )

    chunks = chunker.chunk_document(document)

    assert len(chunks) >= 1

    for chunk in chunks:
        assert "Technique ID: T1003.002" in chunk.content
        assert (
            "Technique Name: "
            "T1003.002 - Security Account Manager"
            in chunk.content
        )
        assert chunk.document_id == "T1003.002"


def test_mitre_chunk_ids_are_unique():

    document = KnowledgeDocument(
        document_id="T1059.001",
        title="T1059.001 - PowerShell",
        source="test",
        content="A " * 1000,
    )

    chunker = MitreChunker(
        chunk_size=200,
        chunk_overlap=50,
    )

    chunks = chunker.chunk_document(document)

    ids = [
        chunk.chunk_id
        for chunk in chunks
    ]

    assert len(ids) == len(set(ids))


def test_invalid_configuration():

    try:
        MitreChunker(
            chunk_size=100,
            chunk_overlap=100,
        )
        assert False
    except ValueError:
        pass