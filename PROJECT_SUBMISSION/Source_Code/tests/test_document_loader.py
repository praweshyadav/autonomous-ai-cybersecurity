from pathlib import Path

from rag.documents.loader import DocumentLoader


def test_document_loader_reads_markdown_documents(tmp_path: Path):
    document = tmp_path / "brute_force.md"

    document.write_text(
        "# Brute Force\n\n"
        "Brute force attacks attempt repeated authentication attempts.",
        encoding="utf-8",
    )

    loader = DocumentLoader(tmp_path)

    documents = loader.load_documents()

    assert len(documents) == 1

    loaded = documents[0]

    assert loaded.document_id == "brute_force"
    assert loaded.title == "brute force"
    assert loaded.source.endswith("brute_force.md")

    assert "Brute Force" in loaded.content
    assert "repeated authentication attempts" in loaded.content