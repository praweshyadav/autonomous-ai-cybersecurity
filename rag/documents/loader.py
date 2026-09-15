from dataclasses import dataclass
from pathlib import Path


@dataclass
class KnowledgeDocument:
    """
    Represents one source document in the cybersecurity
    knowledge base.
    """

    document_id: str
    title: str
    source: str
    content: str


class DocumentLoader:
    """
    Loads cybersecurity knowledge documents from the
    local knowledge-base directory.
    """

    SUPPORTED_EXTENSIONS = {".txt", ".md"}

    def __init__(self, documents_dir: str | Path):
        self.documents_dir = Path(documents_dir)

    def load_documents(self) -> list[KnowledgeDocument]:
        """
        Load all supported documents from the documents directory.
        """

        if not self.documents_dir.exists():
            raise FileNotFoundError(
                f"Knowledge directory not found: {self.documents_dir}"
            )

        documents = []

        for file_path in sorted(self.documents_dir.iterdir()):

            if not file_path.is_file():
                continue

            if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
                continue

            content = file_path.read_text(
                encoding="utf-8"
            ).strip()

            if not content:
                continue

            document = KnowledgeDocument(
                document_id=file_path.stem,
                title=file_path.stem.replace("_", " "),
                source=str(file_path),
                content=content,
            )

            documents.append(document)

        return documents