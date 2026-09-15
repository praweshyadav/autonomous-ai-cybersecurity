from dataclasses import dataclass

from rag.documents.loader import KnowledgeDocument


@dataclass
class DocumentChunk:
    """
    Represents one chunk of a knowledge document.
    """

    chunk_id: str
    document_id: str
    title: str
    source: str
    content: str


class DocumentChunker:
    """
    Splits knowledge documents into smaller chunks suitable
    for embedding and vector retrieval.
    """

    def __init__(
        self,
        chunk_size: int = 500,
        chunk_overlap: int = 100,
    ):
        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than 0")

        if chunk_overlap < 0:
            raise ValueError("chunk_overlap cannot be negative")

        if chunk_overlap >= chunk_size:
            raise ValueError(
                "chunk_overlap must be smaller than chunk_size"
            )

        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_document(
        self,
        document: KnowledgeDocument,
    ) -> list[DocumentChunk]:
        """
        Split one document into overlapping chunks.
        """

        content = document.content.strip()

        if not content:
            return []

        chunks = []

        start = 0
        chunk_number = 0

        while start < len(content):
            end = min(
                start + self.chunk_size,
                len(content),
            )

            chunk_content = content[start:end].strip()

            if chunk_content:
                chunk = DocumentChunk(
                    chunk_id=(
                        f"{document.document_id}"
                        f"-chunk-{chunk_number:04d}"
                    ),
                    document_id=document.document_id,
                    title=document.title,
                    source=document.source,
                    content=chunk_content,
                )

                chunks.append(chunk)

            if end >= len(content):
                break

            start = end - self.chunk_overlap
            chunk_number += 1

        return chunks

    def chunk_documents(
        self,
        documents: list[KnowledgeDocument],
    ) -> list[DocumentChunk]:
        """
        Split multiple documents into chunks.
        """

        chunks = []

        for document in documents:
            chunks.extend(
                self.chunk_document(document)
            )

        return chunks