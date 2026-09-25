from dataclasses import dataclass

from rag.documents.loader import KnowledgeDocument


@dataclass
class MitreChunk:
    chunk_id: str
    document_id: str
    title: str
    source: str
    content: str


class MitreChunker:
    """
    Chunk MITRE ATT&CK technique documents while preserving
    the technique identity and metadata in every chunk.
    """

    def __init__(
        self,
        chunk_size: int = 700,
        chunk_overlap: int = 100,
    ):
        if chunk_size <= 0:
            raise ValueError(
                "chunk_size must be greater than 0"
            )

        if chunk_overlap < 0:
            raise ValueError(
                "chunk_overlap cannot be negative"
            )

        if chunk_overlap >= chunk_size:
            raise ValueError(
                "chunk_overlap must be smaller than chunk_size"
            )

        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_document(
        self,
        document: KnowledgeDocument,
    ) -> list[MitreChunk]:

        if not document.content.strip():
            return []

        # --------------------------------------------------------
        # Keep the technique identity and metadata in every chunk.
        # --------------------------------------------------------

        prefix = (
            f"MITRE ATT&CK Technique\n"
            f"Technique ID: {document.document_id}\n"
            f"Technique Name: {document.title}\n\n"
        )

        content = document.content.strip()

        # Remove duplicate identity information from the original
        # document when it is already present in the prefix.
        lines = content.splitlines()

        filtered_lines = []

        for line in lines:

            if line.startswith("Technique ID:"):
                continue

            if line.startswith("Technique Name:"):
                continue

            filtered_lines.append(line)

        content = "\n".join(
            filtered_lines
        ).strip()

        # --------------------------------------------------------
        # Character-based chunks with overlap.
        # --------------------------------------------------------

        available_size = (
            self.chunk_size
            - len(prefix)
        )

        if available_size <= 0:
            raise ValueError(
                "chunk_size is too small for MITRE metadata prefix"
            )

        chunks = []

        start = 0
        chunk_number = 0

        while start < len(content):

            end = min(
                start + available_size,
                len(content),
            )

            chunk_content = (
                prefix
                + content[start:end].strip()
            )

            chunks.append(
                MitreChunk(
                    chunk_id=(
                        f"{document.document_id}"
                        f"-chunk-{chunk_number:04d}"
                    ),
                    document_id=document.document_id,
                    title=document.title,
                    source=document.source,
                    content=chunk_content,
                )
            )

            if end >= len(content):
                break

            start = (
                end
                - self.chunk_overlap
            )

            chunk_number += 1

        return chunks

    def chunk_documents(
        self,
        documents: list[KnowledgeDocument],
    ) -> list[MitreChunk]:

        chunks = []

        for document in documents:
            chunks.extend(
                self.chunk_document(document)
            )

        return chunks