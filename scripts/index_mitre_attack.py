import json
from pathlib import Path

from rag.documents.loader import KnowledgeDocument
from rag.documents.mitre_chunker import MitreChunker
from rag.embeddings import EmbeddingModel
from rag.index.vector_store import VectorStore


INPUT_FILE = Path(
    "rag/documents/mitre/parsed_documents.jsonl"
)

QDRANT_PATH = "rag/index/qdrant"

COLLECTION_NAME = "mitre_attack"

CHUNK_SIZE = 700
CHUNK_OVERLAP = 100

BATCH_SIZE = 32


def load_parsed_documents() -> list[KnowledgeDocument]:
    """
    Load parsed MITRE ATT&CK documents from JSONL.
    """

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Parsed MITRE file not found: {INPUT_FILE}"
        )

    documents = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            record = json.loads(line)

            documents.append(
                KnowledgeDocument(
                    document_id=record["document_id"],
                    title=record["title"],
                    source=record["source"],
                    content=record["content"],
                )
            )

    return documents


def main():

    print("=" * 70)
    print("MITRE ATT&CK VECTOR INDEXER")
    print("=" * 70)

    # ------------------------------------------------------------
    # 1. Load parsed MITRE documents
    # ------------------------------------------------------------

    print(
        "\n[1/5] Loading parsed MITRE documents..."
    )

    documents = load_parsed_documents()

    print(
        f"Documents loaded: {len(documents):,}"
    )

    if not documents:
        raise RuntimeError(
            "No parsed MITRE documents found."
        )

    # ------------------------------------------------------------
    # 2. Chunk documents
    # ------------------------------------------------------------

    print(
        "\n[2/5] Chunking documents..."
    )

    chunker = MitreChunker(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )

    chunks = chunker.chunk_documents(
        documents
    )

    print(
        f"Chunks created: {len(chunks):,}"
    )

    if not chunks:
        raise RuntimeError(
            "No chunks were created."
        )

    # ------------------------------------------------------------
    # 3. Load embedding model
    # ------------------------------------------------------------

    print(
        "\n[3/5] Loading embedding model..."
    )

    embedding_model = EmbeddingModel()

    print(
        f"Embedding model: "
        f"{embedding_model.model_name}"
    )

    # ------------------------------------------------------------
    # 4. Create fresh Qdrant vector store
    # ------------------------------------------------------------

    print(
        "\n[4/5] Creating fresh Qdrant vector store..."
    )

    vector_store = VectorStore(
        path=QDRANT_PATH,
        collection_name=COLLECTION_NAME,
        vector_size=384,
    )

    vector_store.reset_collection()

    print(
        f"Fresh collection created: "
        f"{COLLECTION_NAME}"
    )

    print(
        f"Current vectors: "
        f"{vector_store.count()}"
    )

    # ------------------------------------------------------------
    # 5. Generate embeddings and index
    # ------------------------------------------------------------

    print(
        "\n[5/5] Generating embeddings and indexing..."
    )

    total = len(chunks)

    for start in range(
        0,
        total,
        BATCH_SIZE,
    ):

        batch = chunks[
            start:start + BATCH_SIZE
        ]

        texts = [
            chunk.content
            for chunk in batch
        ]

        embeddings = embedding_model.encode(
            texts
        )

        vector_store.add_chunks(
            batch,
            embeddings,
        )

        processed = min(
            start + BATCH_SIZE,
            total,
        )

        print(
            f"Indexed {processed:,}/{total:,}"
        )

    # ------------------------------------------------------------
    # Final verification
    # ------------------------------------------------------------

    final_count = vector_store.count()

    print(
        "\n" + "=" * 70
    )

    print(
        "MITRE ATT&CK INDEXING COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        f"Documents : {len(documents):,}"
    )

    print(
        f"Chunks    : {len(chunks):,}"
    )

    print(
        f"Vectors   : {final_count:,}"
    )

    print(
        f"Collection: {COLLECTION_NAME}"
    )

    print(
        "=" * 70
    )

    # ------------------------------------------------------------
    # Safety check
    # ------------------------------------------------------------

    if final_count != len(chunks):
        raise RuntimeError(
            "Index verification failed: "
            f"{final_count:,} vectors for "
            f"{len(chunks):,} chunks."
        )

    print(
        "Index verification: PASSED"
    )


if __name__ == "__main__":
    main()