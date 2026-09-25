from typing import Any
from uuid import uuid5, NAMESPACE_URL

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from rag.documents.chunker import DocumentChunk


class VectorStore:
    """
    Qdrant-backed vector store for cybersecurity knowledge.

    Supports two modes:

    1. Local development/testing:
       VectorStore(path="rag/index/qdrant")

    2. Qdrant server:
       VectorStore(url="http://localhost:6333")

    Exactly one of `path` or `url` must be provided.
    """

    def __init__(
        self,
        path: str | None = None,
        url: str | None = None,
        collection_name: str = "cybersecurity_knowledge",
        vector_size: int = 384,
    ) -> None:
        if path is not None and url is not None:
            raise ValueError(
                "Provide either path or url, not both."
            )

        if path is None and url is None:
            raise ValueError(
                "Either path or url must be provided."
            )

        if not isinstance(collection_name, str) or not collection_name.strip():
            raise ValueError(
                "collection_name must be a non-empty string."
            )

        if vector_size <= 0:
            raise ValueError(
                "vector_size must be greater than 0."
            )

        self.path = path
        self.url = url
        self.collection_name = collection_name
        self.vector_size = vector_size
        self._closed = False

        if url is not None:
            self.client = QdrantClient(
                url=url
            )
            self.mode = "server"
        else:
            self.client = QdrantClient(
                path=path
            )
            self.mode = "local"

        self._create_collection()

    def _ensure_open(self) -> None:
        """
        Ensure the vector store has not been closed.
        """
        if self._closed:
            raise RuntimeError(
                "VectorStore is already closed."
            )

    def _create_collection(self) -> None:
        """
        Create the Qdrant collection if it does not already exist.
        """
        self._ensure_open()

        collections = self.client.get_collections()

        existing_names = {
            collection.name
            for collection in collections.collections
        }

        if self.collection_name in existing_names:
            return

        self.client.create_collection(
            collection_name=self.collection_name,
            vectors_config=VectorParams(
                size=self.vector_size,
                distance=Distance.COSINE,
            ),
        )

    def reset_collection(self) -> None:
        """
        Delete the current collection and recreate it.

        Only the configured collection is affected.
        """
        self._ensure_open()

        collections = self.client.get_collections()

        existing_names = {
            collection.name
            for collection in collections.collections
        }

        if self.collection_name in existing_names:
            self.client.delete_collection(
                collection_name=self.collection_name
            )

        self.client.create_collection(
            collection_name=self.collection_name,
            vectors_config=VectorParams(
                size=self.vector_size,
                distance=Distance.COSINE,
            ),
        )

    def _point_id(
        self,
        chunk_id: str,
    ) -> str:
        """
        Convert an application-level chunk ID into a deterministic UUID.

        The same chunk_id always produces the same UUID.
        """
        return str(
            uuid5(
                NAMESPACE_URL,
                chunk_id,
            )
        )

    def add_chunks(
        self,
        chunks: list[DocumentChunk],
        embeddings,
    ) -> None:
        """
        Store document chunks together with their embeddings.
        """
        self._ensure_open()

        if len(chunks) != len(embeddings):
            raise ValueError(
                "Number of chunks must match number of embeddings."
            )

        if not chunks:
            return

        points = []

        for chunk, embedding in zip(
            chunks,
            embeddings,
        ):
            vector = embedding.tolist()

            if len(vector) != self.vector_size:
                raise ValueError(
                    f"Embedding dimension {len(vector)} does not "
                    f"match vector store dimension {self.vector_size}."
                )

            points.append(
                PointStruct(
                    id=self._point_id(
                        chunk.chunk_id
                    ),
                    vector=vector,
                    payload={
                        "chunk_id": chunk.chunk_id,
                        "document_id": chunk.document_id,
                        "title": chunk.title,
                        "source": chunk.source,
                        "content": chunk.content,
                    },
                )
            )

        self.client.upsert(
            collection_name=self.collection_name,
            points=points,
        )

    def search(
        self,
        query_vector,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Search the vector store using cosine similarity.
        """
        self._ensure_open()

        if len(query_vector) != self.vector_size:
            raise ValueError(
                f"Query vector dimension {len(query_vector)} does not "
                f"match vector store dimension {self.vector_size}."
            )

        results = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector.tolist(),
            limit=limit,
            with_payload=True,
        ).points

        return [
            {
                "score": result.score,
                "payload": result.payload,
            }
            for result in results
        ]

    def count(self) -> int:
        """
        Return the number of stored vectors.
        """
        self._ensure_open()

        result = self.client.count(
            collection_name=self.collection_name,
            exact=True,
        )

        return result.count

    def close(self) -> None:
        """
        Close the underlying Qdrant client.

        For local mode this releases the filesystem lock.
        For server mode this closes the HTTP/gRPC client resources.

        Calling close() multiple times is safe.
        """
        if self._closed:
            return

        self.client.close()
        self._closed = True

    def __enter__(self):
        """
        Support usage with a context manager.
        """
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        """
        Automatically close the Qdrant client.
        """
        self.close()

    def __del__(self) -> None:
        """
        Best-effort cleanup if the object is garbage collected.
        """
        try:
            self.close()
        except Exception:
            pass
