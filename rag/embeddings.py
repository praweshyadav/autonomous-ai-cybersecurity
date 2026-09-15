from sentence_transformers import SentenceTransformer


class EmbeddingModel:
    """
    Generates vector embeddings for cybersecurity knowledge chunks.
    """

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)

    def encode(self, texts: list[str]):
        """
        Convert a list of texts into embedding vectors.
        """

        if not texts:
            return []

        return self.model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

    def encode_one(self, text: str):
        """
        Convert a single text into one embedding vector.
        """

        embeddings = self.encode([text])

        return embeddings[0]