import numpy as np

from rag.embeddings import EmbeddingModel


def test_embedding_model_generates_vectors():
    model = EmbeddingModel()

    texts = [
        "Brute force attacks repeatedly attempt authentication.",
        "Denial of service attacks overwhelm a target system.",
    ]

    embeddings = model.encode(texts)

    assert isinstance(embeddings, np.ndarray)

    assert embeddings.shape[0] == 2
    assert embeddings.shape[1] > 0

    assert np.isfinite(embeddings).all()


def test_embedding_model_generates_single_vector():
    model = EmbeddingModel()

    embedding = model.encode_one(
        "FTP brute force attack against a server."
    )

    assert isinstance(embedding, np.ndarray)

    assert embedding.ndim == 1
    assert embedding.shape[0] > 0

    assert np.isfinite(embedding).all()


def test_empty_input_returns_empty_result():
    model = EmbeddingModel()

    embeddings = model.encode([])

    assert embeddings == []