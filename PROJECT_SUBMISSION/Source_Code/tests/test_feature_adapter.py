import pandas as pd
import pytest

from detection.feature_adapter import FeatureAdapter


BINARY_FEATURES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "AttackFamily",
]

FAMILY_FEATURES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
]


@pytest.fixture
def adapter():
    return FeatureAdapter(
        binary_feature_names=BINARY_FEATURES,
        family_feature_columns=FAMILY_FEATURES,
    )


@pytest.fixture
def dataframe():
    return pd.DataFrame(
        {
            "TotLen Bwd Pkts": [70.0],
            "Protocol": [6],
            "Dst Port": [22],
            "Tot Fwd Pkts": [10],
            "Flow Duration": [1000.0],
            "Tot Bwd Pkts": [8],
            "TotLen Fwd Pkts": [500.0],
        }
    )


def test_binary_features_are_in_exact_model_order(
    adapter,
    dataframe,
):
    result = adapter.to_binary_features(dataframe)

    assert list(result.columns) == BINARY_FEATURES
    assert result.shape == (1, len(BINARY_FEATURES))


def test_binary_attack_family_is_explicitly_zero(
    adapter,
    dataframe,
):
    result = adapter.to_binary_features(dataframe)

    assert "AttackFamily" in result.columns
    assert result["AttackFamily"].tolist() == [0]


def test_family_features_exclude_attack_family(
    adapter,
    dataframe,
):
    result = adapter.to_family_features(dataframe)

    assert list(result.columns) == FAMILY_FEATURES
    assert "AttackFamily" not in result.columns
    assert result.shape == (1, len(FAMILY_FEATURES))


def test_binary_array_has_correct_shape(
    adapter,
    dataframe,
):
    result = adapter.to_binary_array(dataframe)

    assert result.shape == (1, len(BINARY_FEATURES))


def test_family_array_has_correct_shape(
    adapter,
    dataframe,
):
    result = adapter.to_family_array(dataframe)

    assert result.shape == (1, len(FAMILY_FEATURES))


def test_missing_feature_is_rejected(
    adapter,
    dataframe,
):
    dataframe = dataframe.drop(columns=["Protocol"])

    with pytest.raises(
        ValueError,
        match="missing required features",
    ):
        adapter.to_binary_features(dataframe)


def test_invalid_dataframe_type_is_rejected(adapter):
    with pytest.raises(
        TypeError,
        match="pandas DataFrame",
    ):
        adapter.to_binary_features(
            {"Protocol": 6}
        )


def test_feature_counts(adapter):
    counts = adapter.feature_counts()

    assert counts == {
        "binary": len(BINARY_FEATURES),
        "family": len(FAMILY_FEATURES),
    }


def test_original_dataframe_is_not_modified(
    adapter,
    dataframe,
):
    original_columns = list(dataframe.columns)

    adapter.to_binary_features(dataframe)

    assert list(dataframe.columns) == original_columns