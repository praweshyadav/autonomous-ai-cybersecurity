import joblib
import pandas as pd
import pytest

from detection.feature_adapter import FeatureAdapter


BINARY_MODEL_PATH = (
    "detection/models/xgboost_binary_detector.joblib"
)

FAMILY_MODEL_PATH = (
    "detection/models/xgboost_attack_family_classifier.joblib"
)


@pytest.fixture
def adapter():
    binary_package = joblib.load(BINARY_MODEL_PATH)
    family_package = joblib.load(FAMILY_MODEL_PATH)

    return FeatureAdapter(
        binary_feature_names=binary_package["feature_names"],
        family_feature_columns=family_package["feature_columns"],
    )


@pytest.fixture
def real_feature_dataframe(adapter):
    """
    Create a dataframe containing every real model feature.

    Values are placeholders only. This test verifies schema
    handling, ordering, and feature separation.
    """
    values = {
        feature: 1.0
        for feature in adapter.binary_feature_names
    }

    return pd.DataFrame([values])


def test_real_binary_schema_has_79_features(adapter):
    assert len(adapter.binary_feature_names) == 79


def test_real_family_schema_has_78_features(adapter):
    assert len(adapter.family_feature_columns) == 78


def test_real_binary_schema_contains_attack_family(adapter):
    assert "AttackFamily" in adapter.binary_feature_names


def test_real_family_schema_excludes_attack_family(adapter):
    assert "AttackFamily" not in adapter.family_feature_columns


def test_real_binary_features_preserve_exact_order(
    adapter,
    real_feature_dataframe,
):
    result = adapter.to_binary_features(
        real_feature_dataframe
    )

    assert list(result.columns) == (
        adapter.binary_feature_names
    )

    assert result.shape == (1, 79)


def test_real_family_features_preserve_exact_order(
    adapter,
    real_feature_dataframe,
):
    result = adapter.to_family_features(
        real_feature_dataframe
    )

    assert list(result.columns) == (
        adapter.family_feature_columns
    )

    assert result.shape == (1, 78)


def test_real_binary_array_shape(
    adapter,
    real_feature_dataframe,
):
    result = adapter.to_binary_array(
        real_feature_dataframe
    )

    assert result.shape == (1, 79)


def test_real_family_array_shape(
    adapter,
    real_feature_dataframe,
):
    result = adapter.to_family_array(
        real_feature_dataframe
    )

    assert result.shape == (1, 78)


def test_real_schema_feature_relationship(adapter):
    binary_features = set(
        adapter.binary_feature_names
    )

    family_features = set(
        adapter.family_feature_columns
    )

    assert family_features.issubset(
        binary_features
    )

    assert binary_features - family_features == {
        "AttackFamily"
    }


def test_missing_real_feature_is_rejected(
    adapter,
    real_feature_dataframe,
):
    missing_feature = adapter.binary_feature_names[0]

    dataframe = real_feature_dataframe.drop(
        columns=[missing_feature]
    )

    with pytest.raises(
        ValueError,
        match="missing required features",
    ):
        adapter.to_binary_features(dataframe)