from pathlib import Path

import joblib
import pytest

from detection.model_loader import (
    AttackFamilyModelBundle,
    BinaryModelBundle,
    DetectionModelLoader,
)


class FakeLabelEncoder:
    classes_ = [
        "Benign",
        "Brute Force",
        "DDoS",
        "DoS",
        "Web Attack",
    ]


def test_load_binary_model(tmp_path):
    model_path = tmp_path / "binary.joblib"

    package = {
        "model": "fake-binary-model",
        "feature_names": [
            "feature_a",
            "feature_b",
            "feature_c",
        ],
    }

    joblib.dump(package, model_path)

    loader = DetectionModelLoader()

    result = loader.load_binary_model(model_path)

    assert isinstance(result, BinaryModelBundle)
    assert result.model == "fake-binary-model"
    assert result.feature_names == [
        "feature_a",
        "feature_b",
        "feature_c",
    ]


def test_load_attack_family_model(tmp_path):
    model_path = tmp_path / "family.joblib"

    label_encoder = FakeLabelEncoder()

    package = {
        "model": "fake-family-model",
        "label_encoder": label_encoder,
        "feature_columns": [
            "feature_a",
            "feature_b",
            "feature_c",
        ],
    }

    joblib.dump(package, model_path)

    loader = DetectionModelLoader()

    result = loader.load_attack_family_model(model_path)

    assert isinstance(result, AttackFamilyModelBundle)
    assert result.model == "fake-family-model"
    assert result.label_encoder is not None
    assert result.feature_columns == [
        "feature_a",
        "feature_b",
        "feature_c",
    ]


def test_missing_binary_model_file(tmp_path):
    loader = DetectionModelLoader()

    with pytest.raises(FileNotFoundError):
        loader.load_binary_model(
            tmp_path / "missing.joblib"
        )


def test_missing_family_model_file(tmp_path):
    loader = DetectionModelLoader()

    with pytest.raises(FileNotFoundError):
        loader.load_attack_family_model(
            tmp_path / "missing.joblib"
        )


def test_binary_model_requires_model_key(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "feature_names": ["feature_a"],
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="missing required fields",
    ):
        loader.load_binary_model(model_path)


def test_binary_model_requires_feature_names(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "model": "fake-model",
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="missing required fields",
    ):
        loader.load_binary_model(model_path)


def test_family_model_requires_all_keys(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "model": "fake-model",
            "feature_columns": ["feature_a"],
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="missing required fields",
    ):
        loader.load_attack_family_model(model_path)


def test_binary_feature_names_must_be_list_or_tuple(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "model": "fake-model",
            "feature_names": "feature_a",
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="must be a list or tuple",
    ):
        loader.load_binary_model(model_path)


def test_family_feature_columns_must_be_list_or_tuple(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "model": "fake-model",
            "label_encoder": FakeLabelEncoder(),
            "feature_columns": "feature_a",
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="must be a list or tuple",
    ):
        loader.load_attack_family_model(model_path)


def test_empty_feature_names_are_rejected(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "model": "fake-model",
            "feature_names": [],
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="cannot be empty",
    ):
        loader.load_binary_model(model_path)


def test_duplicate_feature_names_are_rejected(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "model": "fake-model",
            "feature_names": [
                "feature_a",
                "feature_a",
            ],
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="duplicate feature names",
    ):
        loader.load_binary_model(model_path)


def test_empty_model_path_is_rejected():
    loader = DetectionModelLoader()

    with pytest.raises(ValueError):
        loader.load_binary_model("")


def test_directory_path_is_rejected(tmp_path):
    loader = DetectionModelLoader()

    with pytest.raises(ValueError):
        loader.load_binary_model(tmp_path)


def test_non_dictionary_package_is_rejected(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        "not-a-dictionary",
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="must be stored as a dictionary",
    ):
        loader.load_binary_model(model_path)


def test_invalid_label_encoder_is_rejected(tmp_path):
    model_path = tmp_path / "invalid.joblib"

    joblib.dump(
        {
            "model": "fake-model",
            "label_encoder": object(),
            "feature_columns": ["feature_a"],
        },
        model_path,
    )

    loader = DetectionModelLoader()

    with pytest.raises(
        ValueError,
        match="label_encoder must expose",
    ):
        loader.load_attack_family_model(model_path)