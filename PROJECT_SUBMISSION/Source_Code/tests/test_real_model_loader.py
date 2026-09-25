from pathlib import Path

from detection.model_loader import (
    AttackFamilyModelBundle,
    BinaryModelBundle,
    DetectionModelLoader,
)


BINARY_MODEL_PATH = Path(
    "detection/models/xgboost_binary_detector.joblib"
)

FAMILY_MODEL_PATH = Path(
    "detection/models/xgboost_attack_family_classifier.joblib"
)


def test_real_binary_model_exists():
    assert BINARY_MODEL_PATH.exists()
    assert BINARY_MODEL_PATH.is_file()


def test_real_attack_family_model_exists():
    assert FAMILY_MODEL_PATH.exists()
    assert FAMILY_MODEL_PATH.is_file()


def test_real_binary_model_loads():
    loader = DetectionModelLoader()

    bundle = loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    assert isinstance(bundle, BinaryModelBundle)
    assert bundle.model is not None
    assert len(bundle.feature_names) > 0


def test_real_binary_model_has_expected_feature_count():
    loader = DetectionModelLoader()

    bundle = loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    assert len(bundle.feature_names) in (78, 79)


def test_real_family_model_loads():
    loader = DetectionModelLoader()

    bundle = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    assert isinstance(
        bundle,
        AttackFamilyModelBundle,
    )

    assert bundle.model is not None
    assert bundle.label_encoder is not None
    assert len(bundle.feature_columns) > 0


def test_real_family_model_has_expected_feature_count():
    loader = DetectionModelLoader()

    bundle = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    assert len(bundle.feature_columns) == 78


def test_real_family_model_has_expected_labels():
    loader = DetectionModelLoader()

    bundle = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    labels = list(bundle.label_encoder.classes_)

    assert labels == [
        "Benign",
        "Brute Force",
        "DDoS",
        "DoS",
        "Web Attack",
    ]


def test_real_models_have_expected_feature_relationship():
    loader = DetectionModelLoader()

    binary = loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    family = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    binary_features = set(binary.feature_names)
    family_features = set(family.feature_columns)

    # The family classifier uses the common 78 network-flow
    # features. The binary detector additionally contains
    # the AttackFamily feature.
    assert family_features.issubset(binary_features)

    assert binary_features - family_features == {
        "AttackFamily"
    }


def test_real_models_have_unique_features():
    loader = DetectionModelLoader()

    binary = loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    family = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    assert len(binary.feature_names) == len(
        set(binary.feature_names)
    )

    assert len(family.feature_columns) == len(
        set(family.feature_columns)
    )