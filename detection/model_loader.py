from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib


@dataclass
class BinaryModelBundle:
    """
    Loaded binary detection model and its expected features.
    """

    model: Any
    feature_names: list[str]


@dataclass
class AttackFamilyModelBundle:
    """
    Loaded attack-family classifier and its metadata.
    """

    model: Any
    label_encoder: Any
    feature_columns: list[str]


class DetectionModelLoader:
    """
    Loads and validates the trained detection models.

    Expected binary package:

        {
            "model": ...,
            "feature_names": [...]
        }

    Expected attack-family package:

        {
            "model": ...,
            "label_encoder": ...,
            "feature_columns": [...]
        }
    """

    def load_binary_model(
        self,
        model_path: str | Path,
    ) -> BinaryModelBundle:
        """
        Load and validate the binary XGBoost detector.
        """
        package = self._load_package(
            model_path,
            "binary detection model",
        )

        self._require_keys(
            package,
            required={"model", "feature_names"},
            model_type="binary detection model",
        )

        feature_names = package["feature_names"]

        self._validate_feature_names(
            feature_names,
            field_name="feature_names",
        )

        return BinaryModelBundle(
            model=package["model"],
            feature_names=list(feature_names),
        )

    def load_attack_family_model(
        self,
        model_path: str | Path,
    ) -> AttackFamilyModelBundle:
        """
        Load and validate the attack-family classifier.
        """
        package = self._load_package(
            model_path,
            "attack-family model",
        )

        self._require_keys(
            package,
            required={
                "model",
                "label_encoder",
                "feature_columns",
            },
            model_type="attack-family model",
        )

        feature_columns = package["feature_columns"]

        self._validate_feature_names(
            feature_columns,
            field_name="feature_columns",
        )

        if not hasattr(package["label_encoder"], "classes_"):
            raise ValueError(
                "Attack-family model label_encoder must expose "
                "a 'classes_' attribute."
            )

        return AttackFamilyModelBundle(
            model=package["model"],
            label_encoder=package["label_encoder"],
            feature_columns=list(feature_columns),
        )

    @staticmethod
    def _load_package(
        model_path: str | Path,
        model_type: str,
    ) -> dict[str, Any]:
        """
        Load a joblib model package.
        """
        if not model_path:
            raise ValueError(
                f"{model_type} path cannot be empty."
            )

        path = Path(model_path)

        if not path.exists():
            raise FileNotFoundError(
                f"{model_type} file not found: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"{model_type} path is not a file: {path}"
            )

        try:
            package = joblib.load(path)
        except Exception as exc:
            raise ValueError(
                f"Failed to load {model_type}: {path}"
            ) from exc

        if not isinstance(package, dict):
            raise ValueError(
                f"{model_type} must be stored as a dictionary package."
            )

        return package

    @staticmethod
    def _require_keys(
        package: dict[str, Any],
        required: set[str],
        model_type: str,
    ) -> None:
        """
        Ensure a model package contains the required fields.
        """
        missing = required - set(package.keys())

        if missing:
            missing_text = ", ".join(sorted(missing))

            raise ValueError(
                f"{model_type} is missing required fields: "
                f"{missing_text}"
            )

    @staticmethod
    def _validate_feature_names(
        feature_names: Any,
        field_name: str,
    ) -> None:
        """
        Validate model feature metadata.
        """
        if not isinstance(feature_names, (list, tuple)):
            raise ValueError(
                f"{field_name} must be a list or tuple."
            )

        if not feature_names:
            raise ValueError(
                f"{field_name} cannot be empty."
            )

        if not all(
            isinstance(name, str) and name.strip()
            for name in feature_names
        ):
            raise ValueError(
                f"All {field_name} entries must be non-empty strings."
            )

        if len(set(feature_names)) != len(feature_names):
            raise ValueError(
                f"{field_name} contains duplicate feature names."
            )