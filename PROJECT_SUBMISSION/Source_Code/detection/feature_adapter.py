from typing import Any

import pandas as pd


class FeatureAdapter:
    """
    Converts network-flow records into the exact feature schemas
    expected by the trained detection models.

    Binary detector:
        79 features.
        The final feature, AttackFamily, is retained only because
        the saved model artifact expects it. The trained binary
        model does not use this feature.

    Attack-family classifier:
        78 features.
        Does not include AttackFamily.

    The adapter never fabricates network-flow measurements.
    """

    def __init__(
        self,
        binary_feature_names: list[str],
        family_feature_columns: list[str],
    ) -> None:
        if not isinstance(binary_feature_names, list):
            raise TypeError(
                "binary_feature_names must be a list."
            )

        if not isinstance(family_feature_columns, list):
            raise TypeError(
                "family_feature_columns must be a list."
            )

        if not binary_feature_names:
            raise ValueError(
                "binary_feature_names cannot be empty."
            )

        if not family_feature_columns:
            raise ValueError(
                "family_feature_columns cannot be empty."
            )

        if len(binary_feature_names) != len(
            set(binary_feature_names)
        ):
            raise ValueError(
                "binary_feature_names contains duplicates."
            )

        if len(family_feature_columns) != len(
            set(family_feature_columns)
        ):
            raise ValueError(
                "family_feature_columns contains duplicates."
            )

        binary_features = set(binary_feature_names)
        family_features = set(family_feature_columns)

        if not family_features.issubset(binary_features):
            raise ValueError(
                "Family-model features must be a subset "
                "of binary-model features."
            )

        binary_only = (
            binary_features - family_features
        )

        if binary_only != {"AttackFamily"}:
            raise ValueError(
                "The binary/family feature difference must "
                "contain only 'AttackFamily'."
            )

        self.binary_feature_names = list(
            binary_feature_names
        )

        self.family_feature_columns = list(
            family_feature_columns
        )

    def validate_columns(
        self,
        dataframe: pd.DataFrame,
    ) -> None:
        """
        Validate that all genuine network-flow features required
        by the family model are present.
        """
        if not isinstance(dataframe, pd.DataFrame):
            raise TypeError(
                "dataframe must be a pandas DataFrame."
            )

        required_features = set(
            self.family_feature_columns
        )

        missing = required_features - set(
            dataframe.columns
        )

        if missing:
            raise ValueError(
                "Input dataframe is missing required "
                f"features: {sorted(missing)}"
            )

    def to_family_features(
        self,
        dataframe: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Return the genuine 78 CIC-IDS features in the exact
        order expected by the attack-family classifier.
        """
        self.validate_columns(dataframe)

        return dataframe[
            self.family_feature_columns
        ].copy()

    def to_binary_features(
        self,
        dataframe: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Return the 79 features expected by the saved binary model.

        AttackFamily is explicitly set to 0 because:
        1. it is not a genuine pre-detection feature,
        2. using ground truth would cause leakage,
        3. the saved binary model has zero feature importance
           for AttackFamily.
        """
        self.validate_columns(dataframe)

        result = dataframe[
            self.family_feature_columns
        ].copy()

        result["AttackFamily"] = 0

        return result[
            self.binary_feature_names
        ]

    def to_binary_array(
        self,
        dataframe: pd.DataFrame,
    ):
        """
        Return binary detector features as a NumPy array.
        """
        return self.to_binary_features(
            dataframe
        ).to_numpy()

    def to_family_array(
        self,
        dataframe: pd.DataFrame,
    ):
        """
        Return attack-family features as a NumPy array.
        """
        return self.to_family_features(
            dataframe
        ).to_numpy()

    def feature_counts(self) -> dict[str, int]:
        """
        Return expected feature counts.
        """
        return {
            "binary": len(
                self.binary_feature_names
            ),
            "family": len(
                self.family_feature_columns
            ),
        }