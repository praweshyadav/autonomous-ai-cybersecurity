from datetime import datetime
from typing import Optional

import pandas as pd

from correlation.schema import SecurityEvent


# CIC-IDS features used by the trained models.
# AttackFamily is intentionally excluded here because it is
# a model-specific feature handled by the detection layer.
CIC_IDS_FLOW_FEATURES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


def build_security_event(
    row: pd.Series,
    event_id: str,
    attack_family: str,
    confidence: float,
    binary_prediction: int,
    true_label: Optional[str] = None,
) -> SecurityEvent:
    """
    Convert one normalized CIC-IDS network-flow row and its
    model predictions into a SecurityEvent.

    All CIC-IDS model features are preserved inside metadata so
    the detection layer can perform inference without fabricating
    missing values.
    """

    timestamp_value = row["Timestamp"]

    try:
        timestamp = pd.to_datetime(
            timestamp_value,
            format="%d/%m/%Y %H:%M:%S",
            errors="raise",
        )
    except (ValueError, TypeError):
        timestamp = pd.to_datetime(
            timestamp_value,
            format="%Y-%m-%d %H:%M:%S",
            errors="raise",
        )

      

    def optional_int(column: str):
        value = row.get(column)

        if pd.isna(value):
            return None

        return int(value)

    metadata = {}

    for feature in CIC_IDS_FLOW_FEATURES:
        if feature in row.index:
            value = row[feature]

            if pd.isna(value):
                metadata[feature] = None
            else:
                metadata[feature] = value

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp.to_pydatetime(),

        # These fields are unavailable in the current common
        # 80-column processed dataset.
        src_ip=None,
        dst_ip=None,
        src_port=None,

        dst_port=optional_int("Dst Port"),
        protocol=optional_int("Protocol"),

        binary_prediction=int(binary_prediction),
        attack_family=attack_family,
        confidence=float(confidence),

        source_file=row.get("SourceFile"),

        # Ground truth is retained only for offline evaluation.
        true_label=true_label,
        true_attack_family=None,

        event_type="network_flow",

        metadata=metadata,
    )
