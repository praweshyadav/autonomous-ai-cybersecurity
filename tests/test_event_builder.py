from datetime import datetime

import pandas as pd

from correlation.event_builder import build_security_event


def test_build_security_event():

    row = pd.Series({
        "Timestamp": "14/02/2018 10:35:12",
        "Dst Port": 22,
        "Protocol": 6,
        "SourceFile": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    })

    event = build_security_event(
        row=row,
        event_id="E000001",
        attack_family="Brute Force",
        confidence=0.97,
        binary_prediction=1,
        true_label="SSH-Bruteforce",
    )

    assert event.event_id == "E000001"

    assert event.timestamp == datetime(
        2018,
        2,
        14,
        10,
        35,
        12,
    )

    assert event.dst_port == 22
    assert event.protocol == 6

    assert event.binary_prediction == 1
    assert event.attack_family == "Brute Force"
    assert event.confidence == 0.97

    assert (
        event.source_file
        == "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv"
    )

    assert event.true_label == "SSH-Bruteforce"

    # Current common processed dataset does not contain these.
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.src_port is None