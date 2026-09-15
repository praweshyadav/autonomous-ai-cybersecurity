from datetime import datetime, timezone

import pytest

from ingestion.normalizer import SecurityEventNormalizer


@pytest.fixture
def normalizer():
    return SecurityEventNormalizer()


def test_normalize_complete_event(normalizer):
    raw_event = {
        "event_id": "EVENT-001",
        "timestamp": "2018-02-14T10:30:15+00:00",
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.10",
        "src_port": 54321,
        "dst_port": 22,
        "protocol": 6,
        "protocol_name": "TCP",
        "binary_prediction": 1,
        "attack_family": "Brute Force",
        "confidence": 0.95,
        "source_file": "test.log",
        "true_label": "SSH-Bruteforce",
        "true_attack_family": "Brute Force",
        "event_type": "authentication_failure",
        "windows_event_id": 4625,
        "username": "admin",
        "domain": "UNIVERSITY",
        "process_name": "sshd",
        "firewall_action": "DENY",
        "raw_log": "example raw log",
        "metadata": {
            "server": "server01",
        },
    }

    event = normalizer.normalize(raw_event)

    assert event.event_id == "EVENT-001"
    assert event.timestamp == datetime(
        2018,
        2,
        14,
        10,
        30,
        15,
        tzinfo=timezone.utc,
    )

    assert event.src_ip == "192.168.1.50"
    assert event.dst_ip == "10.0.0.10"
    assert event.src_port == 54321
    assert event.dst_port == 22
    assert event.protocol == 6
    assert event.protocol_name == "TCP"

    assert event.binary_prediction == 1
    assert event.attack_family == "Brute Force"
    assert event.confidence == 0.95

    assert event.source_file == "test.log"
    assert event.true_label == "SSH-Bruteforce"
    assert event.true_attack_family == "Brute Force"

    assert event.event_type == "authentication_failure"
    assert event.windows_event_id == 4625
    assert event.username == "admin"
    assert event.domain == "UNIVERSITY"
    assert event.process_name == "sshd"

    assert event.firewall_action == "DENY"
    assert event.raw_log == "example raw log"

    assert event.metadata == {
        "server": "server01"
    }


def test_normalize_minimal_event(normalizer):
    raw_event = {
        "event_id": "EVENT-002",
        "timestamp": "2018-02-14T10:30:15",
    }

    event = normalizer.normalize(raw_event)

    assert event.event_id == "EVENT-002"
    assert event.timestamp == datetime(
        2018,
        2,
        14,
        10,
        30,
        15,
    )

    assert event.binary_prediction == 0
    assert event.attack_family == "Benign"
    assert event.confidence == 0.0

    assert event.event_type is None
    assert event.username is None
    assert event.process_name is None
    assert event.firewall_action is None
    assert event.raw_log is None
    assert event.metadata == {}


def test_datetime_timestamp(normalizer):
    timestamp = datetime(
        2018,
        2,
        14,
        10,
        30,
        15,
        tzinfo=timezone.utc,
    )

    raw_event = {
        "event_id": "EVENT-003",
        "timestamp": timestamp,
    }

    event = normalizer.normalize(raw_event)

    assert event.timestamp == timestamp


def test_missing_event_id(normalizer):
    raw_event = {
        "timestamp": "2018-02-14T10:30:15",
    }

    with pytest.raises(ValueError):
        normalizer.normalize(raw_event)


def test_invalid_timestamp(normalizer):
    raw_event = {
        "event_id": "EVENT-004",
        "timestamp": "not-a-timestamp",
    }

    with pytest.raises(ValueError):
        normalizer.normalize(raw_event)


def test_invalid_timestamp_type(normalizer):
    raw_event = {
        "event_id": "EVENT-005",
        "timestamp": 12345,
    }

    with pytest.raises(ValueError):
        normalizer.normalize(raw_event)


def test_invalid_integer(normalizer):
    raw_event = {
        "event_id": "EVENT-006",
        "timestamp": "2018-02-14T10:30:15",
        "src_port": "not-a-number",
    }

    with pytest.raises(ValueError):
        normalizer.normalize(raw_event)


def test_non_dict(normalizer):
    with pytest.raises(TypeError):
        normalizer.normalize("not a dictionary")


def test_string_numeric_normalization(normalizer):
    raw_event = {
        "event_id": "EVENT-007",
        "timestamp": "2018-02-14T10:30:15",
        "src_port": "54321",
        "dst_port": "22",
        "protocol": "6",
        "windows_event_id": "4625",
    }

    event = normalizer.normalize(raw_event)

    assert event.src_port == 54321
    assert event.dst_port == 22
    assert event.protocol == 6
    assert event.windows_event_id == 4625


def test_confidence_must_be_between_zero_and_one(
    normalizer,
):
    raw_event = {
        "event_id": "EVENT-008",
        "timestamp": "2018-02-14T10:30:15",
        "confidence": 1.5,
    }

    with pytest.raises(ValueError):
        normalizer.normalize(raw_event)


def test_negative_confidence_is_rejected(normalizer):
    raw_event = {
        "event_id": "EVENT-009",
        "timestamp": "2018-02-14T10:30:15",
        "confidence": -0.1,
    }

    with pytest.raises(ValueError):
        normalizer.normalize(raw_event)


def test_invalid_binary_prediction_is_rejected(
    normalizer,
):
    raw_event = {
        "event_id": "EVENT-010",
        "timestamp": "2018-02-14T10:30:15",
        "binary_prediction": 2,
    }

    with pytest.raises(ValueError):
        normalizer.normalize(raw_event)


def test_metadata_must_be_dictionary(normalizer):
    raw_event = {
        "event_id": "EVENT-011",
        "timestamp": "2018-02-14T10:30:15",
        "metadata": "invalid",
    }

    with pytest.raises(TypeError):
        normalizer.normalize(raw_event)