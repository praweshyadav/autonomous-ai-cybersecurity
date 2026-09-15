import json

from rag.documents.mitre_parser import MitreAttackParser


def test_mitre_parser_extracts_attack_patterns(tmp_path):
    mitre_file = tmp_path / "enterprise-attack.json"

    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test",
                "name": "Brute Force",
                "description": "Repeated authentication attempts.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1110",
                        "url": "https://attack.mitre.org/techniques/T1110/",
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "credential-access",
                    }
                ],
                "x_mitre_platforms": [
                    "Windows",
                    "Linux",
                ],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--test",
                "name": "Some Mitigation",
                "description": "Not a technique.",
            },
        ]
    }

    mitre_file.write_text(
        json.dumps(bundle),
        encoding="utf-8",
    )

    parser = MitreAttackParser(mitre_file)

    documents = parser.parse()

    assert len(documents) == 1

    document = documents[0]

    assert document.document_id == "T1110"

    assert document.title == "T1110 - Brute Force"

    assert "Technique ID: T1110" in document.content

    assert "Technique Name: Brute Force" in document.content

    assert (
        "Repeated authentication attempts."
        in document.content
    )

    assert "Credential Access" in document.content

    assert "Windows, Linux" in document.content

    assert (
        "https://attack.mitre.org/techniques/T1110/"
        in document.content
    )


def test_mitre_parser_skips_revoked_and_deprecated(tmp_path):
    mitre_file = tmp_path / "enterprise-attack.json"

    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Revoked Technique",
                "description": "Should not be included.",
                "revoked": True,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Deprecated Technique",
                "description": "Should not be included.",
                "x_mitre_deprecated": True,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9998",
                    }
                ],
            },
        ]
    }

    mitre_file.write_text(
        json.dumps(bundle),
        encoding="utf-8",
    )

    parser = MitreAttackParser(mitre_file)

    documents = parser.parse()

    assert documents == []