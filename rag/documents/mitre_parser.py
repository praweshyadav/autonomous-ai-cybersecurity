import json
from pathlib import Path

from rag.documents.loader import KnowledgeDocument


class MitreAttackParser:
    """
    Parses the official MITRE ATT&CK Enterprise STIX dataset
    into KnowledgeDocument objects.
    """

    def __init__(self, json_path: str | Path):
        self.json_path = Path(json_path)

    def parse(self) -> list[KnowledgeDocument]:
        """
        Parse Enterprise ATT&CK STIX JSON and return
        attack techniques as knowledge documents.
        """

        if not self.json_path.exists():
            raise FileNotFoundError(
                f"MITRE ATT&CK file not found: {self.json_path}"
            )

        with self.json_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            bundle = json.load(file)

        objects = bundle.get("objects", [])

        documents = []

        for obj in objects:

            if obj.get("type") != "attack-pattern":
                continue

            if obj.get("revoked", False):
                continue

            if obj.get("x_mitre_deprecated", False):
                continue

            external_id = self._get_external_id(obj)

            if not external_id:
                continue

            name = obj.get("name", "").strip()

            description = obj.get("description", "").strip()

            if not name or not description:
                continue

            tactics = self._get_tactics(obj)

            platforms = obj.get(
                "x_mitre_platforms",
                [],
            )

            references = self._get_references(obj)

            content = self._build_content(
                external_id=external_id,
                name=name,
                description=description,
                tactics=tactics,
                platforms=platforms,
                references=references,
            )

            documents.append(
                KnowledgeDocument(
                    document_id=external_id,
                    title=f"{external_id} - {name}",
                    source=str(self.json_path),
                    content=content,
                )
            )

        return documents

    @staticmethod
    def _get_external_id(obj: dict) -> str | None:
        """
        Extract the MITRE ATT&CK external technique ID.
        """

        for reference in obj.get("external_references", []):

            source_name = reference.get(
                "source_name"
            )

            external_id = reference.get(
                "external_id"
            )

            if (
                source_name == "mitre-attack"
                and external_id
                and external_id.startswith("T")
            ):
                return external_id

        return None

    @staticmethod
    def _get_tactics(obj: dict) -> list[str]:
        """
        Extract ATT&CK tactic names from kill_chain_phases.
        """

        tactics = []

        for phase in obj.get(
            "kill_chain_phases",
            [],
        ):
            phase_name = phase.get(
                "phase_name"
            )

            if phase_name:
                tactics.append(
                    phase_name.replace("-", " ").title()
                )

        return sorted(set(tactics))

    @staticmethod
    def _get_references(obj: dict) -> list[str]:
        """
        Extract external reference URLs.
        """

        references = []

        for reference in obj.get(
            "external_references",
            [],
        ):
            url = reference.get("url")

            if url:
                references.append(url)

        return references

    @staticmethod
    def _build_content(
        external_id: str,
        name: str,
        description: str,
        tactics: list[str],
        platforms: list[str],
        references: list[str],
    ) -> str:
        """
        Build a clean text representation suitable for
        downstream chunking and embedding.
        """

        lines = [
            f"Technique ID: {external_id}",
            f"Technique Name: {name}",
            "",
            "Description:",
            description,
            "",
            "Tactics:",
            ", ".join(tactics) if tactics else "Not specified",
            "",
            "Platforms:",
            ", ".join(platforms) if platforms else "Not specified",
            "",
            "References:",
        ]

        if references:
            lines.extend(
                f"- {reference}"
                for reference in references
            )
        else:
            lines.append("None")

        return "\n".join(lines)