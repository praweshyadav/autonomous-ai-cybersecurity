import json
import re
from urllib import error, request

from agent.llm_contract import (
    AgentHypothesis,
    AgentTechniqueAssessment,
    LLMInvestigationInput,
    LLMInvestigationOutput,
)
from agent.llm_provider import LLMProvider


class OllamaLLMProvider(LLMProvider):
    """
    Local Ollama provider.

    Sends controlled investigation context to a local
    Ollama server and converts the response into the
    LLMInvestigationOutput contract.

    The LLM is treated as an untrusted component.
    Its output is strictly validated before being
    converted into the trusted application contract.
    """

    def __init__(
        self,
        model: str = "gemma3:4b",
        base_url: str = "http://127.0.0.1:11434",
        timeout: int = 120,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def investigate(
        self,
        investigation_input: LLMInvestigationInput,
    ) -> LLMInvestigationOutput:

        prompt = self._build_prompt(
            investigation_input
        )

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity investigation "
                        "assistant. Analyze only the evidence "
                        "provided to you. Do not invent evidence. "
                        "Return valid JSON only."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0,
            },
        }

        response_data = self._request(
            payload
        )

        content = (
            response_data
            .get("message", {})
            .get("content", "")
        )

        if not content:
            raise ValueError(
                "Ollama returned an empty response."
            )

        return self._parse_output(
            content,
            investigation_input,
        )

    def _request(
        self,
        payload: dict,
    ) -> dict:

        body = json.dumps(
            payload
        ).encode("utf-8")

        http_request = request.Request(
            url=f"{self.base_url}/api/chat",
            data=body,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with request.urlopen(
                http_request,
                timeout=self.timeout,
            ) as response:

                response_body = (
                    response.read()
                    .decode("utf-8")
                )

        except error.URLError as exc:
            raise RuntimeError(
                "Could not connect to Ollama at "
                f"{self.base_url}. "
                "Make sure 'ollama serve' is running."
            ) from exc

        try:
            return json.loads(
                response_body
            )

        except json.JSONDecodeError as exc:
            raise ValueError(
                "Ollama returned invalid JSON."
            ) from exc

    def _build_prompt(
        self,
        investigation_input: LLMInvestigationInput,
    ) -> str:

        evidence = [
            {
                "evidence_id": item.evidence_id,
                "source": item.source,
                "description": item.description,
                "evidence_type": item.evidence_type,
            }
            for item in investigation_input.evidence
        ]

        techniques = [
            {
                "technique_id": item.technique_id,
                "technique_name": item.technique_name,
                "relevance": item.relevance,
                "relevance_score": item.relevance_score,
                "reason": item.reason,
            }
            for item in (
                investigation_input.mitre_techniques
            )
        ]

        incident = {
                    "incident_id": investigation_input.incident_id,
                    "severity": investigation_input.severity,
                    "primary_attack_family": (
                        investigation_input.primary_attack_family
                    ),
                    "attack_families": (
                        investigation_input.attack_families
                    ),
                    "event_count": (
                        investigation_input.event_count
                    ),
                    "duration_seconds": (
                        investigation_input.duration_seconds
                    ),
                    "confidence": (
                        investigation_input.confidence
                    ),
                    "family_distribution": (
                        investigation_input.family_distribution
                    ),
                    "protocols": (
                        investigation_input.protocols
                    ),
                    "destination_ports": (
                        investigation_input.destination_ports
                    ),
                    "source_ips": (
                        investigation_input.source_ips
                    ),
                    "destination_ips": (
                        investigation_input.destination_ips
                    ),
                }

        output_schema = {
            "incident_id": "string",
            "summary": "string",
            "threat_assessment": "string",
            "hypotheses": [
                {
                    "hypothesis": "string",
                    "supporting_evidence_ids": [
                        "E001"
                    ],
                    "contradicting_evidence_ids": [],
                    "confidence": 0.0,
                }
            ],
            "technique_assessments": [
                {
                    "technique_id": "T1110",
                    "technique_name": "T1110 - Brute Force",
                    "assessment": "string",
                    "supporting_evidence_ids": [
                        "E001"
                    ],
                    "confidence": 0.0,
                }
            ],
            "evidence_gaps": [
                "string"
            ],
            "next_investigation_steps": [
                "string"
            ],
            "recommended_actions": [
                "string"
            ],
            "confidence": 0.0,
            "uncertainty": [
                "string"
            ],
        }

        return (
            "Investigation goal:\n"
            f"{investigation_input.investigation_goal}\n\n"
            "Incident:\n"
            f"{json.dumps(incident, indent=2)}\n\n"
            "Observed and evaluated evidence:\n"
            f"{json.dumps(evidence, indent=2)}\n\n"
            "Relevant MITRE ATT&CK techniques:\n"
            f"{json.dumps(techniques, indent=2)}\n\n"
            "Rules:\n"
            "1. Use only the supplied evidence.\n"
            "2. Do not invent IPs, hosts, users, "
            "commands, timestamps, or attack behavior.\n"
            "3. Treat hypotheses as hypotheses, not facts.\n"
            "4. Only assess MITRE techniques supplied above.\n"
            "5. For every technique assessment, copy the "
            "`technique_id` and `technique_name` EXACTLY from "
            "the supplied MITRE ATT&CK techniques list.\n"
            "   - `technique_id` and `technique_name` are separate fields.\n"
            "   - Never combine them into one field.\n"
            "   - If the supplied values are "
            "`technique_id='T1110'` and "
            "`technique_name='Brute Force'`, return exactly "
            "`'T1110'` and `'Brute Force'`.\n"
            "   - Do not return `'T1110 - Brute Force'` as the "
            "`technique_name` unless that exact string was supplied "
            "as the technique_name.\n"
            "   - Do not shorten, rename, paraphrase, or modify either value.\n"
            "6. Confidence values must reflect the strength of the "
            "supplied evidence. Do not use 0.0 when the supplied "
            "evidence supports the conclusion. Use a value between "
            "0.0 and 1.0 that represents your evidence-based "
            "assessment, not the confidence of the detection engine.\n"
            "7. Do not execute or request execution of actions.\n"
            "8. Return JSON matching this structure:\n"
            f"{json.dumps(output_schema, indent=2)}"
        )

    def _parse_output(
        self,
        content: str,
        investigation_input: LLMInvestigationInput,
    ) -> LLMInvestigationOutput:

        try:
            data = json.loads(content)

        except json.JSONDecodeError as exc:
            raise ValueError(
                "LLM returned invalid JSON."
            ) from exc

        self._validate_output(
            data,
            investigation_input,
        )

        hypotheses = [
            AgentHypothesis(
                hypothesis=item["hypothesis"],
                supporting_evidence_ids=item.get(
                    "supporting_evidence_ids",
                    [],
                ),
                contradicting_evidence_ids=item.get(
                    "contradicting_evidence_ids",
                    [],
                ),
                confidence=float(
                    item.get(
                        "confidence",
                        0.0,
                    )
                ),
            )
            for item in data.get(
                "hypotheses",
                [],
            )
        ]

        technique_assessments = [
            AgentTechniqueAssessment(
                technique_id=item["technique_id"],
                technique_name=item[
                    "technique_name"
                ],
                assessment=item["assessment"],
                supporting_evidence_ids=item.get(
                    "supporting_evidence_ids",
                    [],
                ),
                confidence=float(
                    item.get(
                        "confidence",
                        0.0,
                    )
                ),
            )
            for item in data.get(
                "technique_assessments",
                [],
            )
        ]

        return LLMInvestigationOutput(
            incident_id=data["incident_id"],
            summary=data["summary"],
            threat_assessment=data[
                "threat_assessment"
            ],
            hypotheses=hypotheses,
            technique_assessments=(
                technique_assessments
            ),
            evidence_gaps=data.get(
                "evidence_gaps",
                [],
            ),
            next_investigation_steps=data.get(
                "next_investigation_steps",
                [],
            ),
            recommended_actions=data.get(
                "recommended_actions",
                [],
            ),
            confidence=float(
                data.get(
                    "confidence",
                    0.0,
                )
            ),
            uncertainty=data.get(
                "uncertainty",
                [],
            ),
            metadata={
                "provider": "ollama",
                "model": self.model,
            },
        )

    # ==========================================================
    # IP ADDRESS GROUNDING
    # ==========================================================

    @staticmethod
    def _extract_ipv4_addresses(text: str) -> set[str]:
        """
        Extract IPv4 addresses from free-form text.
        """

        if not isinstance(text, str):
            return set()

        pattern = (
            r"\b(?:"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"\b"
        )

        return set(
            re.findall(
                pattern,
                text,
            )
        )

    @classmethod
    def _validate_ip_grounding(
        cls,
        data: dict,
        investigation_input: LLMInvestigationInput,
    ) -> None:
        """
        Reject IP addresses introduced by the LLM that were
        not present in the supplied investigation input.
        """

        allowed_ips = set(
            investigation_input.source_ips
            + investigation_input.destination_ips
        )

        text_fields = [
            data.get(
                "summary",
                "",
            ),
            data.get(
                "threat_assessment",
                "",
            ),
        ]

        for hypothesis in data.get(
            "hypotheses",
            [],
        ):
            if isinstance(
                hypothesis,
                dict,
            ):
                text_fields.append(
                    hypothesis.get(
                        "hypothesis",
                        "",
                    )
                )

        for assessment in data.get(
            "technique_assessments",
            [],
        ):
            if isinstance(
                assessment,
                dict,
            ):
                text_fields.append(
                    assessment.get(
                        "assessment",
                        "",
                    )
                )

        for field in [
            "evidence_gaps",
            "next_investigation_steps",
            "recommended_actions",
            "uncertainty",
        ]:
            for value in data.get(
                field,
                [],
            ):
                if isinstance(
                    value,
                    str,
                ):
                    text_fields.append(value)

        observed_ips = set()

        for text in text_fields:
            observed_ips.update(
                cls._extract_ipv4_addresses(
                    text
                )
            )

        unknown_ips = (
            observed_ips - allowed_ips
        )

        if unknown_ips:
            raise ValueError(
                "LLM introduced unsupported IP address(es): "
                + ", ".join(
                    sorted(unknown_ips)
                )
            )

    def _validate_output(
        self,
        data: dict,
        investigation_input: LLMInvestigationInput,
    ):
        """
        Strictly validate the LLM output before converting
        it into the trusted investigation contract.

        The LLM is treated as an untrusted component.
        It must never be allowed to introduce unknown
        evidence, MITRE techniques, invalid confidence values,
        unsupported IP addresses, or malformed structures.
        """

        if not isinstance(data, dict):
            raise ValueError(
                "LLM output must be a JSON object."
            )

        # --------------------------------------------------
        # IP grounding
        # --------------------------------------------------

        self._validate_ip_grounding(
            data,
            investigation_input,
        )

        # --------------------------------------------------
        # Required top-level fields
        # --------------------------------------------------

        required_fields = [
            "incident_id",
            "summary",
            "threat_assessment",
        ]

        for field in required_fields:
            if field not in data:
                raise ValueError(
                    f"LLM output missing required field: {field}"
                )

        # --------------------------------------------------
        # Required field types
        # --------------------------------------------------

        if not isinstance(
            data["incident_id"],
            str,
        ):
            raise ValueError(
                "LLM incident_id must be a string."
            )

        if not isinstance(
            data["summary"],
            str,
        ):
            raise ValueError(
                "LLM summary must be a string."
            )

        if not isinstance(
            data["threat_assessment"],
            str,
        ):
            raise ValueError(
                "LLM threat_assessment must be a string."
            )

        # --------------------------------------------------
        # Incident ID integrity
        # --------------------------------------------------

        if (
            data["incident_id"]
            != investigation_input.incident_id
        ):
            raise ValueError(
                "LLM returned an unexpected incident_id."
            )

        # --------------------------------------------------
        # Top-level confidence
        # --------------------------------------------------

        try:
            confidence = float(
                data.get(
                    "confidence",
                    0.0,
                )
            )

        except (TypeError, ValueError) as exc:
            raise ValueError(
                "LLM confidence must be a number."
            ) from exc

        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "LLM confidence must be between 0 and 1."
            )

        # --------------------------------------------------
        # Optional list fields
        # --------------------------------------------------

        list_fields = [
            "hypotheses",
            "technique_assessments",
            "evidence_gaps",
            "next_investigation_steps",
            "recommended_actions",
            "uncertainty",
        ]

        for field in list_fields:
            if field in data and not isinstance(
                data[field],
                list,
            ):
                raise ValueError(
                    f"LLM field '{field}' must be a list."
                )

        # --------------------------------------------------
        # Valid evidence IDs
        # --------------------------------------------------

        valid_evidence = {
            evidence.evidence_id
            for evidence in (
                investigation_input.evidence
            )
        }

        # --------------------------------------------------
        # Validate hypotheses
        # --------------------------------------------------

        for hypothesis in data.get(
            "hypotheses",
            [],
        ):

            if not isinstance(
                hypothesis,
                dict,
            ):
                raise ValueError(
                    "Each hypothesis must be a JSON object."
                )

            if "hypothesis" not in hypothesis:
                raise ValueError(
                    "LLM hypothesis is missing the "
                    "'hypothesis' field."
                )

            if not isinstance(
                hypothesis["hypothesis"],
                str,
            ):
                raise ValueError(
                    "LLM hypothesis must be a string."
                )

            supporting_ids = hypothesis.get(
                "supporting_evidence_ids",
                [],
            )

            contradicting_ids = hypothesis.get(
                "contradicting_evidence_ids",
                [],
            )

            if not isinstance(
                supporting_ids,
                list,
            ):
                raise ValueError(
                    "supporting_evidence_ids must be a list."
                )

            if not isinstance(
                contradicting_ids,
                list,
            ):
                raise ValueError(
                    "contradicting_evidence_ids must be a list."
                )

            evidence_ids = (
                supporting_ids
                + contradicting_ids
            )

            for evidence_id in evidence_ids:

                if evidence_id not in valid_evidence:
                    raise ValueError(
                        "LLM referenced unknown evidence ID: "
                        f"{evidence_id}"
                    )

            try:
                hypothesis_confidence = float(
                    hypothesis.get(
                        "confidence",
                        0.0,
                    )
                )

            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "Hypothesis confidence must be a number."
                ) from exc

            if not 0.0 <= hypothesis_confidence <= 1.0:
                raise ValueError(
                    "Hypothesis confidence must be "
                    "between 0 and 1."
                )

        # --------------------------------------------------
        # Valid MITRE techniques
        # --------------------------------------------------

        valid_techniques = {
            technique.technique_id: technique.technique_name
            for technique in (
                investigation_input.mitre_techniques
            )
        }

        # --------------------------------------------------
        # Validate MITRE assessments
        # --------------------------------------------------

        for item in data.get(
            "technique_assessments",
            [],
        ):

            if not isinstance(
                item,
                dict,
            ):
                raise ValueError(
                    "Each technique assessment must "
                    "be a JSON object."
                )

            required_technique_fields = [
                "technique_id",
                "technique_name",
                "assessment",
            ]

            for field in required_technique_fields:
                if field not in item:
                    raise ValueError(
                        "LLM technique assessment is missing "
                        f"the '{field}' field."
                    )

            technique_id = item.get(
                "technique_id"
            )

            if technique_id not in valid_techniques:
                raise ValueError(
                    "LLM referenced a MITRE technique "
                    "that was not supplied in the "
                    "investigation input: "
                    f"{technique_id}"
                )

            technique_name = item.get(
                "technique_name"
            )

            expected_name = valid_techniques[
                technique_id
            ]

            if technique_name != expected_name:
                prefixed_name = (
                    f"{technique_id} - {expected_name}"
                )

                if technique_name != prefixed_name:
                    raise ValueError(
                        "LLM returned a mismatched MITRE "
                        f"technique name for {technique_id}. "
                        f"Expected '{expected_name}', "
                        f"got '{technique_name}'."
                    )

            if not isinstance(
                item["assessment"],
                str,
            ):
                raise ValueError(
                    "MITRE assessment must be a string."
                )

            supporting_ids = item.get(
                "supporting_evidence_ids",
                [],
            )

            if not isinstance(
                supporting_ids,
                list,
            ):
                raise ValueError(
                    "MITRE supporting_evidence_ids "
                    "must be a list."
                )

            for evidence_id in supporting_ids:

                if evidence_id not in valid_evidence:
                    raise ValueError(
                        "LLM referenced unknown evidence ID: "
                        f"{evidence_id}"
                    )

            try:
                technique_confidence = float(
                    item.get(
                        "confidence",
                        0.0,
                    )
                )

            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "MITRE technique confidence must "
                    "be a number."
                ) from exc

            if not 0.0 <= technique_confidence <= 1.0:
                raise ValueError(
                    "MITRE technique confidence must "
                    "be between 0 and 1."
                )

        # --------------------------------------------------
        # Validate textual list fields
        # --------------------------------------------------

        for field in [
            "evidence_gaps",
            "next_investigation_steps",
            "recommended_actions",
            "uncertainty",
        ]:

            for value in data.get(
                field,
                [],
            ):

                if not isinstance(
                    value,
                    str,
                ):
                    raise ValueError(
                        f"Every item in '{field}' "
                        "must be a string."
                    )