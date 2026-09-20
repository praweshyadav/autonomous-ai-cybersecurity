from pydantic import BaseModel, Field


class IncidentSummary(BaseModel):
    incident_id: str
    start_time: str
    end_time: str
    severity: str
    primary_attack_family: str
    confidence: float
    event_count: int
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    destination_ports: list[int] = Field(default_factory=list)
    protocols: list[int] = Field(default_factory=list)
    family_distribution: dict[str, int] = Field(default_factory=dict)
