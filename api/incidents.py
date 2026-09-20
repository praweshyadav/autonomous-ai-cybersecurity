from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_auth
from api.schemas import IncidentSummary
from persistence.incident_repository import IncidentRepository
import os


DEFAULT_DATABASE_URL = os.getenv("DATABASE_URL")

if not DEFAULT_DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not configured."
    )


router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["incidents"],
    dependencies=[Depends(require_auth)],
)


def _get_repository() -> IncidentRepository:
    return IncidentRepository(database_url=DEFAULT_DATABASE_URL)


def _to_summary(incident) -> IncidentSummary:
    return IncidentSummary(
        incident_id=incident.incident_id,
        start_time=incident.start_time.isoformat(),
        end_time=incident.end_time.isoformat(),
        severity=incident.severity,
        primary_attack_family=incident.primary_attack_family or "Unknown",
        confidence=float(incident.confidence),
        event_count=len(incident.events),
        source_ips=sorted(incident.src_ips),
        destination_ips=sorted(incident.dst_ips),
        destination_ports=sorted(incident.dst_ports),
        protocols=sorted(incident.protocols),
        family_distribution=dict(incident.family_distribution),
    )


@router.get("", response_model=list[IncidentSummary])
def list_incidents(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[IncidentSummary]:
    repository = _get_repository()
    incidents = repository.list_recent(limit=limit)
    return [_to_summary(incident) for incident in incidents]


@router.get("/{incident_id}", response_model=IncidentSummary)
def get_incident(incident_id: str) -> IncidentSummary:
    repository = _get_repository()
    incident = repository.get_by_id(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' not found.",
        )

    return _to_summary(incident)
