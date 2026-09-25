from datetime import timedelta
from typing import List

from correlation.schema import SecurityEvent, Incident


class IncidentCorrelator:
    """
    Correlates individual security events into incidents.

    Correlation is based on multiple pieces of evidence:
        - Time proximity
        - Network protocol
        - Destination port
        - Source IP (when available)
        - Destination IP (when available)
        - Attack family

    Attack family is treated as evidence, not as an absolute
    requirement. This is important because the ML classifier
    can occasionally confuse attack families.
    """

    def __init__(
        self,
        time_window_seconds: int = 60,
        correlation_threshold: int = 4,
    ):
        self.time_window = timedelta(
            seconds=time_window_seconds
        )

        self.correlation_threshold = (
            correlation_threshold
        )

    # ========================================================
    # Correlation scoring
    # ========================================================

    def correlation_score(
        self,
        event_a: SecurityEvent,
        event_b: SecurityEvent,
    ) -> int:
        """
        Calculate an explainable correlation score between
        two security events.

        Higher score means stronger evidence that the events
        belong to the same incident.
        """

        # ----------------------------------------------------
        # Benign events should not create attack incidents.
        # ----------------------------------------------------

        if event_a.attack_family == "Benign":
            return 0

        if event_b.attack_family == "Benign":
            return 0

        score = 0

        # ----------------------------------------------------
        # 1. Time proximity
        # ----------------------------------------------------

        time_difference = abs(
            event_a.timestamp - event_b.timestamp
        )

        if time_difference <= self.time_window:
            score += 2
        else:
            # If events are outside the time window,
            # they cannot belong to the same incident.
            return 0

        # ----------------------------------------------------
        # 2. Protocol
        # ----------------------------------------------------

        if (
            event_a.protocol is not None
            and event_b.protocol is not None
        ):
            if event_a.protocol == event_b.protocol:
                score += 1

        # ----------------------------------------------------
        # 3. Destination port
        # ----------------------------------------------------

        if (
            event_a.dst_port is not None
            and event_b.dst_port is not None
        ):
            if event_a.dst_port == event_b.dst_port:
                score += 1

        # ----------------------------------------------------
        # 4. Source IP
        # ----------------------------------------------------

        if (
            event_a.src_ip is not None
            and event_b.src_ip is not None
        ):
            if event_a.src_ip == event_b.src_ip:
                score += 2

        # ----------------------------------------------------
        # 5. Destination IP
        # ----------------------------------------------------

        if (
            event_a.dst_ip is not None
            and event_b.dst_ip is not None
        ):
            if event_a.dst_ip == event_b.dst_ip:
                score += 2

        # ----------------------------------------------------
        # 6. Attack family
        # ----------------------------------------------------

        if event_a.attack_family == event_b.attack_family:
            score += 2

        return score

    # ========================================================
    # Determine whether two events are related
    # ========================================================

    def events_are_related(
        self,
        event_a: SecurityEvent,
        event_b: SecurityEvent,
    ) -> bool:
        """
        Determine whether two events should belong to the
        same incident.
        """

        score = self.correlation_score(
            event_a,
            event_b,
        )

        return score >= self.correlation_threshold

    # ========================================================
    # Correlate events
    # ========================================================

    def correlate(
        self,
        events: List[SecurityEvent],
    ) -> List[Incident]:
        """
        Convert individual security events into incidents.
        """

        if not events:
            return []

        # ----------------------------------------------------
        # Process events chronologically.
        # ----------------------------------------------------

        events = sorted(
            events,
            key=lambda event: event.timestamp,
        )

        incidents: List[Incident] = []

        # ----------------------------------------------------
        # Process every event.
        # ----------------------------------------------------

        for event in events:

            # ------------------------------------------------
            # Ignore benign events.
            # ------------------------------------------------

            if event.attack_family == "Benign":
                continue

            matching_incident = None

            # ------------------------------------------------
            # Look for an existing related incident.
            #
            # We search newest incidents first because a recent
            # incident is more likely to contain the event.
            # ------------------------------------------------

            for incident in reversed(incidents):

                # If the event is too far from the end of the
                # incident, older incidents are unlikely to match.
                if (
                    event.timestamp - incident.end_time
                    > self.time_window
                ):
                    break

                # ------------------------------------------------
                # Compare the event against events already
                # contained in this incident.
                # ------------------------------------------------

                if any(
                    self.events_are_related(
                        event,
                        existing_event,
                    )
                    for existing_event in incident.events
                ):
                    matching_incident = incident
                    break

            # ------------------------------------------------
            # Add event to an existing incident.
            # ------------------------------------------------

            if matching_incident is not None:

                matching_incident.add_event(
                    event
                )

                # Keep the strongest confidence observed.
                matching_incident.confidence = max(
                    matching_incident.confidence,
                    event.confidence,
                )

            # ------------------------------------------------
            # Otherwise create a new incident.
            # ------------------------------------------------

            else:

                incident_id = (
                    f"INC-{len(incidents) + 1:06d}"
                )

                incident = Incident(
                    incident_id=incident_id,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    confidence=event.confidence,
                )

                incident.add_event(
                    event
                )

                incidents.append(
                    incident
                )

        # ----------------------------------------------------
        # Calculate final incident properties.
        # ----------------------------------------------------

        for incident in incidents:
            self._finalize_incident(
                incident
            )

        return incidents

    # ========================================================
    # Finalize incident
    # ========================================================
    def _finalize_incident( 
        self, 
        incident: Incident, 
        ) -> None: 
        """ 
        Calculate derived properties for an incident. 
        """ 
 
        # -------------------------------------------------------- 
        # Family distribution 
        # -------------------------------------------------------- 
 
        family_counts = incident.family_distribution 
 
        # Safety check. 
        if not family_counts: 
            return 
 
        # -------------------------------------------------------- 
        # Store all candidate families. 
        # -------------------------------------------------------- 
 
        incident.attack_families = list( 
            family_counts.keys() 
        ) 
 
        # -------------------------------------------------------- 
        # Determine primary attack family. 
        # 
        # The family with the most events becomes the 
        # primary family. 
        # -------------------------------------------------------- 
 
        incident.primary_attack_family = max( 
            family_counts, 
            key=family_counts.get, 
        ) 
 
        # -------------------------------------------------------- 
        # Calculate average confidence. 
        # -------------------------------------------------------- 
 
        if incident.events: 
 
            incident.confidence = ( 
                sum( 
                    event.confidence 
                    for event in incident.events 
                ) 
                / len(incident.events) 
            ) 
 
        # -------------------------------------------------------- 
        # Calculate severity. 
        # -------------------------------------------------------- 
 
        event_count = len( 
            incident.events 
        ) 
 
        primary_family = ( 
            incident.primary_attack_family 
        ) 
 
        # -------------------------------------------------------- 
        # Critical attack families. 
        # -------------------------------------------------------- 
 
        if primary_family in { 
            "DDoS", 
            "Infiltration", 
        }: 
 
            incident.severity = "critical" 
 
        # -------------------------------------------------------- 
        # Very large attack campaigns. 
        # -------------------------------------------------------- 
 
        elif event_count >= 1000: 
 
            incident.severity = "critical" 
 
        # -------------------------------------------------------- 
        # High severity attack families. 
        # -------------------------------------------------------- 
 
        elif primary_family in { 
            "DoS", 
            "Brute Force", 
            "Web Attack", 
        }: 
 
            incident.severity = "high" 
 
        # -------------------------------------------------------- 
        # Medium-sized incidents. 
        # -------------------------------------------------------- 
 
        elif event_count >= 20: 
 
            incident.severity = "medium" 
 
        # -------------------------------------------------------- 
        # Small incidents. 
        # -------------------------------------------------------- 
 
        else: 
 
            incident.severity = "low"