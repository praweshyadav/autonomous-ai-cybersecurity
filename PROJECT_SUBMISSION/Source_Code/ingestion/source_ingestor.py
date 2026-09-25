from pathlib import Path
from typing import Any, Iterator

from correlation.schema import SecurityEvent
from ingestion.collectors.file_collector import FileCollector
from ingestion.collectors.tail_collector import TailCollector
from ingestion.normalizer import SecurityEventNormalizer
from ingestion.pipeline import IngestionPipeline


class SourceIngestor:
    """
    Connects a source collector to the ingestion pipeline.

    Flow:
        Source
          ↓
        Collector
          ↓
        Parser
          ↓
        Normalizer
          ↓
        SecurityEvent
    """

    def __init__(
        self,
        file_path: str | Path,
        parser: Any,
        normalizer: SecurityEventNormalizer | None = None,
    ):
        if not file_path:
            raise ValueError("file_path cannot be empty.")

        if parser is None:
            raise ValueError("parser cannot be None.")

        self.file_path = Path(file_path)

        self.collector = FileCollector(
            self.file_path
        )

        self.pipeline = IngestionPipeline(
            parser=parser,
            normalizer=normalizer,
        )

    def ingest(
        self,
        **parser_kwargs: Any,
    ) -> list[SecurityEvent]:
        """
        Read the complete source file and convert all valid
        records into normalized SecurityEvents.
        """
        raw_records = self.collector.collect_batch()

        return self.pipeline.process_batch(
            raw_records,
            **parser_kwargs,
        )

    def ingest_batch(
        self,
        limit: int,
        **parser_kwargs: Any,
    ) -> list[SecurityEvent]:
        """
        Read at most `limit` records from the source.
        """
        if limit <= 0:
            raise ValueError(
                "limit must be greater than zero."
            )

        raw_records = self.collector.collect_batch(
            limit=limit
        )

        return self.pipeline.process_batch(
            raw_records,
            **parser_kwargs,
        )

    def ingest_stream(
        self,
        poll_interval: float = 0.5,
        start_at_end: bool = True,
        **parser_kwargs: Any,
    ) -> Iterator[SecurityEvent]:
        """
        Continuously monitor the source file and yield
        normalized SecurityEvents as new records arrive.

        Args:
            poll_interval:
                Seconds to wait between checks for new records.

            start_at_end:
                If True, existing records are ignored and only
                newly appended records are processed.

                If False, existing records are processed first,
                followed by newly appended records.

        Yields:
            Normalized SecurityEvent objects.
        """

        tail_collector = TailCollector(
            file_path=self.file_path,
            poll_interval=poll_interval,
            start_at_end=start_at_end,
        )

        for raw_record in tail_collector.collect():
            events = self.pipeline.process(
                raw_record,
                **parser_kwargs,
            )

            if events is None:
                continue

            if isinstance(events, list):
                for event in events:
                    yield event
            else:
                yield events