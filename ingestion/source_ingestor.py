from pathlib import Path
from typing import Any

from correlation.schema import SecurityEvent
from ingestion.collectors.file_collector import FileCollector
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

        self.collector = FileCollector(file_path)
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
            raise ValueError("limit must be greater than zero.")

        raw_records = self.collector.collect_batch(limit=limit)

        return self.pipeline.process_batch(
            raw_records,
            **parser_kwargs,
        )