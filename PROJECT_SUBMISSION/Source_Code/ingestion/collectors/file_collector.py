from pathlib import Path
from typing import Iterator


class FileCollector:
    """
    Reads log records from a file.

    The collector is responsible only for reading records.
    Parsing and normalization are handled by the ingestion pipeline.

    This gives us a local development equivalent of a server
    continuously producing log records.
    """

    def __init__(
        self,
        file_path: str | Path,
    ):
        if not file_path:
            raise ValueError(
                "file_path cannot be empty."
            )

        self.file_path = Path(
            file_path
        )

    def collect(self) -> Iterator[str]:
        """
        Read all existing non-empty lines from the file.

        Each yielded value represents one raw log record.
        """

        if not self.file_path.exists():
            raise FileNotFoundError(
                f"Log file not found: "
                f"{self.file_path}"
            )

        if not self.file_path.is_file():
            raise ValueError(
                f"Path is not a file: "
                f"{self.file_path}"
            )

        with self.file_path.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:
                line = line.strip()

                if line:
                    yield line

    def collect_batch(
        self,
        limit: int | None = None,
    ) -> list[str]:
        """
        Collect log records into a list.

        Args:
            limit:
                Maximum number of records to return.
                None means all available records.
        """

        if limit is not None and limit <= 0:
            raise ValueError(
                "limit must be greater than 0."
            )

        records: list[str] = []

        for record in self.collect():
            records.append(record)

            if (
                limit is not None
                and len(records) >= limit
            ):
                break

        return records