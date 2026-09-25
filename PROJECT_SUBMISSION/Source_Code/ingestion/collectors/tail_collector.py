from pathlib import Path
from typing import Iterator
import time


class TailCollector:
    """
    Continuously watches a log file and yields new non-empty lines.

    The collector is responsible only for reading raw log records.
    Parsing, normalization, detection, and correlation are handled
    by downstream ingestion components.
    """

    def __init__(
        self,
        file_path: str | Path,
        poll_interval: float = 0.5,
        start_at_end: bool = True,
    ):
        if not file_path:
            raise ValueError(
                "file_path cannot be empty."
            )

        if poll_interval <= 0:
            raise ValueError(
                "poll_interval must be greater than 0."
            )

        self.file_path = Path(file_path)
        self.poll_interval = poll_interval
        self.start_at_end = start_at_end

    def collect(self) -> Iterator[str]:
        """
        Continuously yield new non-empty lines from the file.

        If start_at_end is True, existing content is skipped and only
        records appended after collection starts are yielded.

        If start_at_end is False, existing records are yielded first,
        followed by newly appended records.
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

            if self.start_at_end:
                file.seek(0, 2)

            while True:
                line = file.readline()

                if line:
                    line = line.strip()

                    if line:
                        yield line

                    continue

                time.sleep(self.poll_interval)