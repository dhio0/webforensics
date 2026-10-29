"""WazuhAdapter: evidence pulled from a Wazuh 4.x indexer (M6).

`pull` (pull.py) is the only part that touches the network; it writes a recording.
`WazuhRecordingSource` reads that recording offline and implements the same LogSource and
FileEvidenceSource protocols as the FileAdapter, so the core is unchanged (D3, D78).
"""

from pathlib import Path

from webforensics.adapters.file_adapter import display_name
from webforensics.adapters.wazuh.fim import fim_files
from webforensics.adapters.wazuh.logs import web_events
from webforensics.adapters.wazuh.recording import (
    RecordedHit,
    RecordingError,
    RecordingHeader,
    read_recording,
)
from webforensics.hashing import sha256_file
from webforensics.models import FileCollection, LogCollection, SourceFile
from webforensics.parsers.access_log import AccessLogFormat
from webforensics.parsers.error_log import ErrorLogFormat

__all__ = ["RecordingError", "WazuhRecordingSource"]


class WazuhRecordingSource:
    def __init__(
        self,
        recording: Path,
        base_dir: Path | None = None,
        webroot: Path | None = None,
        url_prefix: str = "/",
        access_format: AccessLogFormat = AccessLogFormat.NGINX_COMBINED,
        error_format: ErrorLogFormat = ErrorLogFormat.NGINX,
        error_utc_offset: str = "+0000",
    ) -> None:
        self._recording = recording
        self._base_dir = base_dir
        self._webroot = webroot
        self._url_prefix = url_prefix
        self._access_format = access_format
        self._error_format = error_format
        self._error_offset = error_utc_offset
        self._loaded: tuple[RecordingHeader, list[RecordedHit], SourceFile] | None = None

    def _load(self) -> tuple[RecordingHeader, list[RecordedHit], SourceFile]:
        if self._loaded is None:
            if not self._recording.is_file():
                raise FileNotFoundError(f"recording not found: {self._recording}")
            header, hits = read_recording(self._recording)
            source = SourceFile(path=display_name(self._recording, self._base_dir),
                                sha256=sha256_file(self._recording),
                                size=self._recording.stat().st_size)
            self._loaded = (header, hits, source)
        return self._loaded

    @property
    def header(self) -> RecordingHeader:
        return self._load()[0]

    def load_logs(self) -> LogCollection:
        header, hits, source = self._load()
        return web_events(header, hits, source, self._access_format, self._error_format,
                          self._error_offset)

    def load_files(self) -> FileCollection:
        header, hits, source = self._load()
        return fim_files(header, hits, source, self._url_prefix, self._webroot)
