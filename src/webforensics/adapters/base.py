"""Interfaces between evidence sources and the core engine (D3).

The core only sees these protocols and the models they return, so a new source
(Wazuh, later Splunk/Elastic) is one new adapter, not a change to correlation.
"""

from typing import Protocol

from webforensics.models import FileCollection, LogCollection


class LogSource(Protocol):
    def load_logs(self) -> LogCollection: ...


class FileEvidenceSource(Protocol):
    def load_files(self) -> FileCollection: ...
