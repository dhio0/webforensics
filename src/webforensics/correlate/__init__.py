"""File-first correlation: suspicious file -> creating request -> root cause (plan §4)."""

from webforensics.correlate.config import CorrelationConfig
from webforensics.correlate.engine import correlate

__all__ = ["CorrelationConfig", "correlate"]
