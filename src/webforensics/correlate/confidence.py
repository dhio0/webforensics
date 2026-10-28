"""Categorical confidence arithmetic (D5): caps and one-step downgrades, no floats."""

from webforensics.models import Confidence

_ORDER = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)


def rank(value: Confidence) -> int:
    return _ORDER.index(value)


def cap(value: Confidence, maximum: Confidence) -> Confidence:
    """The lower of the two."""
    return value if rank(value) <= rank(maximum) else maximum


def lower(value: Confidence) -> Confidence:
    """One step down; LOW stays LOW."""
    return _ORDER[max(rank(value) - 1, 0)]
