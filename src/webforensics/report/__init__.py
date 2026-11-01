"""Indonesian incident report: build (language-neutral) then render (Markdown, HTML, JSON)."""

from datetime import timezone

from webforensics.models import Report
from webforensics.report import viewer
from webforensics.report.build import build_report
from webforensics.report.document import build_document, gap_labels
from webforensics.report.html import render_html
from webforensics.report.markdown import render_markdown
from webforensics.report.text import Texts

FORMATS = ("md", "html", "json")


def render(report: Report, tz: timezone, *, strict: bool = False) -> dict[str, str]:
    """All three formats as text, keyed by file extension. Byte-identical across runs."""
    texts = Texts(tz=tz, gap_labels=gap_labels(report.result.gaps), strict=strict)
    doc = build_document(report, texts)
    return {
        "md": render_markdown(doc),
        "html": render_html(doc),
        "json": report.model_dump_json(indent=2) + "\n",
    }


def render_viewer(report: Report, tz: timezone, *, strict: bool = False) -> str:
    """The interactive offline viewer (`webforensics view`). Byte-identical across runs."""
    texts = Texts(tz=tz, gap_labels=gap_labels(report.result.gaps), strict=strict)
    return viewer.render_viewer(report, texts)


__all__ = ["FORMATS", "build_report", "render", "render_viewer"]
