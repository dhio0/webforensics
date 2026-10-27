import json

from typer.testing import CliRunner

from webforensics import __version__
from webforensics.cli import app

runner = CliRunner()


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "inspect" in result.output


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_inspect_summary(fixtures_dir):
    result = runner.invoke(
        app,
        [
            "inspect",
            "--log", str(fixtures_dir / "logs" / "nginx_access.log"),
            "--manifest", str(fixtures_dir / "manifests" / "shop.manifest.tsv"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Logs: 6 events, 2 unparsed lines" in result.output
    assert "Files: 6 entries, 2 rejected manifest rows" in result.output


def test_inspect_json_is_deterministic(fixtures_dir):
    args = ["inspect", "--json", "--log", str(fixtures_dir / "logs" / "nginx_access.log")]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == 0
    assert first.output == second.output
    assert len(json.loads(first.output)["logs"]["events"]) == 6


def test_inspect_needs_input():
    result = runner.invoke(app, ["inspect"])
    assert result.exit_code == 2


def test_inspect_missing_log(tmp_path):
    result = runner.invoke(app, ["inspect", "--log", str(tmp_path / "nope.log")])
    assert result.exit_code == 2
