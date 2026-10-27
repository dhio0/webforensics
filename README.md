# webforensics

A defensive tool that reconstructs **how a website was compromised**. It correlates evidence from the webroot (suspicious or modified files, their timestamps and hashes) with web server access logs. Like a human analyst, it starts from the file and traces back to the request that created it and the exploit that made that possible. The final output is an incident report in Indonesian.

> **Status: early development (milestone 1 of 7).** Evidence loading works (access logs + webroot manifest). Detection, correlation, reports and the evaluation benchmark are not implemented yet. See [docs/plan.md](docs/plan.md).

## Design principles
- **Deterministic and offline core.** Rules and heuristics only, with no LLM and no network calls in the analysis path. The same inputs always give the same output.
- **Every claim cites evidence.** Each claim points to a log file + line number, or a file path + SHA-256.
- **Honest about uncertainty.** Evidence gaps and confidence levels are explicit, and mtime-only claims are treated as weak because mtime is easy to forge.

## What works today (M1)
```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"   # Windows: .venv\Scripts\pip

# On the compromised server (read-only, needs bash + GNU coreutils):
scripts/collect.sh -w /var/www/html -o /tmp/case01 -l /var/log/nginx

# On the analyst machine:
webforensics inspect --manifest case01/manifest.tsv --log case01/logs
webforensics inspect --manifest case01/manifest.tsv --log case01/logs --json
```
The evidence formats are described in [docs/evidence-format.md](docs/evidence-format.md).

## Development
```bash
pytest
ruff check .
```

## Docs
- [docs/plan.md](docs/plan.md): plan, data models, correlation algorithm, milestones, risks
- [docs/decisions.md](docs/decisions.md): design decisions and their reasons
- [docs/evidence-format.md](docs/evidence-format.md): manifest v1 and supported log formats

## Roadmap
Planned work is listed in [docs/plan.md](docs/plan.md) (§5). A comparison with related tools will be added only after checking those tools first-hand.
