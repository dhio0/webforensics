# Performance

Measured with `scripts/bench.py` (seeded synthetic nginx log; 1 in 8 requests is a bot SQLi
payload; 300 deployed files plus N suspicious files). Machine: Windows 11 laptop, Python
3.11. Time and memory come from separate runs, because tracemalloc slows Python down a lot.

| Lines | Suspicious files | Parse | Correlate | Total | Peak memory |
|---:|---:|---:|---:|---:|---:|
| 200,000 | 10 | 2.6 s | 1.2 s | 3.9 s | — |
| 1,000,000 | 50 | 13.3 s | 6.8 s | 20.1 s | 0.98 GB |

Measured after D88. Before it the same runs took 5.1 s and 27.4 s, with 1.13 GB peak at
1M lines; the synthetic log has short lines, so it gains less than real logs (below).

Before the M3 optimizations the same 1M-line run was projected at roughly 2 minutes for a
single suspicious file and about 4 GB of memory, and every extra suspicious file re-scanned
the whole log.

## What made the difference
- **`LogEvent` is a slotted dataclass** (D52): ~80 B of overhead per line instead of ~1.3 KB
  for a pydantic instance. Repeated strings (IPs, user agents, paths) are interned.
- **Indexes instead of scans** (D53): requests by URL, by actor and by time (bisect) are built
  once. Cost grows with log size + number of seeds, not their product.
- **Rule matching is cached per request shape**: identical (path, query, user agent)
  combinations are decoded and matched once.
- **Gap detection** only computes the local median for intervals that could be a gap.
- **Login outcomes** look up the next attempt per path and page views by bisection, so a
  brute-force run is O(N log N).

## Real logs (D88)

Real access logs of a hosting server (Zenodo 20001206, Organization Y, OpenLiteSpeed), one
run per site, no webroot. Peak working set measured in-process.

| Site | Lines | Peak at 2ad5d68 | Peak after D88 | Time |
|---|---:|---:|---:|---:|
| sub17 | 1,766,047 | 2,976 MB | 1,614 MB | 48 s |
| sub3 | 1,482,118 | 2,487 MB | 1,350 MB | 38 s |
| sub1 | 1,029,778 | 1,568 MB | 883 MB | 32 s |
| sub20 (wp-login brute force) | 183,295 | 1,284 MB | 196 MB | 5 s |

About 0.9 KB per line after D88. Before it, real logs cost more than the synthetic
benchmark because of longer user agents, one pydantic object per failed login, and the
line text of every request kept for citations (now read back from the file only for cited
lines). All 7.4M lines in one run took 224.8 s and peaked at 5,984 MB (about 0.8 KB per
line), with 7.9 GB free at the start. It fits on a 16 GB laptop with few other programs
open; per-site runs stay the recommended unit for hosting servers (D88).

## Known limits
- Line text is kept in memory only for gzip-compressed logs (they cannot be seeked
  cheaply); plain logs are read back by byte offset when a line is cited (D88). Memory is
  now dominated by the per-request objects and the indexes, plus one pydantic `Finding` per
  attack-pattern line, so a log where most lines are bot payloads uses more.
- `tests/unit/test_performance.py` guards against quadratic regressions with a generous time
  bound (40k events, 31 seeds, < 10 s; about 0.6 s locally). It is not a benchmark.
