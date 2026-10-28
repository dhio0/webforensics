# Performance

Measured with `scripts/bench.py` (seeded synthetic nginx log; 1 in 8 requests is a bot SQLi
payload; 300 deployed files plus N suspicious files). Machine: Windows 11 laptop, Python
3.11. Time and memory come from separate runs, because tracemalloc slows Python down a lot.

| Lines | Suspicious files | Parse | Correlate | Total | Peak memory |
|---:|---:|---:|---:|---:|---:|
| 200,000 | 10 | 3.2 s | 1.9 s | 5.1 s | — |
| 1,000,000 | 50 | 17.6 s | 9.8 s | 27.4 s | 1.13 GB |

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

## Known limits
- Memory is dominated by the raw line text kept for citations and by one pydantic `Finding`
  per attack-pattern line. A log where most lines are bot payloads uses more memory than the
  table suggests. Streaming the logs (only keeping lines that end up cited) would fix this,
  but needs a second pass over the files. That is deferred until real cases need it.
- `tests/unit/test_performance.py` guards against quadratic regressions with a generous time
  bound (40k events, 31 seeds, < 10 s; about 0.6 s locally). It is not a benchmark.
