# Benchmark fixtures

**Synthetic. Not measurements.** Hand-authored cpgvd reports used to
exercise the benchmark framework where Joern and an LLM backend are not
available (CI, and any machine without a local model). Regenerate with:

```bash
python benchmark/scripts/make_fixtures.py
```

Runs produced from these are flagged `synthetic: true` and every rendered
report carries a warning banner. Never cite figures derived from them.
