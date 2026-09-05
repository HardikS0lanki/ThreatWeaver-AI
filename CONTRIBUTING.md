# Contributing

Contributions that improve evidence quality, platform coverage, validation, tests, or documentation are welcome.

1. Do not submit confidential, employer-owned, customer, or personal data.
2. Add or update behavioral tests for code changes.
3. Keep external connectors read-only by default.
4. Distinguish observed evidence, reported claims, inference, and unverified assumptions.
5. Do not add framework mappings without an authoritative reference and a concrete use case.
6. Run `PYTHONPATH=src python -m unittest discover -s tests -v` and validate the synthetic model before opening a pull request.

Security vulnerabilities should follow `SECURITY.md`, not public issues.
