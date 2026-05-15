# Contributing

This project is defensive and educational only. Contributions must preserve the safety scope described in `README.md` and `docs/SAFETY.md`.

## Development Checks

Run these before submitting changes:

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

## Contribution Boundaries

Do not add malware, exploit code, persistence, evasion, privilege escalation, destructive remediation, real credential collection, real logs, real indicators, or third-party scanning.

