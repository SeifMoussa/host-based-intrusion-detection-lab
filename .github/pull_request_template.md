## Summary

Describe the change.

## Safety Checklist

- [ ] Uses only synthetic local lab data.
- [ ] Does not add malware, exploit code, persistence, evasion, privilege escalation, or destructive remediation.
- [ ] Does not collect real credentials, real OS process lists, real logs, real indicators, or third-party data.
- [ ] Does not add live monitoring or background agents.

## Testing

List commands run:

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

