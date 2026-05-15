# Project Completion Checklist

## Safety

- [x] Uses only synthetic local lab data.
- [x] Does not monitor real system paths by default.
- [x] Does not collect real OS process lists.
- [x] Does not run background agents.
- [x] Does not include malware or exploit code.
- [x] Does not include persistence, evasion, privilege escalation, or destructive remediation.
- [x] Expanded safety validation tests added.

## Core Functionality

- [x] Static JSON baseline format defined.
- [x] JSON baseline generation implemented for explicit sample paths.
- [x] File integrity monitoring implemented for explicit sample paths.
- [x] Synthetic host-event sample loading and shape validation implemented.
- [x] Detection logic implemented for synthetic records.
- [x] Alerts include evidence and triage guidance.
- [x] Markdown and JSON reports generated.
- [x] Explicit suppression handling for synthetic false positives.

## Quality

- [x] pytest passes.
- [x] ruff check passes.
- [x] ruff format check passes.
- [x] Coverage run reaches at least 90%.
- [x] Documentation safety checker added.
- [x] CI configured locally for GitHub Actions.
- [x] CodeQL configured locally for GitHub Actions.
- [x] Dependabot configured.
- [ ] GitHub Actions result verified on GitHub after publishing.
- [ ] CodeQL result verified on GitHub after publishing.
- [x] Documentation complete for final QA.
- [x] Phase 8 repository structure audit completed locally.
- [x] Phase 8 safety and hygiene audit completed locally.
- [x] Phase 9 release preparation materials completed.
- [x] Manual publishing commands prepared.
- [x] v0.1.0 release notes drafted.
- [ ] Repository published to GitHub.
- [ ] v0.1.0 tag created.
- [ ] GitHub release created.
