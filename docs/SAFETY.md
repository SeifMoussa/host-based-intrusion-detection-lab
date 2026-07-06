# Safety

This project is defensive and educational only.

The lab must only scan explicit local sample paths inside this repository and must only process synthetic JSON/CSV host-event records.

Sample constraints:

- Host-event records must be fake, harmless, and clearly marked with `lab_marker`.
- Sample paths must stay under `samples/`.
- Sample files must be harmless UTF-8 text files.
- The example baseline must reference only repo-controlled files under `samples/files/`.
- The example JSON baseline is static; baseline generation is implemented separately through the baseline creation workflow.
- Suppressions are explicit, synthetic-only, and preserve evidence plus reason metadata.
- Report examples must include the defensive lab-only disclaimer.

Background monitoring, live OS process collection, and real system path monitoring are intentionally excluded to keep the lab deterministic and safe for public review.

CI/CodeQL configured but not yet GitHub-verified.

Prohibited content and behavior:

- Malware.
- Exploit code.
- Persistence.
- Evasion.
- Privilege escalation.
- Destructive remediation.
- Real credential collection.
- Real OS process collection.
- Background agents.
- Third-party scanning.
- Real logs or real indicators.

Evidence sources for this project are synthetic host-event samples, safe sample files, JSON baselines, FIM comparisons, host-event detections, generated reports, tests, and later CI/CodeQL.
