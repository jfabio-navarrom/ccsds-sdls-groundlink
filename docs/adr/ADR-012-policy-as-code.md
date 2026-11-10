# ADR-012: Link security configuration as code, with versioned risk acceptances

- **Status:** accepted
- **Date:** 2026-11-10

## Context

In phases 1 to 3 the security parameters of the link were spread over the code: SPI, algorithm, IV and MAC lengths, anti-replay and key references. Nobody could answer quickly "does this link meet the CCSDS baseline?". If a code change weakened a parameter, nothing failed.

I have a separate project, `ccsds-policy-as-code`, with 24 Rego policies traced to CCSDS 355.0-B-2 and 352.0-B-2. They check a Security Association (SA) database written in YAML.

## Decision

1. **Document the real SAs** in `docs/architecture/groundlink.sdls.yaml`, in the `ccsds-policy-as-code` format. It describes what is implemented, not the ideal.
2. **Tie the document to the code.** `tests/test_sa_database.py` compares the YAML with the Python and C++ constants. If one changes without the other, CI fails.
3. **Scan in CI** with Conftest and the `ccsds-policy-as-code` policies (`policies` job).
4. **Manage deviations as code.** `accepted-risks.yaml` lists each accepted finding with justification, compensating controls, remediation, owner and review date. `tools/check_policy.py` makes CI fail if a new finding shows up, if an acceptance does not match any finding anymore, or if its review date has passed.

## Why

- **An honest model.** Describing the link as "ideal" would give a clean but misleading scan. The scan found three real deviations in my own implementation: the ARSN is the IV, there is no anti-replay window, and the keys are not in an HSM.
- **An accepted risk is not a forgotten risk.** With a review date that CI enforces, an exception can not stay forever. This is the difference between GRC in a spreadsheet and continuous GRC.
- **Stale acceptances also fail.** If someone fixes a problem, the register gets cleaned. No ghost exceptions.

## Options I rejected

- **Turn off the failing rules:** it hides the deviation from any reviewer.
- **Adjust the YAML so it passes:** that would be false documentation.
- **Copy the policies into this repo:** duplicated code that goes out of sync. The policy repo is the single source.

## Consequences

- The `policies` job needs `ccsds-policy-as-code` to be reachable from GitHub Actions. If it is not, the job prints a warning and skips, but `test_sa_database` still runs.
- Changing a security parameter means touching three places: the code, the YAML, and the risk register if the scan result changes. This is on purpose.
