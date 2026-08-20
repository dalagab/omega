# SigmaScope YARA rules

YARA is a **supplemental evidence** engine. A match does not replace SigmaScope's own
artifact findings, severity, source attribution, or review-coverage model.

Production rules are disabled unless they satisfy `policy.json`. Every `.yar` / `.yara`
file must have a same-name metadata sidecar, for example:

- `credential-theft.yar`
- `credential-theft.yar.metadata.json`

The metadata document must use `omega.sigmascope.yara-rule-metadata.v1` and record the
rule file, enabled/disabled status, provenance (`kind` + `source`), license, review time,
false-positive expectation, intended scope, and review notes. A rule without that
metadata causes the daily Definitions build to fail closed.

No production YARA rules are enabled in this source tree yet. That is deliberate: the
integration and review contract are now ready, but signatures should be added only when
they are specific enough to provide useful evidence without turning broad strings into
security verdicts.
