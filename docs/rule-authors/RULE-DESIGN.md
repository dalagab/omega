# Rule design guidance

## Prefer evidence chains that a human can follow

A reviewer should be able to move from finding → rule → fact/selector → retained observation without reverse-engineering hidden behavior.

## Separate primitive facts from correlations

If several rules need to know that a managed call implies `network.http`, create one fact-producing rule and reuse the fact. Correlation rules can then focus on meaningful combinations.

## Avoid reputation-only verdicts

Repository popularity, author identity or source provider may be useful context, but a security finding should normally point to observable behavior/provenance rather than “unknown source = malicious”.

## Use severity for impact, not uncertainty

Coverage/attribution uncertainty belongs in coverage/provenance state. Severity belongs to the security meaning of the detected condition.

## Avoid runtime language for static evidence

Use wording such as “contains”, “references”, “can”, “static observations match”. Do not say “sent”, “executed”, “stole” or similar unless runtime evidence actually supports that claim.

## Design negative fixtures carefully

Near-miss fixtures are often more valuable than trivial empty fixtures. If a rule matches network + process launch, include cases with network only, process only, similar API names and benign neighboring patterns.

## Request Deep Scan only when more evidence would change the investigation

An `analysisRequest` should explain what uncertainty the deeper profile can resolve. Do not use Deep Scan merely because a finding is severe.
