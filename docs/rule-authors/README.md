# Rule authoring

Use Stigma-1 rules when the observations you need already exist and the desired security logic can be expressed deterministically over them.

## Before writing a rule

1. State the security question in plain language.
2. Identify the exact retained observation(s) required.
3. Check the Rule data reference for collection completeness.
4. Decide whether the output should be a reusable fact, a finding or a Deep Scan request.
5. Decide what the result does **not** prove so the final wording cannot overclaim.

## Author in DeltaScope

Security Researcher → Rules provides:

- System Rules (read-only repository/frozen context);
- My Rules (local editable revisions);
- YAML and visual editing;
- schema/intelligence assistance;
- validation/formatting;
- selected-plugin dry run;
- bounded replay;
- positive/negative fixture tools;
- candidate export/GitHub proposal handoff.

## Quality checklist

A good rule has:

- stable ID;
- narrow purpose;
- registered inputs only;
- explicit severity/category;
- useful human explanation;
- positive fixture;
- near-miss negative fixture;
- no dependence on incomplete data unless the rule explicitly handles that coverage state;
- replay results reviewed for likely false positives.

## When not to use a rule

Do not use SRL to compensate for a missing primitive observation. Add the observation to SigmaScope/Evidence-v2 first. Do not use SRL for arbitrary external fetching or executable analysis; use a collector or code-owned Deep Scan profile as appropriate.
