# YARA upstream review queue

This is a review queue, **not** a production rule source. Nothing listed here is fetched
or enabled automatically.

Candidate upstreams for narrow rule-by-rule review:

- YARA Forge core/extended outputs: useful discovery/normalization source for vetted
  community rules. Never import the aggregate pack wholesale; retain the original rule
  provenance and license.
- Neo23x0/signature-base: candidate high-quality malware/tool signatures. Review each
  selected rule's current license and false-positive profile before copying it.
- embee-research/Yara-detection-rules: candidate modern RAT/stealer/tooling detections.
  Review exact upstream commit, rule license and applicability to Windows/.NET plugin
  supply-chain compromise.

Priority families/classes for review:

1. commodity credential stealers;
2. RAT/backdoor families commonly delivered as Windows/.NET payloads;
3. loaders/downloaders and embedded payload stages;
4. mature C2/offensive-framework implant signatures with low false-positive risk;
5. packer/obfuscator rules only as anomaly evidence.

For any accepted third-party rule, freeze: repository URL, exact commit, original path,
license, local reviewed SHA-256, review timestamp/reviewer, intended scope and expected
false-positive level. A later upstream change is a new review, not an automatic update.
