# SigmaScope YARA rules

YARA is **supplemental evidence**. A match never replaces SigmaScope's artifact findings,
severity, source attribution, review coverage, or ClamAV result.

## Production scan scope

SigmaScope scans the exact downloaded package container and, when the package is a ZIP,
a bounded generated view of code/config/payload-like archive members. Original ZIP paths
are never extracted directly to disk. Each materialized member gets a generated filename;
Evidence-v2 records the original archive path, member SHA-256 and byte count beside any
YARA match.

Current member limits are deliberately smaller than the primary hostile-archive parser:
256 members, 16 MiB per member and 64 MiB total. Large media/font resources are skipped.
The scan scope and truncation/skip counts are persisted in Evidence-v2.

## Review contract

Production rules are disabled unless they satisfy `policy.json`. Every `.yar` / `.yara`
file must have a same-name metadata sidecar. The v2 metadata contract records:

- exact `reviewedRuleSha256` of the reviewed rule bytes;
- exact declared rule names;
- enabled/disabled status;
- provenance and license;
- reviewer and review timestamp;
- rule class and confidence;
- false-positive expectation, scope and review notes.

The Definitions build fails closed if the sidecar hash differs from the rule bytes, if
rule names differ from declarations, or if an enabled file fails YARA compilation. The
frozen YARA executable is also identity-pinned and workers verify it before scanning.

## Omega Core

The initial production seed contains 14 first-party compound rules:

- credential/token access combined with exfiltration indicators;
- classic and NtCreateThreadEx process-injection chains;
- encoded PowerShell download/execute;
- Windows Defender exclusion/tamper commands;
- base64-embedded PE dynamic loading;
- AMSI memory-patch indicators;
- Run/RunOnce, scheduled-task and Windows-service persistence;
- anti-debug and anti-VM clusters as contextual anomaly evidence.

The rules intentionally do **not** trigger on ordinary `HttpClient`, P/Invoke, Discord
URLs, filesystem APIs, `Process.Start`, PowerShell strings, high entropy, unsigned PE
files or obfuscation by themselves.

## Third-party rules

No third-party pack is enabled wholesale. `UPSTREAM_REVIEW_QUEUE.md` lists candidate
sources. Individual rules may be imported only after exact-rule review, provenance and
license capture, false-positive assessment, and hash pinning under this same contract.
