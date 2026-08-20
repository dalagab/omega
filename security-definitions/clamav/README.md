# SigmaScope ClamAV definitions

Official ClamAV CVD/CLD databases are **not committed to Git**. The daily Definitions
workflow refreshes them with FreshClam, packages them as a deterministic content-
addressed asset, records the asset SHA-256/byte count and every database SHA-256, then
freezes that descriptor into Definitions.

Continuous workers download only that frozen asset and verify it before extraction.
They never run FreshClam. The frozen descriptor also records the exact `clamscan` binary
identity observed at the Definitions boundary; a worker whose executable SHA-256/byte
count differs does not run ClamAV for that scan.

ClamAV remains supplemental evidence only. Signature hits do not replace SigmaScope's
severity or source-review model.
