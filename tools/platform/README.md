# Omega platform evidence

`PlatformEvidenceTool` is a compatibility-evidence inventory, not a security verdict engine and not part of the hostile Rift host.

It combines three kinds of evidence:

1. packaged RID/native assets (`runtimes/win-*`, `linux-*`, `osx-*`),
2. managed metadata that is relevant to portability (assembly references and P/Invoke library names),
3. an optional Rift runtime report showing what happened on the actual analysis host.

The output is `omega.player-environment-support.v1` and always carries Windows, Linux and macOS records. Statuses are evidence-based (`verified-in-rift`, `blocked-in-rift`, `packaged-unverified`, `platform-dependent-unverified`, `unknown`) rather than a guessed boolean.

A native Linux Rift result is deliberately **not** presented as proof that the plugin works in FFXIV under Wine/Proton. Likewise, packaged macOS native assets do not prove a plugin works under a macOS compatibility environment. Those environments need their own qualified executors before Omega can call them verified.
