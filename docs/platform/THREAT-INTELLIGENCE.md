# URL, domain and IP threat intelligence

Omega maintains a **frozen daily threat-intelligence snapshot** for endpoint research and Stigma-1 correlation. The snapshot is deliberately separate from plugin scanning: SigmaScope never asks a live third-party reputation API while evaluating a plugin.

## What the snapshot contains

The collector stores:

- feed identity, status, licensing/provenance and record counts;
- normalized URL, domain and public-IP indicators;
- active/current risk and category supplied by the feed mapping;
- first/last-seen data when the feed provides it;
- the hostnames already present in current Omega endpoint evidence;
- the public IP addresses those observed hosts resolved to at collection time;
- exact host/IP/URL matches between observed plugin endpoints and the frozen indicators;
- a content-derived `reputationRevision`.

DeltaScope exposes this as **Security Researcher → Threat Intelligence**. The page is ordered as an intelligence briefing rather than a feed browser:

1. **corpus × feed intersection** — indicators that touch endpoints present in current plugin evidence;
2. **endpoint research queue** — exact hits, shared-infrastructure adjacency, newly observed endpoints, unlisted/unrecognised infrastructure and DNS attention;
3. **feed health/lifecycle** — collector outcome, timestamp/freshness provenance and inactive retained indicators;
4. **full frozen feed data** — reference-only and collapsed by default.

An endpoint labelled **UNLISTED** means only that the bounded active feed set has no match for it. It must never be interpreted as `safe`, `clean`, or reputable. DeltaScope further splits unlisted endpoints into recognised/categorised context and **unlisted & unrecognised** research leads. Loopback/private/special-use endpoints are hidden by default but remain available through an explicit filter.

### Exact IOC hit versus shared infrastructure

DeltaScope distinguishes an exact endpoint identity hit from a hostname that merely resolved to a listed IP:

- **exact host/domain/IP/URL identity** — promoted as a feed intersection and linked directly to the affected current plugin variants;
- **resolved-IP adjacency** — displayed as **shared infrastructure**, because CDN/cloud/shared-hosting DNS overlap is not proof that the hostname itself is the malicious indicator.

This distinction changes only the investigator presentation. It does **not** rewrite the immutable frozen reputation snapshot or silently mutate the Stigma-1/SRL policy input.

## Default and optional feeds

The default feed is the Feodo Tracker recommended active botnet-C2 IP blocklist. Omega maps those active C2 IPs to `critical` / `botnet-c2` intelligence.

ThreatFox recent IOCs can also be collected when `ABUSECH_AUTH_KEY` is configured. The collector is intentionally optional so the daily Definitions boundary still works when no API key is available. ThreatFox's recent-IOC API requires an Auth-Key; Omega never embeds one in published evidence.

If the optional ThreatFox refresh fails after Feodo refreshed successfully, Omega keeps the fresh Feodo data. Prior ThreatFox rows may remain visible as retained research reference, but they are marked **inactive** and are removed from active matching indexes so Stigma-1 cannot treat stale optional-feed data as currently active intelligence.

Feeds whose license/terms do not permit Omega to republish a frozen public data snapshot must not be enabled merely because they are technically accessible. A new source needs licensing/provenance review first.

## DNS resolution

A rule must not make an arbitrary live DNS lookup while evaluating a plugin. Instead, the daily collector resolves hostnames that already occur in **current** plugin endpoint evidence and freezes the resulting public IP addresses beside that day's reputation snapshot.

If DNS lookup temporarily fails, Omega may retain the prior frozen resolution for that same observed host and records the resolution status. This prevents a transient resolver outage from silently erasing all reputation context.

DNS is evidence context, not ownership attribution. Shared/CDN IPs can serve many unrelated domains, so a feed match must be interpreted using the actual indicator/feed semantics and plugin endpoint context.

## Research pivots and lifecycle

Every corpus-intersecting indicator exposes its affected current plugin variants. DeltaScope can pivot **indicator → Findings** by pre-filling the Findings inbox endpoint filter; endpoint findings can show `FEED MATCH` or `FEED ADJACENCY` context once the frozen threat snapshot is loaded.

Endpoint first/last-observed timestamps are shown when the published relationship index contains them. A **New this week** filter is therefore publication-backed only when those timestamps exist; DeltaScope does not fabricate historical first-seen dates.

Feed freshness is separate from collector success. `COMPLETE` means the collector completed; it does not by itself prove the feed is recent. DeltaScope prefers a feed-specific timestamp when published and otherwise labels a snapshot-level timestamp as such. Inactive indicators are retained as lifecycle/reference context, but `inactive` is not presented as an upstream retraction unless the frozen payload carries an explicit retirement/retraction timestamp.

The page also presents a bounded ATT&CK **research lens** over the already-loaded newest-finding window. Those mappings are behavioral analogues for pivoting, not claims that a plugin is maliciously executing an ATT&CK technique.

## How SRL uses it

The immutable `networkEndpoints` observations are enriched at **rule-reprojection time** with fields such as:

- `resolvedIps`
- `threatIntelMatched`
- `threatIntelActive`
- `threatIntelRisk`
- `threatIntelCategories`
- `threatIntelSources`
- `threatIntelIndicatorIds`
- `threatIntelRevision`

This is deterministic enrichment from frozen Definitions. Changing the daily reputation snapshot does **not** require reopening the plugin ZIP. It changes the SRL projection revision and can be re-evaluated from retained endpoint evidence.

A basic SRL selector can therefore ask whether an endpoint is in the current frozen threat set:

```yaml
selectors:
  active_bad_endpoint:
    collection: networkEndpoints
    where:
      threatIntelMatched: {equals: true}
      threatIntelActive: {equals: true}
      threatIntelRisk: {in-ci: [high, critical]}
```

Omega also ships experimental facts for active threat-intelligence matches and active botnet-C2 endpoints.

## Risk versus exfiltration

A bad-IP match is **not** proof that a plugin connected to the IP. A data-collection or webhook service is also not automatically malicious.

Potential exfiltration is a **correlation**. For example, Stigma-1 can correlate:

1. retained credential/protected-data capability evidence; and
2. an endpoint matched by the currently active threat-intelligence snapshot.

That can justify a high/critical review finding such as *potential sensitive-data exfiltration path*, while still explicitly stating that static analysis did not observe runtime transmission.

## Updating and failure behavior

The catalog publication workflow runs the reputation collector before the daily Definitions freeze. The resulting `reputation.json` is hash-pinned into Definitions and copied into Security Evidence v2 for DeltaScope inspection.

If the required Feodo feed cannot be refreshed and a valid previous snapshot exists, the collector retains that last-known-good snapshot. If no valid prior snapshot exists, the collection step fails rather than publishing fabricated or empty "clean" reputation data. Optional-feed failures degrade only that feed and never erase a freshly collected required feed.

## Adding a feed

A new feed should define:

1. source and license/redistribution terms;
2. authentication requirements and rate limits;
3. supported IOC types;
4. what `active` means and how expiration works;
5. category/risk mapping;
6. deterministic normalization;
7. bounded record limits;
8. last-known-good failure behavior;
9. collector regression fixtures;
10. whether the data can legally be included in Omega's public frozen Definitions.

Do not add a live network lookup to SRL or SigmaScope. Collection happens at the Definitions boundary; evaluation consumes only the frozen result.
