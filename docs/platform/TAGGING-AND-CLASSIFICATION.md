# Tagging and classification

Omega uses several kinds of tags and classifications. They have different authority and should not be mixed together.

## Marketplace tags

Plugin manifests can provide `tags` and `categoryTags`. Catalog normalization stores them in the plugin-tag model and uses them for discovery/search/presentation.

These are descriptive marketplace metadata. They are not security findings.

Relevant code:

- `tools/catalog/build_sqlite_catalog.py`
- `tools/catalog/catalog_json_store.py`
- `tools/catalog/catalog_revisions.py`


### Catalog storage and search

Manifest `tags` and `categoryTags` are retained separately and normalized into the `plugin_tags` table with `kind=tag` or `kind=category`. The catalog search index then combines the normalized tags for discoverability. The important implementation points are:

- schema/storage: `tools/catalog/build_sqlite_catalog.py` (`plugin_tags`, `tags_json`, `category_tags_json`);
- JSON publication/rebuild: `tools/catalog/catalog_json_store.py`;
- revision identity: `tools/catalog/catalog_revisions.py`;
- search materialization: `plugin_search` construction in `build_sqlite_catalog.py`.

When changing tag normalization, preserve the original manifest values where possible, normalize only at the indexing boundary, and add a catalog regression proving that tags survive JSON → SQLite reconstruction.

## Developer-profile categories and tags

`.omega/plugin.yaml` can include profile categories/tags. These are developer-authored explanatory metadata. They improve indexing and description but do not override the independent catalog or scanner.

Relevant code:

- `tools/catalog/plugin_profile.py`
- `docs/OMEGA-PLUGIN-PROFILE.md`

## Capability vocabulary

Security capabilities use a canonical registry under `security-definitions/capabilities/registry.json`. Capability IDs should be stable, descriptive and reusable across scanner observations, developer profiles and rule output.

Adding a capability is a security-contract change. It requires:

1. a stable ID and human label;
2. a precise definition of what observation qualifies;
3. documentation of expected developer declaration semantics;
4. scanner/rule mapping where applicable;
5. tests for normalization and unknown IDs.

Do not create a new capability merely to represent a single rule result if an existing lower-level capability already describes the behavior.

## Source permission taxonomy

`tools/catalog/analyze_permissions.py` contains a compact source-oriented permission taxonomy for categories such as filesystem, network, IPC, commands and hooks. It is useful for source-level presentation and comparison.

This taxonomy is intentionally coarser than SigmaScope’s security observation model. When extending it:

1. add a new category only when it describes a meaningful user-facing permission family;
2. use bounded, reviewable regex patterns;
3. add a display label and deterministic display ordering;
4. add tests with positive and negative snippets;
5. avoid treating the source tag as proof that the installable artifact has the same behavior.

## Presentation classifications

Some tags are used only for presentation policy, for example content classification. Those belong in presentation code such as `catalog_presentation.py`, not in security severity logic.

## Endpoint classifications

Observed endpoints can be classified by security intelligence or rule logic. Endpoint classification should retain the original normalized endpoint and the reason/source for its classification so investigators can distinguish a raw destination from an interpretation.

## Adding or changing a tag safely

Before adding a tag, decide which domain owns it:

| Question | Correct home |
| --- | --- |
| How should users browse this plugin? | Marketplace tag/category |
| What does the developer say the plugin is? | Developer profile metadata |
| What security behavior was observed? | Capability/observation |
| What coarse source permission family applies? | Source permission taxonomy |
| How should the UI treat content? | Presentation classification |
| What security conclusion follows from evidence? | Stigma-1 finding/rule, not a generic tag |

A tag should not silently cross these boundaries.
