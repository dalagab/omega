# DeltaScope rule workflow

## 1. Select or create a rule

Open Security Researcher → Rules. System Rules are read-only; use **Fork to My Rules** or **New Rule** to create an editable local revision.

## 2. Edit

Use YAML for precise source editing or Visual for node-based rule flow. Both represent the same SRL model; visual changes are converted back through the SRL compiler rather than using a browser-only execution engine.

## 3. Validate and format

Validation checks schema, allowed collections/operators, output shape and other SRL constraints. Formatting creates a deterministic readable YAML representation.

## 4. Explain and inspect

Use the editor’s context intelligence, symbol outline and flow view to understand which collections/facts the rule consumes and what it emits.

## 5. Dry-run a plugin

Select a plugin in the global plugin picker, then dry-run the rule. Inspect matched selectors, emitted facts/findings and any missing-observation requirement.

## 6. Replay

Replay a selected set or bounded corpus to understand how broadly the candidate matches. Treat replay results as review data; they do not alter published evidence.

## 7. Fixtures

Create and maintain both positive and negative fixtures. Test both before export.

## 8. Export/propose

Export creates a local candidate bundle. The GitHub proposal handoff opens the reviewed repository workflow; it does not silently submit, merge or activate the rule.

## 9. Production boundary

Merged source still passes through Definitions compilation/freezing and production authority gates. DeltaScope itself does not write production findings or queue state.
