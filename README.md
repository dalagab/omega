# Omega

**Omega is a plugin marketplace for Dalamud.**

Think of it like this:

- **Dalamud** is the thing that installs and updates plugins.
- **Omega** helps you find plugins and understand what you are looking at.
- When you choose to install something, **Dalamud still does the installing**.

That is basically it.

## I just want to install Omega

Go here:

**https://dalagab.github.io/omega/#install**

The installation page has the current Omega repository link, a copy button, and the steps for adding it to Dalamud.

We intentionally keep the actual repository URL on the website instead of copying it into this README, so there is one obvious place to find the current installation instructions.

## What does Omega do?

Omega looks at public Dalamud plugin repositories and puts the plugins it can find into one in-game marketplace.

It can show things such as:

- what a plugin does;
- who made it;
- where it comes from;
- which repository or repositories publish it;
- available versions;
- dependencies;
- changelogs and project links;
- security information collected by Sigmascope.

Omega does **not** replace Dalamud's plugin installer.

## Is every plugin in Omega safe?

No.

Omega tries to give you **more information**, not make the decision for you.

A plugin appearing in Omega does not mean it is approved, recommended, or guaranteed to be safe. Omega can show public information and static security evidence, but you still choose what you install.

## What is Sigmascope?

Sigmascope is Omega's security scanner.

It examines plugin packages and available source code as **data**. It does not load or run the plugins it scans.

Its job is to collect useful evidence — things like dependencies, capabilities, endpoints, hashes, and other indicators — so Omega can show you more context before you make a choice.

## Where is the website?

**https://dalagab.github.io/omega/**

## Support

For installation help, questions, feedback, or corrections, join the [Omega Discord](https://discord.gg/rMBHbJTjp).


## I am a developer

You are in the right repository.

The production source, tests, catalog tooling, Sigmascope tooling, source definitions, and release automation live here.

A few useful places to start:

- `Omega/` — the Dalamud plugin.
- `Omega.RegressionTests/` — C# regression tests.
- `tools/catalog/` — catalog collection and database generation.
- `tools/security/` — Sigmascope and Security Evidence tooling.
- `sources/` — known plugin repository sources.
- `SECURITY.md` — security architecture and reporting information.
- `CHANGELOG.md` — development and release changes.

The public website is maintained separately on the `website` branch.

## Is Omega wrong about your plugin?

If you maintain a plugin and believe Omega or Sigmascope has described it incorrectly, **please tell us**.

Scanner results are evidence and classifications, not unquestionable verdicts. If a security finding, capability, automation classification, dependency, endpoint, source association, or other result is wrong, we want to know **what was reported and where the scanner went wrong**.

Use the scanner-result correction form:

**https://github.com/dalagab/omega/issues/new?template=scanner-result.yml**

Please include the plugin version, the result you believe is incorrect, what you think the correct result should be, and a link to the source code or other public evidence that lets us verify it.

The goal is not to give individual plugins special treatment. If the scanner logic is wrong, we want to fix the logic so the correction applies consistently to everyone.

## One last thing

Omega is an independent community project. It is not affiliated with Square Enix, Dalamud, XIVLauncher, or FINAL FANTASY XIV.

## Current client interaction notes

- Required resolved plugin dependencies can be opened in the normal Omega install chooser; optional and inferred relationships remain reviewable rather than silently installed.
- Repository-move updates stay in Updates as explicit review items.
- The changelog icon beside an available update opens an **Update changes** panel with the version transition, source repository, and published change text.
