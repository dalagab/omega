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

## One last thing

Omega is an independent community project. It is not affiliated with Square Enix, Dalamud, XIVLauncher, or FINAL FANTASY XIV.
