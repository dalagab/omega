# Why I Built Omega

I started Omega because I think the Dalamud plugin ecosystem is one of the most interesting things the FFXIV community has built — and at the same time, one of its biggest strengths is also one of its biggest problems.+

It is open.

There are plugins everywhere.

There are official repositories, third-party repositories, individual developer repositories, forks, testing versions, abandoned projects, revived projects, plugins that depend on other plugins, plugins that move between repositories, and projects that most players will simply never know exist.

I don't think the answer to that is to close the ecosystem.

I think the answer is to **understand it better**.

That is what Omega is ultimately about.

Omega started as a better way to discover plugins. But once you build something that can see a large part of the ecosystem, another question becomes impossible to ignore:

**What exactly are we installing?**

Not just whether a plugin has a nice description.

Not just whether somebody on Discord says they have used it for years.

Not just whether its source repository looks legitimate.

What does the actual plugin contain? What can it do? What does it communicate with? What changed between versions? Does the published source appear to explain the behaviour we observe? Does a new build suddenly do something its previous build did not?

And, importantly:

**Can we answer those questions without pretending that a computer can magically tell us whether a plugin is "good" or "bad"?**

That question is why Omega grew into several separate systems.

## Omega

Omega is the part players actually see.

At its simplest, Omega is a marketplace for Dalamud plugins.

It collects publicly available plugin repositories into one searchable catalogue and tries to show a player enough information to understand what they are looking at: the developer, the source, versions, dependencies, project information and, increasingly, security information.

Omega does not replace Dalamud.

Dalamud still installs and manages the plugin.

Omega helps you make the decision before that happens.

And that distinction is important, because I don't want Omega to become an authority that simply stamps **SAFE** or **UNSAFE** onto software.

Software security does not work like that.

A plugin having network access is not automatically malicious. A plugin writing files is not automatically malicious. Native code is not automatically malicious. Starting another process is not automatically malicious.

But all of those things are useful to know.

My goal is not to remove the user's decision.

My goal is to make it a much better-informed decision.

## SigmaScope

SigmaScope is the static security-analysis side of that idea.

It examines the actual plugin packages Omega discovers, and where possible the corresponding public source code.

It treats those things as **untrusted data**.

It can inspect package structure, hashes, managed assemblies, native components, dependencies, API usage, endpoints, filesystem behaviour, process execution capabilities, networking capabilities and many other characteristics without loading the plugin into Dalamud.

It also integrates specialist evidence such as YARA, ClamAV and dependency-vulnerability information rather than pretending one scanner should replace all of them.

The distinction between an artifact and its source is deliberately preserved.

If I have source code for a plugin, that is useful.

It does **not** automatically prove that the DLL somebody downloaded was built from that source.

Those are different claims, and Omega should say which claim it can actually support.

The same applies to information supplied by developers.

I want developers to be able to say:

> Yes, my plugin uses the network, and this is why.

Or:

> Yes, this contains a native component, and this is what it does.

That information is valuable context.

But a developer declaration should never make a scanner finding disappear.

The observation remains the observation.

The explanation sits beside it.

That is a trust model I think can scale.

## The Interdimensional Rift

Static analysis can tell us an enormous amount, but eventually you run into a fundamental limitation:

Code can contain the capability to do something without actually doing it.

So I built the **Interdimensional Rift**.

Rift is an isolated runtime observation environment.

It is where we can take a plugin and ask a different question:

**What happens when this thing actually runs?**

That obviously creates a much more serious security problem. You cannot safely answer that question by executing arbitrary plugins on a normal machine and hoping for the best.

So Rift is built around containment.

The current Linux design layers a disposable host, resource controls, namespaces, an isolated network environment, filesystem allowlisting, dropped capabilities, seccomp restrictions, bounded temporary filesystems, process limits, memory limits and hard timeouts around a small instrumented runtime.

The plugin does not get the runner's home directory.

It does not get the repository checkout.

It does not get GitHub credentials.

It does not get Docker sockets.

It does not get a normal network route.

And the instrumentation itself is not considered the security boundary.

The outside containment is.

I even built two reference systems specifically because I don't think a security system should merely assume that it works.

**Canary** tests the Rift itself.

It checks that the containment we think exists really exists.

And **Alpha** is a deliberately suspicious-looking but harmless reference subject. It contains signals that SigmaScope and Rift are expected to recognize and harmless runtime probes that let us test whether those observations are still visible.

In other words:

Canary asks, **"Is the laboratory still sealed?"**

Alpha asks, **"Are the instruments still working?"**

A successful Rift run still does not declare a plugin safe.

Rift reports what it observed.

And "not observed" means exactly that: **not observed during this scenario**.

Nothing more.

## DeltaScope

Once you start collecting all of this evidence, another problem appears.

Security data is useless if nobody can investigate it.

That is why DeltaScope exists.

DeltaScope is the researcher and developer workbench.

It is where SigmaScope findings, Rift observations, historical information, endpoints, source attribution, antivirus evidence, YARA matches, dependencies and relationships can be investigated together.

I deliberately do not want DeltaScope quietly modifying production security data because somebody clicked a button.

Production evidence is read-only there.

Findings don't disappear because an investigator dislikes them.

Rules don't become active because somebody experimented with one.

A researcher can investigate, reproduce, compare, write and test rules, and then propose a change through a reviewed process.

That separation is intentional.

Security research should be powerful.

Security publication should be controlled.

Those are not the same operation.

## SRL

This leads to perhaps the part of the project I am most interested in long-term: the **SigmaScope Rule Language**, or SRL.

SRL is a deterministic, non-executable rule language.

It lets us describe things like:

> If we observe this capability and this behaviour under these conditions, produce this fact.

And then:

> If these facts occur together, produce this security finding.

The important part is that this becomes reviewable knowledge rather than another pile of hard-coded `if` statements buried inside a scanner.

Rules can have IDs.

They can have explanations.

They can have fixtures.

They can have positive tests.

They can have near-miss negative tests.

They can be replayed against retained observations.

They can be reviewed in Git.

They can be versioned as part of frozen security definitions.

And because the language is deliberately non-executable, a security rule cannot become arbitrary code running inside the scanner.

The pipeline is intentionally one-directional:

**observations → facts → correlations → findings**

That makes the logic much easier to reason about.

It also gives us something I think will become extremely valuable: the ability to improve our understanding of old evidence.

If the observations required by a new rule were already retained, we can potentially re-evaluate them without downloading and parsing the plugin again.

If the required evidence was **not** collected, the correct answer is not "no finding."

The correct answer is:

**we need to look again.**

That opens the door to targeted re-analysis and deeper scans instead of endlessly re-scanning everything or, worse, treating missing information as clean information.

I am deliberately being conservative with this transition. SRL is being built, parity-tested and replay-tested before it becomes the production authority. I would rather keep an older known system running for longer than replace it with a clever new system before we have evidence that the new one behaves correctly.

## Why I think this can work

Because the system does not depend on everybody trusting me.

In fact, I specifically don't want it to.

The interesting part of Omega is not a score I invented.

It is the evidence underneath it.

A hash can be checked.

An endpoint can be checked.

A dependency can be checked.

A YARA rule can be read.

An SRL rule can be read.

A source association can be challenged.

A finding can be reproduced.

A scanner bug can have a regression test.

A developer can explain legitimate behaviour.

A security researcher can demonstrate why that explanation does or does not match the artifact.

And when we are wrong — because at some point we absolutely will be — I don't want the solution to be manually changing one plugin from red to green.

I want to find out **why the system was wrong** and fix the rule, parser, observation or attribution logic so every plugin benefits from the correction.

That, to me, is the difference between a reputation system and a security system.

## What I hope this does for plugin developers

I don't want SigmaScope to become a machine for accusing developers.

Quite the opposite.

Most unusual behaviour has a perfectly legitimate explanation.

A launcher may need to start a process.

A synchronization plugin obviously needs a network connection.

A plugin managing large amounts of local information will write files.

Something integrating native functionality will contain native code.

Showing that clearly can actually help legitimate developers.

Instead of:

> "This plugin looks scary."

we can eventually have:

> "This plugin communicates with these services, stores these files, uses these capabilities, includes these components, and the developer explains why here."

That is a much healthier conversation.

It can also help developers notice things they did not intend.

A dependency may introduce an endpoint they were unaware of.

A build pipeline may package something accidentally.

A compromised dependency may suddenly change behaviour.

A repository migration may produce an artifact different from the expected baseline.

A new release may acquire capabilities the previous releases never had.

Those do not have to begin as accusations.

They can begin as observations.

And observations can be investigated.

## What I hope this does for security researchers

I want researchers to have something better than periodically downloading random plugins and starting from zero.

Imagine an ecosystem where changes are continuously recorded.

Where historical artifacts have identities.

Where source attribution is preserved.

Where new high-signal behaviour can automatically become interesting.

Where a rule can be developed against real retained evidence.

Where a suspicious divergence can be sent for deeper analysis.

Where static evidence and isolated runtime observations can be viewed side by side.

Where findings have provenance all the way back to the rule and security-definition snapshot that produced them.

That turns individual security research into something cumulative.

Every good rule makes the next scan better.

Every false positive can improve a rule.

Every newly understood capability improves the vocabulary.

Every confirmed malicious technique can become a detection other researchers can inspect.

The system gets more useful because people interact with it.

## And what I hope this does for players

Mostly, I want to replace this:

> "Someone told me this plugin is fine."

with something closer to this:

> "I understand what this plugin is, where it came from, what Omega observed, what changed, what the developer says it does, and what risks I am accepting."

That is still not certainty.

There is no scanner I can build that makes installing arbitrary third-party code risk-free.

Omega will never honestly be able to promise that every plugin it lists is safe.

But there is an enormous amount of space between **blind trust** and **perfect certainty**.

I think we can do much better in that space.

## One thing I also want to be transparent about: AI

A huge amount of AI assistance has been used while building Omega and the systems around it.

I don't see a reason to hide that.

AI has helped with development, architecture discussions, reviewing ideas, documentation, testing strategies and challenging decisions.

But AI is **not the security authority inside Omega**.

There is no language model deciding that your plugin is dangerous.

There is no AI generating a secret reputation score.

SigmaScope's observations are produced by code. SRL rules are deterministic. Findings can be traced back to their inputs and definitions. Rift produces recorded observations. The important security decisions are intended to remain reproducible and inspectable.

I started writing code in the 80's on computers with black and white screen.
I am more then happy to admit, that the machine can write better code.

I am perfectly comfortable using AI to help build the machine.

I am not comfortable asking everyone to trust an AI because it said the machine found something.

## Where I want this to go

I don't want Omega to become the police of the plugin ecosystem.

I want it to become **infrastructure for understanding the plugin ecosystem**.

Omega discovers.

SigmaScope examines.

Rift observes.

DeltaScope investigates.

SRL turns what we learn into reproducible knowledge.

And then Omega brings the useful part of that knowledge back to the player.

If we do this properly, a security finding does not just make one plugin look bad.

It can make the ecosystem better.

It can lead to a corrected dependency.

A safer release.

A documented capability.

A fixed scanner.

A new detection rule.

A deeper investigation.

A warning before somebody gets hurt.

Or sometimes simply a clear explanation that something unusual is completely intentional.

That is why I made this.

Not because I think every third-party plugin is dangerous.

And not because I think I can decide what everyone else should be allowed to run.

I made it because an open ecosystem deserves open tools for understanding it.

**I don't want Omega to tell you what to trust.**

**I want Omega to give you better reasons for deciding what you trust.**