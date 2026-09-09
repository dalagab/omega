(() => {
  'use strict';

  document.title = 'Omega Marketplace — A simpler FFXIV plugin browser';

  const styleId = 'omega-eli5-brand-refresh-style';
  if (!document.getElementById(styleId)) {
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      html { scroll-snap-type: none !important; }
      .story-panel { scroll-snap-align: none !important; scroll-snap-stop: normal !important; }
      #content { display: flex !important; flex-direction: column !important; }
      .omega-eli5-hidden { display: none !important; }
      #overview { order: 0 !important; }
      #install-flow { order: 10 !important; }
      #why { order: 20 !important; }
      #install { order: 30 !important; }
      #team { order: 40 !important; display: block !important; }
      #sigmascope { order: 50 !important; display: block !important; }
      #omega-eli5-faq { order: 60 !important; }
    `;
    document.head.appendChild(style);
  }

  window.addEventListener('wheel', (event) => {
    event.stopImmediatePropagation();
  }, { capture: true, passive: true });

  const main = document.querySelector('#content');
  if (!main) return;

  const keepIds = new Set(['overview', 'install-flow', 'why', 'install', 'team', 'sigmascope']);
  for (const child of Array.from(main.children)) {
    if (child.tagName !== 'SECTION') continue;
    const id = child.id || '';
    if (keepIds.has(id)) continue;
    child.classList.add('omega-eli5-hidden');
  }

  const overview = document.querySelector('#overview');
  if (overview) {
    overview.innerHTML = `
      <div class="absolute inset-0 -z-10">
        <div class="absolute inset-0 bg-gradient-to-r from-omega-950 via-omega-950/75 to-omega-950/25"></div>
        <div class="absolute inset-0 bg-gradient-to-t from-omega-950/90 via-transparent to-omega-950/35"></div>
        <div class="command-grid absolute inset-0 opacity-40"></div>
      </div>
      <div class="mx-auto grid min-h-[100svh] max-w-7xl gap-10 px-4 py-16 sm:px-6 lg:grid-cols-[1.05fr_.95fr] lg:items-center lg:px-8 lg:py-24">
        <div class="relative z-10 max-w-xl rounded-[2rem] border border-white/15 bg-omega-950/90 p-6 shadow-2xl backdrop-blur-md sm:p-9">
          <div class="mb-5 inline-flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[.04] px-4 py-3">
            <img src="assets/brand/omega-marketplace-logo.png" alt="Omega Marketplace logo" class="h-14 w-14 object-contain">
            <div>
              <p class="text-xs font-black uppercase tracking-[.18em] text-omega-cyan">Omega Marketplace</p>
              <p class="text-sm text-slate-300">For Final Fantasy XIV</p>
            </div>
          </div>
          <h1 class="hero-copy max-w-2xl text-4xl font-black tracking-[-.055em] text-white sm:text-5xl lg:text-6xl">A simpler way to find FFXIV plugins.</h1>
          <p class="mt-5 max-w-lg text-base leading-7 text-slate-200 sm:text-lg sm:leading-8">Omega lets you browse plugins from Dalamud and custom repositories in one place. You do not have to hunt around different lists to figure out what is out there.</p>
          <p class="mt-4 max-w-lg leading-7 text-slate-300">You can search, read what a plugin does, see where it comes from, and notice warnings before you choose to install it.</p>
          <p class="mt-5 rounded-2xl border border-omega-cyan/20 bg-omega-cyan/[.04] p-4 text-sm leading-6 text-slate-200"><strong class="text-white">Omega does not replace Dalamud.</strong> Omega helps you decide. Dalamud still handles installing, updating, disabling, and removing plugins.</p>
        </div>
        <div class="space-y-4">
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/brand/omega-marketplace-banner.png" alt="Omega Marketplace banner art" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">The new Omega Marketplace banner brings the brand to the front of the page.</figcaption>
          </figure>
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-main.png" alt="Omega main marketplace view inside the game" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">This is the in-game marketplace view players actually use.</figcaption>
          </figure>
        </div>
      </div>
    `;
  }

  const installFlow = document.querySelector('#install-flow');
  if (installFlow) {
    installFlow.innerHTML = `
      <div id="how-it-works" class="mx-auto grid min-h-[100svh] max-w-7xl gap-10 px-4 py-16 sm:px-6 lg:grid-cols-2 lg:items-center lg:px-8">
        <div>
          <p class="eyebrow text-xs font-black uppercase text-omega-cyan">What Omega adds</p>
          <h2 class="hero-copy mt-4 max-w-2xl text-4xl font-black tracking-tight text-white sm:text-6xl">Dalamud installs plugins.<br>Omega helps you choose them.</h2>
          <p class="mt-5 max-w-xl text-lg leading-8 text-slate-200">Omega sits on top of the normal plugin flow and gives you more useful information before you click install.</p>
          <div class="mt-8 space-y-4">
            <article class="rounded-2xl border border-white/10 bg-omega-950/65 p-5">
              <p class="text-xs font-black uppercase tracking-wider text-omega-cyan">01 · One easy place to browse</p>
              <h3 class="mt-2 text-xl font-black text-white">Dalamud and custom repositories feel like one marketplace.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">You get the same layout, search, and filters instead of every repository feeling like its own separate world.</p>
            </article>
            <article class="rounded-2xl border border-white/10 bg-omega-950/65 p-5">
              <p class="text-xs font-black uppercase tracking-wider text-omega-gold">02 · Better plugin pages</p>
              <h3 class="mt-2 text-xl font-black text-white">See the useful stuff before you install.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">Omega can show screenshots, source information, versions, compatibility, dependencies, and warnings together in one place.</p>
            </article>
            <article class="rounded-2xl border border-omega-cyan/25 bg-omega-cyan/[.045] p-5">
              <p class="text-xs font-black uppercase tracking-wider text-omega-400">03 · Clearer choices</p>
              <h3 class="mt-2 text-xl font-black text-white">If the same plugin appears more than once, you can see that.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-200">Omega can show when more than one source offers the same plugin, so you are not blindly picking between look-alikes.</p>
            </article>
          </div>
        </div>
        <div class="space-y-4">
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-filters.png" alt="Omega marketplace filters for authors, repositories, categories, compatibility, security and content" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">Search and filters work across the whole marketplace.</figcaption>
          </figure>
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-source-select.png" alt="Omega showing several repositories that provide the same plugin and marking a preferred source" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">If several sources provide a plugin, Omega can show the choice before you install.</figcaption>
          </figure>
        </div>
      </div>
    `;
  }

  const why = document.querySelector('#why');
  if (why) {
    why.innerHTML = `
      <div class="mx-auto max-w-7xl">
        <div class="max-w-4xl">
          <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Why Omega is needed</p>
          <h2 class="hero-copy mt-4 text-3xl font-black tracking-tight text-white sm:text-5xl">A plugin can look harmless and still do a lot.</h2>
          <p class="mt-5 text-lg leading-8 text-slate-200">Omega cannot know for sure if a plugin is safe. What it can do is point out things you may want to know before you install it.</p>
          <p class="mt-5 leading-7 text-slate-300">That can include whether a plugin connects to the internet, changes files, automates parts of the game, relies on other tools, or comes from a different source than expected. If something looks unusual, Omega tells you. You still decide whether to install it.</p>
        </div>
        <div class="mt-10 grid gap-5 lg:grid-cols-3">
          <article class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/omega-install-plugin.png" alt="A normal-looking Omega plugin page with an install button" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-cyan">01 · It can look normal</p>
              <h3 class="mt-2 text-xl font-black text-white">A nice description does not show everything.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">A plugin page can look simple and friendly while the software behind it is still powerful.</p>
            </div>
          </article>
          <article class="overflow-hidden rounded-[2rem] border border-omega-gold/25 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/omega-install-warning.png" alt="Omega warning that a plugin can automate gameplay before installation" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-gold">02 · Omega can warn you</p>
              <h3 class="mt-2 text-xl font-black text-white">Important stuff gets explained in plain English.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">If Omega spots something worth noticing, it can stop and explain it before you continue.</p>
            </div>
          </article>
          <article class="overflow-hidden rounded-[2rem] border border-omega-400/25 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/source-trust.png" alt="Omega showing package and source history with different security states" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-400">03 · Not every copy is the same</p>
              <h3 class="mt-2 text-xl font-black text-white">The same plugin name can come from different places.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">Omega keeps the source, version, and warning information together so those differences are easier to spot.</p>
            </div>
          </article>
        </div>
      </div>
    `;
  }

  const install = document.querySelector('#install');
  if (install) {
    install.innerHTML = `
      <div class="mx-auto max-w-5xl rounded-[2rem] border border-omega-cyan/20 bg-omega-950/70 p-7 shadow-2xl backdrop-blur-sm sm:p-10" data-reveal>
        <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Install Omega</p>
        <h2 class="mt-4 text-3xl font-black text-white sm:text-5xl">Ready to try it?</h2>
        <p class="mt-5 max-w-3xl text-lg leading-8 text-slate-200">Omega is added through Dalamud, using the normal Custom Plugin Repositories feature.</p>

        <div class="mt-7 rounded-[2rem] border border-red-300/40 bg-red-500/10 p-6">
          <div class="flex items-center gap-4">
            <span aria-hidden="true" class="grid size-16 shrink-0 place-items-center rounded-2xl border border-red-300/70 bg-red-500/20 text-4xl font-black text-red-200 shadow-[0_0_36px_rgba(248,113,113,.35)]">⚠</span>
            <div>
              <p class="eyebrow text-xs font-black uppercase text-red-200">Read before installing</p>
              <p class="mt-2 font-bold text-white">Plugins are software running on your computer.</p>
            </div>
          </div>
          <p class="mt-5 max-w-3xl leading-7 text-slate-200">Omega helps you understand what you are installing, but it cannot make that choice for you. Plugins can access game-related data and some can automate gameplay, which can put an account at risk.</p>
          <p class="mt-4 max-w-3xl rounded-2xl border border-omega-gold/25 bg-omega-gold/[.06] p-4 leading-7 text-slate-100"><strong class="text-omega-gold">Omega is alpha software.</strong> It may still break, and some information may be missing or wrong.</p>
        </div>

        <button type="button" data-omega-install-start aria-expanded="false" class="mt-7 inline-flex min-h-12 items-center justify-center rounded-2xl bg-white px-6 py-3 font-black text-omega-950 hover:bg-omega-cyan">Install Omega</button>
        <p class="mt-3 text-sm leading-6 text-slate-400">This button does not install anything by itself. It shows the quick steps below.</p>

        <div data-omega-install-steps hidden class="mt-8 border-t border-white/10 pt-8">
          <div class="grid gap-10 lg:grid-cols-2 lg:items-center">
            <div>
              <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Three quick steps</p>
              <ol class="mt-6 space-y-5">
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-400/10 text-sm font-black text-omega-400">1</span><div><strong class="text-white">Open Dalamud settings.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Find <strong class="text-slate-200">Custom Plugin Repositories</strong>.</p></div></li>
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-cyan/10 text-sm font-black text-omega-cyan">2</span><div><strong class="text-white">Add the Omega repository URL.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Copy the link below, add it, and make sure the repository is enabled.</p></div></li>
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-gold/10 text-sm font-black text-omega-gold">3</span><div><strong class="text-white">Open <code>/xlplugins</code> and search for Omega.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Install it like a normal Dalamud plugin.</p></div></li>
              </ol>
              <div class="mt-7 overflow-x-auto rounded-2xl border border-white/10 bg-black/25 p-4 code-scroll"><code id="repo-url" class="whitespace-pre text-xs text-slate-300 sm:text-sm">https://github.com/dalagab/omega/releases/download/omega-latest/pluginmaster.json</code></div>
              <button data-copy="#repo-url" class="mt-3 inline-flex min-h-11 items-center rounded-xl border border-omega-cyan/25 px-4 text-sm font-black text-omega-cyan transition hover:border-omega-cyan/60 hover:text-white">Copy repository URL</button>
            </div>
            <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
              <div data-screenshot-slot="dalamud-custom-repo.png" data-alt="Dalamud Custom Plugin Repositories settings" class="min-h-[20rem]"></div>
              <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">Add Omega the same way you add any other custom Dalamud repository.</figcaption>
            </figure>
          </div>
        </div>
      </div>
    `;

    const installButton = install.querySelector('[data-omega-install-start]');
    const installSteps = install.querySelector('[data-omega-install-steps]');
    if (installButton && installSteps) {
      installButton.addEventListener('click', () => {
        installSteps.hidden = false;
        installButton.hidden = true;
        installButton.setAttribute('aria-expanded', 'true');
      });
    }
  }

  const team = document.querySelector('#team');
  if (team) {
    const heading = team.querySelector('h2');
    if (heading) heading.textContent = 'Who made Omega?';
    const eyebrow = team.querySelector('.eyebrow');
    if (eyebrow) eyebrow.textContent = 'The team behind Omega';
    const cards = team.querySelectorAll('article');
    if (cards[0]) {
      const p = cards[0].querySelector('p:last-of-type');
      if (p) p.textContent = 'Omega’s mascot and resident data gremlin. TONI likes records, patterns, and spotting odd things in public plugin information.';
    }
    if (cards[1]) {
      const p = cards[1].querySelector('p:last-of-type');
      if (p) p.textContent = 'The human behind the project. Wants players to have a clearer and easier way to understand what they are installing.';
    }
    if (cards[2]) {
      const p = cards[2].querySelector('p:last-of-type');
      if (p) p.textContent = 'The quiet security specialists. They help keep the safety side grounded in real defensive-security experience.';
    }
  }

  const sigmascope = document.querySelector('#sigmascope');
  if (sigmascope) {
    sigmascope.innerHTML = `
      <div class="mx-auto grid min-h-[100svh] max-w-7xl content-center gap-10 px-4 py-16 sm:px-6 lg:px-8 lg:py-20">
        <div class="max-w-3xl">
          <p class="eyebrow text-xs font-black uppercase text-omega-cyan">How Omega gets its info</p>
          <h2 class="hero-copy mt-4 text-3xl font-black tracking-tight text-white sm:text-5xl">Sigmascope looks for useful clues.</h2>
          <p class="mt-5 text-lg leading-8 text-slate-200">Sigmascope is the checking system behind Omega. It inspects plugin files and public information so Omega has more to show than just a name and an Install button.</p>
        </div>
        <div class="grid gap-4 md:grid-cols-3">
          <article class="rounded-[1.8rem] border border-omega-cyan/20 bg-omega-950/85 p-6 backdrop-blur-md">
            <p class="text-sm font-black uppercase tracking-[.18em] text-omega-cyan">It does not run the plugin</p>
            <h3 class="mt-3 text-2xl font-black text-white">It reads files, it does not execute them.</h3>
            <p class="mt-3 leading-7 text-slate-300">That matters because Omega is trying to inspect software, not launch it.</p>
          </article>
          <article class="rounded-[1.8rem] border border-white/10 bg-omega-950/85 p-6 backdrop-blur-md">
            <p class="text-sm font-black uppercase tracking-[.18em] text-omega-gold">It looks for things worth noticing</p>
            <h3 class="mt-3 text-2xl font-black text-white">Connections, files, automation, and other clues.</h3>
            <p class="mt-3 leading-7 text-slate-300">The goal is not to scare players. The goal is to show useful context before they install something.</p>
          </article>
          <article class="rounded-[1.8rem] border border-omega-400/20 bg-omega-950/85 p-6 backdrop-blur-md">
            <p class="text-sm font-black uppercase tracking-[.18em] text-omega-400">It is not magic</p>
            <h3 class="mt-3 text-2xl font-black text-white">No scan can prove a plugin is safe.</h3>
            <p class="mt-3 leading-7 text-slate-300">Sigmascope helps Omega point out what is visible. You still make the final choice.</p>
          </article>
        </div>
      </div>
    `;
  }

  let faq = document.querySelector('#omega-eli5-faq');
  if (!faq) {
    faq = document.createElement('section');
    faq.id = 'omega-eli5-faq';
    faq.className = 'border-y border-white/10 bg-white/[.025]';
    main.appendChild(faq);
  }
  faq.innerHTML = `
    <div class="mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8 lg:py-24">
      <p class="eyebrow text-xs font-black uppercase text-omega-gold">FAQ</p>
      <h2 class="mt-4 text-3xl font-black text-white sm:text-5xl">Quick answers in normal English.</h2>
      <div class="mt-8 space-y-3">
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega replace Dalamud?</summary><p class="mt-3 leading-7 text-slate-400">No. Dalamud still installs, updates, disables, and removes plugins. Omega helps you browse and understand them.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega know if a plugin is safe?</summary><p class="mt-3 leading-7 text-slate-400">No. Omega cannot promise that. It can only show warnings, clues, and extra information that may help you decide.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">What kind of warnings can Omega show?</summary><p class="mt-3 leading-7 text-slate-400">Things like internet connections, file access, automation, or other details that may matter when deciding whether you trust a plugin.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega install plugins by itself?</summary><p class="mt-3 leading-7 text-slate-400">No. Omega does not bypass the normal plugin flow. You still install through Dalamud.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega scan my computer or my personal data?</summary><p class="mt-3 leading-7 text-slate-400">No. Omega’s safety information comes from checking public plugin files and public plugin information, not from scanning your PC.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Sigmascope run plugins while checking them?</summary><p class="mt-3 leading-7 text-slate-400">No. It inspects them without executing them.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega use AI to scan plugins?</summary><p class="mt-3 leading-7 text-slate-400">No. The plugin-checking side does not use AI verdicts. It uses deterministic checks and recorded evidence.</p></details>
      </div>
    </div>
  `;
})();
