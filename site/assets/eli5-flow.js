(() => {
  'use strict';

  const styleId = 'omega-eli5-flow-style';
  if (!document.getElementById(styleId)) {
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      html { scroll-snap-type: none !important; }
      .story-panel { scroll-snap-align: none !important; scroll-snap-stop: normal !important; }
      #content { display: flex !important; flex-direction: column !important; }
      #overview { order: 0 !important; }
      #install-flow { order: 10 !important; }
      #why { order: 20 !important; }
      #install { order: 30 !important; }
      #team { display: block !important; order: 40 !important; }
      #sigmascope { display: block !important; order: 50 !important; }
      #about + section { display: block !important; order: 60 !important; }
      #ai-faq { display: block !important; order: 61 !important; }
      #faq, #about, #aetherfeed-note { display: none !important; }
      .manifesto-link { display: none !important; }
    `;
    document.head.appendChild(style);
  }

  // The old story page catches the mouse wheel and jumps one panel at a time.
  // Register first, in capture phase, so the existing handler never turns the
  // new long-form page back into a slideshow.
  window.addEventListener('wheel', (event) => {
    event.stopImmediatePropagation();
  }, { capture: true, passive: true });

  const installFlow = document.querySelector('#install-flow');
  if (installFlow) {
    installFlow.innerHTML = `
      <div id="how-it-works" class="mx-auto grid min-h-[100svh] max-w-7xl gap-10 px-4 py-16 sm:px-6 lg:grid-cols-2 lg:items-center lg:px-8">
        <div>
          <p class="eyebrow text-xs font-black uppercase text-omega-cyan">What Omega adds</p>
          <h2 class="hero-copy mt-4 max-w-2xl text-4xl font-black tracking-tight text-white sm:text-6xl">Dalamud installs plugins.<br>Omega makes choosing one easier.</h2>
          <p class="mt-5 max-w-xl text-lg leading-8 text-slate-200">Omega does not replace Dalamud. It adds a clearer layer on top of the plugin system you already use.</p>
          <div class="mt-8 space-y-4">
            <article class="rounded-2xl border border-white/10 bg-omega-950/65 p-5">
              <p class="text-xs font-black uppercase tracking-wider text-omega-cyan">01 · One familiar marketplace</p>
              <h3 class="mt-2 text-xl font-black text-white">Dalamud and custom repositories, shown the same way.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">Plugins from different repositories use the same layout, search, filters, and plugin pages. You do not have to learn how every repository is organised.</p>
            </article>
            <article class="rounded-2xl border border-white/10 bg-omega-950/65 p-5">
              <p class="text-xs font-black uppercase tracking-wider text-omega-gold">02 · More useful information</p>
              <h3 class="mt-2 text-xl font-black text-white">See more than a name and an Install button.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">Omega can show descriptions, screenshots, compatibility, source information, versions, dependencies, and security findings together on the plugin page.</p>
            </article>
            <article class="rounded-2xl border border-omega-cyan/25 bg-omega-cyan/[.045] p-5">
              <p class="text-xs font-black uppercase tracking-wider text-omega-400">03 · Clearer source choices</p>
              <h3 class="mt-2 text-xl font-black text-white">Know which copy you are choosing.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-200">When the same plugin is available from more than one repository, Omega can show the available sources and identify its preferred known source instead of treating every package as identical.</p>
            </article>
          </div>
        </div>
        <div class="space-y-4">
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-filters.png" alt="Omega marketplace filters for authors, repositories, categories, compatibility, security and content" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">Dalamud and custom-repository plugins use the same search and filters.</figcaption>
          </figure>
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-source-select.png" alt="Omega showing several repositories that provide the same plugin and marking a preferred source" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">If several repositories provide a plugin, Omega can show the choice before installation.</figcaption>
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
          <h2 class="hero-copy mt-4 text-3xl font-black tracking-tight text-white sm:text-5xl">A plugin can look harmless and still be powerful software.</h2>
          <p class="mt-5 text-lg leading-8 text-slate-200">A Final Fantasy XIV plugin is software running on your computer. Useful plugins may need to connect to the internet, read or write files, talk to other plugins, hook into the game, or automate parts of gameplay. Those abilities are not automatically bad&mdash;many good plugins need them&mdash;but they are worth knowing about.</p>
          <p class="mt-5 leading-7 text-slate-300"><strong class="text-white">Omega cannot promise that a plugin is safe.</strong> It tries to keep players safer by making important capabilities, known dependency problems, package differences, and missing information visible before you install.</p>
        </div>
        <div class="mt-10 grid gap-5 lg:grid-cols-3">
          <article class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/omega-install-plugin.png" alt="A normal-looking Omega plugin page with an install button" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-cyan">01 · It can look completely normal</p>
              <h3 class="mt-2 text-xl font-black text-white">A description does not show every capability.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">A plugin can look simple and trustworthy while the software behind it has much more access than the description needs to explain.</p>
            </div>
          </article>
          <article class="overflow-hidden rounded-[2rem] border border-omega-gold/25 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/omega-install-warning.png" alt="Omega warning that a plugin can automate gameplay before installation" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-gold">02 · Warn before you install</p>
              <h3 class="mt-2 text-xl font-black text-white">Explain the important bit in normal English.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">When Omega sees a capability that deserves attention, it can stop and explain it before you continue. A warning is context, not an accusation that the plugin is malicious.</p>
            </div>
          </article>
          <article class="overflow-hidden rounded-[2rem] border border-omega-400/25 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/source-trust.png" alt="Omega showing package and source history with different security states" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-400">03 · Compare what is actually offered</p>
              <h3 class="mt-2 text-xl font-black text-white">The same plugin name can come from different packages.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">Omega keeps source, version, package, and scan information together so meaningful differences are visible instead of hidden behind the same plugin name.</p>
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
        <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Installation</p>
        <h2 class="mt-4 text-3xl font-black text-white sm:text-5xl">Ready to try Omega?</h2>
        <p class="mt-5 max-w-3xl text-lg leading-8 text-slate-200">Omega itself is installed through Dalamud, using the normal Custom Plugin Repositories feature.</p>

        <div class="mt-7 rounded-[2rem] border border-red-300/40 bg-red-500/10 p-6">
          <div class="flex items-center gap-4">
            <span aria-hidden="true" class="grid size-16 shrink-0 place-items-center rounded-2xl border border-red-300/70 bg-red-500/20 text-4xl font-black text-red-200 shadow-[0_0_36px_rgba(248,113,113,.35)]">⚠</span>
            <div>
              <p class="eyebrow text-xs font-black uppercase text-red-200">Read before installing</p>
              <p class="mt-2 font-bold text-white">Plugins are software running on your computer.</p>
            </div>
          </div>
          <p class="mt-5 max-w-3xl leading-7 text-slate-200">They can access data and resources available to the game process and your Windows user, and automation can put an FFXIV account at risk. Omega provides information and warnings, not a guarantee that software is safe.</p>
          <p class="mt-4 max-w-3xl rounded-2xl border border-omega-gold/25 bg-omega-gold/[.06] p-4 leading-7 text-slate-100"><strong class="text-omega-gold">Omega is alpha software.</strong> It may break, and its data may be incomplete or wrong. Reports, corrections, testing, and other help are appreciated.</p>
        </div>

        <button type="button" data-eli5-install-start aria-expanded="false" class="mt-7 inline-flex min-h-12 items-center justify-center rounded-2xl bg-white px-6 py-3 font-black text-omega-950 hover:bg-omega-cyan">Install Omega</button>
        <p class="mt-3 text-sm leading-6 text-slate-400">Nothing is installed directly from this website. The button shows the simple Dalamud steps below.</p>

        <div data-eli5-install-steps hidden class="mt-8 border-t border-white/10 pt-8">
          <div class="grid gap-10 lg:grid-cols-2 lg:items-center">
            <div>
              <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Three steps</p>
              <ol class="mt-6 space-y-5">
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-400/10 text-sm font-black text-omega-400">1</span><div><strong class="text-white">Open Dalamud settings.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Find <strong class="text-slate-200">Custom Plugin Repositories</strong>.</p></div></li>
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-cyan/10 text-sm font-black text-omega-cyan">2</span><div><strong class="text-white">Add the Omega repository URL.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Copy the URL below, add it to the list, and make sure it is enabled.</p></div></li>
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-gold/10 text-sm font-black text-omega-gold">3</span><div><strong class="text-white">Open <code>/xlplugins</code> and search for Omega.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Choose Install. Dalamud handles updates and removal normally afterwards.</p></div></li>
              </ol>
              <div class="mt-7 overflow-x-auto rounded-2xl border border-white/10 bg-black/25 p-4 code-scroll"><code id="repo-url" class="whitespace-pre text-xs text-slate-300 sm:text-sm">https://github.com/dalagab/omega/releases/download/omega-latest/pluginmaster.json</code></div>
              <button data-copy="#repo-url" class="mt-3 inline-flex min-h-11 items-center rounded-xl border border-omega-cyan/25 px-4 text-sm font-black text-omega-cyan transition hover:border-omega-cyan/60 hover:text-white">Copy repository URL</button>
            </div>
            <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
              <div data-screenshot-slot="dalamud-custom-repo.png" data-alt="Dalamud Custom Plugin Repositories settings" class="min-h-[20rem]"></div>
              <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">Add Omega exactly like any other Dalamud custom repository.</figcaption>
            </figure>
          </div>
        </div>
      </div>
    `;

    const button = install.querySelector('[data-eli5-install-start]');
    const steps = install.querySelector('[data-eli5-install-steps]');
    if (button && steps) {
      button.addEventListener('click', () => {
        steps.hidden = false;
        button.setAttribute('aria-expanded', 'true');
        button.hidden = true;
      });
    }
  }
})();
