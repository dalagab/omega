(() => {
  'use strict';

  document.title = 'Omega Marketplace — FFXIV plugins made simpler';

  const styleId = 'omega-eli5-v9-style';
  if (!document.getElementById(styleId)) {
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      html { scroll-behavior: smooth !important; }
      body { overflow-y: auto !important; }
      .story-panel {
        min-height: 100svh !important;
        scroll-snap-align: start !important;
        scroll-snap-stop: always !important;
      }
      #content {
        display: flex !important;
        flex-direction: column !important;
        overflow: visible !important;
      }
      .omega-eli5-v9-hidden { display: none !important; }
      #overview { order: 0 !important; background: #05070d !important; padding: 0 !important; min-height: 100svh !important; }
      #overview::before, #overview::after { display: none !important; content: none !important; }
      .scene-omega { background: #05070d !important; background-image: none !important; }
      #overview > .mx-auto { max-width: none !important; }
      #install-flow { order: 10 !important; min-height: 100svh !important; }
      #why { order: 20 !important; min-height: 100svh !important; }
      #install {
        order: 30 !important;
        min-height: 100svh !important;
        display: grid !important;
        align-items: center !important;
      }
      #team {
        order: 40 !important;
        min-height: 100svh !important;
        display: grid !important;
        align-items: center !important;
      }
      #aetherfeed-note {
        order: 50 !important;
        min-height: 100svh !important;
        display: grid !important;
        align-items: center !important;
        scroll-snap-align: start !important;
        scroll-snap-stop: always !important;
      }
      #omega-eli5-v9-faq {
        order: 60 !important;
        min-height: 100svh !important;
        scroll-snap-align: start !important;
        scroll-snap-stop: always !important;
      }
    `;
    document.head.appendChild(style);
  }

  const main = document.querySelector('#content');
  if (!main) return;

  const keepIds = new Set(['overview', 'install-flow', 'why', 'install', 'team', 'aetherfeed-note']);
  for (const child of Array.from(main.children)) {
    if (child.tagName !== 'SECTION') continue;
    const id = child.id || '';
    if (keepIds.has(id)) continue;
    child.classList.add('omega-eli5-v9-hidden');
  }

  const overview = document.querySelector('#overview');
  if (overview) {
    overview.innerHTML = `
      <div class="relative min-h-[100svh] w-full overflow-hidden bg-omega-950">
        <img src="assets/brand/omega-marketplace-top-banner.png" alt="Omega Marketplace fantasy banner art" class="absolute inset-0 h-full w-full object-cover">
        <div class="absolute inset-0 bg-gradient-to-r from-black/55 via-black/18 to-black/55"></div>
        <div class="absolute inset-0 bg-gradient-to-b from-black/18 via-transparent to-black/30"></div>

        <div class="relative hidden min-h-[100svh] w-full lg:block">
          <article class="absolute left-10 top-1/2 max-w-md -translate-y-1/2 rounded-[1.8rem] border border-white/10 bg-omega-950/88 p-7 shadow-2xl backdrop-blur-md xl:left-16 xl:max-w-lg">
            <p class="text-xs font-black uppercase tracking-[.18em] text-omega-cyan">For Final Fantasy XIV players</p>
            <h1 class="mt-4 text-4xl font-black tracking-tight text-white xl:text-6xl">Find FFXIV plugins in one place.</h1>
            <p class="mt-4 text-base leading-7 text-slate-200 xl:text-lg xl:leading-8">Omega brings plugins from Dalamud and custom repositories together, so browsing feels easier and less messy.</p>
          </article>
          <article class="absolute right-10 top-1/2 max-w-md -translate-y-1/2 rounded-[1.8rem] border border-white/10 bg-omega-950/88 p-7 shadow-2xl backdrop-blur-md xl:right-16 xl:max-w-lg">
            <p class="text-xs font-black uppercase tracking-[.18em] text-omega-gold">Before you install</p>
            <h2 class="mt-4 text-4xl font-black tracking-tight text-white xl:text-6xl">Know what you’re adding to your game.</h2>
            <p class="mt-4 text-base leading-7 text-slate-200 xl:text-lg xl:leading-8">See where it came from, what it can do, and anything Omega thinks you should know. You choose; Dalamud handles the install.</p>
          </article>
        </div>

        <div class="relative flex min-h-[100svh] items-end lg:hidden">
          <div class="grid w-full gap-4 px-4 pb-8 sm:px-6">
            <article class="rounded-[1.8rem] border border-white/10 bg-omega-950/92 p-6 shadow-2xl backdrop-blur-md">
              <p class="text-xs font-black uppercase tracking-[.18em] text-omega-cyan">For Final Fantasy XIV players</p>
              <h1 class="mt-4 text-3xl font-black tracking-tight text-white">Find FFXIV plugins in one place.</h1>
              <p class="mt-4 text-base leading-7 text-slate-200">Omega brings plugins from Dalamud and custom repositories together, so browsing feels easier and less messy.</p>
            </article>
            <article class="rounded-[1.8rem] border border-white/10 bg-omega-950/92 p-6 shadow-2xl backdrop-blur-md">
              <p class="text-xs font-black uppercase tracking-[.18em] text-omega-gold">Before you install</p>
              <h2 class="mt-4 text-3xl font-black tracking-tight text-white">Know what you’re adding to your game.</h2>
              <p class="mt-4 text-base leading-7 text-slate-200">See where it came from, what it can do, and anything Omega thinks you should know. You choose; Dalamud handles the install.</p>
            </article>
          </div>
        </div>
      </div>
    `;
  }

  const installFlow = document.querySelector('#install-flow');
  if (installFlow) {
    installFlow.innerHTML = `
      <div class="mx-auto grid min-h-[100svh] max-w-7xl content-center px-4 py-12 sm:px-6 lg:px-8 lg:py-16">
        <div class="max-w-4xl">
          <p class="eyebrow text-xs font-black uppercase text-omega-cyan">What can you do in Omega?</p>
          <h2 class="hero-copy mt-4 text-3xl font-black tracking-tight text-white sm:text-5xl">Your plugin world, in one place.</h2>
          <p class="mt-5 max-w-3xl text-lg leading-8 text-slate-200">Open Omega when you want to see what’s new, find something specific, or sort out the plugins you already use.</p>
        </div>
        <div class="mt-8 grid gap-5 lg:grid-cols-3">
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-main.png" alt="Omega Spotlight showing new and interesting plugins" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-5">
              <p class="text-xs font-black uppercase tracking-[.16em] text-omega-cyan">Spotlight</p>
              <h3 class="mt-2 text-xl font-black text-white">See what’s happening in plugin land.</h3>
              <p class="mt-2 text-sm leading-6 text-slate-300">New releases, fresh updates, popular picks, and anything else worth a look.</p>
            </figcaption>
          </figure>
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-filters.png" alt="Omega Discover searching and filtering the plugin ecosystem" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-5">
              <p class="text-xs font-black uppercase tracking-[.16em] text-omega-gold">Discover</p>
              <h3 class="mt-2 text-xl font-black text-white">Find what you’re after.</h3>
              <p class="mt-2 text-sm leading-6 text-slate-300">Search the wider plugin world without hopping between separate lists. Filter it down until you find what you’re after.</p>
            </figcaption>
          </figure>
          <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
            <img src="assets/screenshots/omega-library.png" alt="Omega Library managing installed plugins" class="block w-full">
            <figcaption class="border-t border-white/10 px-5 py-5">
              <p class="text-xs font-black uppercase tracking-[.16em] text-omega-400">Library</p>
              <h3 class="mt-2 text-xl font-black text-white">Keep your plugins under control.</h3>
              <p class="mt-2 text-sm leading-6 text-slate-300">See what you already use, where it came from, which version you have, and keep the whole lot manageable.</p>
            </figcaption>
          </figure>
        </div>
      </div>
    `;
  }

  const why = document.querySelector('#why');
  if (why) {
    why.innerHTML = `
      <div class="mx-auto grid min-h-[100svh] max-w-7xl content-center px-4 py-12 sm:px-6 lg:px-8 lg:py-16">
        <div class="max-w-4xl">
          <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Why Omega shows warnings</p>
          <h2 class="hero-copy mt-4 text-3xl font-black tracking-tight text-white sm:text-5xl">Think of it like a label on the box.</h2>
          <p class="mt-5 text-lg leading-8 text-slate-200">Before you install a plugin, Omega tries to show the important things that are easy to miss. Does it use the internet? Can it change files? Can it automate parts of the game? Does it need another plugin to work?</p>
          <p class="mt-4 leading-7 text-slate-300">Those things can be completely normal. Omega is not saying a plugin is good or bad. It is simply putting the useful bits on the label so you know what you are choosing.</p>
        </div>
        <div class="mt-8 grid gap-5 lg:grid-cols-3">
          <article class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/omega-install-plugin.png" alt="A plugin page inside Omega" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-cyan">What can it do?</p>
              <h3 class="mt-2 text-xl font-black text-white">The important bits, in normal words.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">Omega turns what it finds into something you can understand before you install.</p>
            </div>
          </article>
          <article class="overflow-hidden rounded-[2rem] border border-omega-gold/25 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/omega-install-warning.png" alt="Omega stopping an installation to explain a warning" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-gold">Not comfortable with it?</p>
              <h3 class="mt-2 text-xl font-black text-white">Omega stops the install.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">If a plugin does something you have said you are not comfortable with, Omega stops the install and tells you why. You decide whether to continue.</p>
            </div>
          </article>
          <article class="overflow-hidden rounded-[2rem] border border-omega-400/25 bg-omega-950/85 shadow-2xl backdrop-blur-md">
            <img src="assets/screenshots/source-trust.png" alt="Omega showing where a plugin copy came from" class="block w-full">
            <div class="p-6">
              <p class="text-xs font-black uppercase tracking-wider text-omega-400">Where did it come from?</p>
              <h3 class="mt-2 text-xl font-black text-white">The same plugin can come from different places.</h3>
              <p class="mt-3 text-sm leading-6 text-slate-300">Omega shows where the plugin came from and which version you are looking at, so you do not have to guess.</p>
            </div>
          </article>
        </div>
        <p class="mt-7 max-w-4xl rounded-2xl border border-white/10 bg-white/[.035] p-5 text-sm leading-6 text-slate-300"><strong class="text-white">A warning is not a “bad plugin” stamp.</strong> It is Omega saying: “Here is something you may want to know before you continue.”</p>
      </div>
    `;
  }

  const install = document.querySelector('#install');
  if (install) {
    install.innerHTML = `
      <div class="mx-auto max-w-5xl rounded-[2rem] border border-omega-cyan/20 bg-omega-950/70 p-7 shadow-2xl backdrop-blur-sm sm:p-10" data-reveal>
        <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Install Omega</p>
        <h2 class="mt-4 text-3xl font-black text-white sm:text-5xl">Ready to try it?</h2>
        <p class="mt-5 max-w-3xl text-lg leading-8 text-slate-200">Omega is installed through Dalamud. Add its repository, then install Omega like any other Dalamud plugin.</p>

        <div class="mt-7 rounded-[2rem] border border-red-300/40 bg-red-500/10 p-6">
          <div class="flex items-center gap-4">
            <span aria-hidden="true" class="grid size-16 shrink-0 place-items-center rounded-2xl border border-red-300/70 bg-red-500/20 text-4xl font-black text-red-200 shadow-[0_0_36px_rgba(248,113,113,.35)]">⚠</span>
            <div>
              <p class="eyebrow text-xs font-black uppercase text-red-200">Read before installing</p>
              <p class="mt-2 font-bold text-white">Plugins are software running on your computer.</p>
            </div>
          </div>
          <p class="mt-5 max-w-3xl leading-7 text-slate-200">Omega helps you understand what you are installing, but the choice is still yours. Plugins can see game data, and some can play parts of the game for you. That can put your account at risk.</p>
          <p class="mt-4 max-w-3xl rounded-2xl border border-omega-gold/25 bg-omega-gold/[.06] p-4 leading-7 text-slate-100"><strong class="text-omega-gold">Omega is still in alpha.</strong> Things may still break, and some information may be missing or wrong.</p>
        </div>

        <button type="button" data-omega-install-start aria-expanded="false" class="mt-7 inline-flex min-h-12 items-center justify-center rounded-2xl bg-white px-6 py-3 font-black text-omega-950 hover:bg-omega-cyan">Install Omega</button>
        <p class="mt-3 text-sm leading-6 text-slate-400">This opens the install steps. Nothing is installed from this website.</p>

        <div data-omega-install-steps hidden class="mt-8 border-t border-white/10 pt-8">
          <div class="grid gap-10 lg:grid-cols-2 lg:items-center">
            <div>
              <p class="eyebrow text-xs font-black uppercase text-omega-cyan">Three quick steps</p>
              <ol class="mt-6 space-y-5">
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-400/10 text-sm font-black text-omega-400">1</span><div><strong class="text-white">Open Dalamud settings.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Find <strong class="text-slate-200">Custom Plugin Repositories</strong>.</p></div></li>
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-cyan/10 text-sm font-black text-omega-cyan">2</span><div><strong class="text-white">Add the Omega repository URL.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Copy the link below into the list and make sure it is enabled.</p></div></li>
                <li class="flex gap-4"><span class="grid size-9 shrink-0 place-items-center rounded-xl bg-omega-gold/10 text-sm font-black text-omega-gold">3</span><div><strong class="text-white">Open <code>/xlplugins</code> and search for Omega.</strong><p class="mt-1 text-sm leading-6 text-slate-400">Install it like a normal Dalamud plugin.</p></div></li>
              </ol>
              <div class="mt-7 overflow-x-auto rounded-2xl border border-white/10 bg-black/25 p-4 code-scroll"><code id="repo-url" class="whitespace-pre text-xs text-slate-300 sm:text-sm">https://github.com/dalagab/omega/releases/download/omega-latest/pluginmaster.json</code></div>
              <button data-copy="#repo-url" class="mt-3 inline-flex min-h-11 items-center rounded-xl border border-omega-cyan/25 px-4 text-sm font-black text-omega-cyan transition hover:border-omega-cyan/60 hover:text-white">Copy repository URL</button>
            </div>
            <figure class="overflow-hidden rounded-[2rem] border border-white/10 bg-omega-950 app-shadow">
              <div data-screenshot-slot="dalamud-custom-repo.png" data-alt="Dalamud Custom Plugin Repositories settings" class="min-h-[20rem]"></div>
              <figcaption class="border-t border-white/10 px-5 py-3 text-sm text-slate-300">Add the Omega link to Dalamud’s Custom Plugin Repositories list.</figcaption>
            </figure>
          </div>
        </div>
      </div>
    `;

    const button = install.querySelector('[data-omega-install-start]');
    const steps = install.querySelector('[data-omega-install-steps]');
    if (button && steps) {
      button.addEventListener('click', () => {
        steps.hidden = false;
        button.hidden = true;
        button.setAttribute('aria-expanded', 'true');
      });
    }
  }

  const team = document.querySelector('#team');
  if (team) {
    const heading = team.querySelector('h2');
    if (heading) heading.textContent = 'Built by a small team with different strengths.';
    const eyebrow = team.querySelector('.eyebrow');
    if (eyebrow) eyebrow.textContent = 'About us';

    let intro = team.querySelector('[data-omega-team-intro]');
    if (!intro && heading) {
      intro = document.createElement('p');
      intro.setAttribute('data-omega-team-intro', '');
      intro.className = 'mt-5 max-w-3xl text-lg leading-8 text-slate-300';
      heading.insertAdjacentElement('afterend', intro);
    }
    if (intro) intro.textContent = 'Omega is a small project. Some of us work on the plugin and website, some keep the behind-the-scenes stuff running, and some focus on security. We all want the same thing: make FFXIV plugins easier to find and easier to understand.';

    const cards = team.querySelectorAll('article');
    if (cards[0]) {
      const title = cards[0].querySelector('h3');
      const p = cards[0].querySelector('p:last-of-type');
      if (title) title.textContent = 'The data gremlin.';
      if (p) p.textContent = 'Omega’s mascot and resident data gremlin. TONI represents the part of Omega that digs through plugin info, spots odd details, and turns piles of data into something useful.';
    }
    if (cards[1]) {
      const title = cards[1].querySelector('h3');
      const p = cards[1].querySelector('p:last-of-type');
      if (title) title.textContent = 'Project lead.';
      if (p) p.textContent = 'Started Omega and helps keep the project moving. Works across the plugin, website, automation, and player experience alongside the rest of the team.';
    }
    if (cards[2]) {
      const label = cards[2].querySelector('p:first-of-type');
      const title = cards[2].querySelector('h3');
      const p = cards[2].querySelector('p:last-of-type');
      if (label) label.textContent = 'Security specialists';
      if (title) title.textContent = 'The people asking the awkward questions.';
      if (p) p.textContent = 'They bring real security experience and help make sure Omega’s warnings are useful, fair, and based on what is actually there.';
    }
  }

  const sigmascope = document.querySelector('#sigmascope');
  if (sigmascope) sigmascope.remove();

  let faq = document.querySelector('#omega-eli5-v9-faq');
  if (!faq) {
    faq = document.createElement('section');
    faq.id = 'omega-eli5-v9-faq';
    faq.setAttribute('data-story-panel', '');
    faq.className = 'story-panel border-y border-white/10 bg-white/[.025]';
    main.appendChild(faq);
  }
  faq.innerHTML = `
    <div class="mx-auto grid min-h-[100svh] max-w-4xl content-center px-4 py-12 sm:px-6 lg:px-8 lg:py-16">
      <p class="eyebrow text-xs font-black uppercase text-omega-gold">FAQ</p>
      <h2 class="mt-4 text-3xl font-black text-white sm:text-5xl">Still wondering about something?</h2>
      <div class="mt-8 space-y-3">
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega replace Dalamud?</summary><p class="mt-3 leading-7 text-slate-400">No. Omega helps you find and understand plugins. Dalamud still installs, updates, disables, and removes them.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega know if a plugin is safe?</summary><p class="mt-3 leading-7 text-slate-400">No. Omega can show warnings and useful information, but it cannot promise that a plugin is safe.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Omega install plugins by itself?</summary><p class="mt-3 leading-7 text-slate-400">No. You choose the plugin, and Dalamud does the install.</p></details>
        <details class="faq-item rounded-2xl border border-white/10 bg-omega-950/65 p-5"><summary class="font-black text-white">Does Sigmascope run plugins while checking them?</summary><p class="mt-3 leading-7 text-slate-400">No. It looks at the plugin files without running the plugin.</p></details>
      </div>
    </div>
  `;
  const testimonial = document.querySelector('#aetherfeed-note');
  if (testimonial) {
    testimonial.classList.remove('omega-eli5-v9-hidden');
    testimonial.setAttribute('data-story-panel', '');
  }

  if (why && install) why.insertAdjacentElement('afterend', install);
  if (install && team) install.insertAdjacentElement('afterend', team);
  if (team && testimonial) team.insertAdjacentElement('afterend', testimonial);
  if (testimonial && faq) testimonial.insertAdjacentElement('afterend', faq);

})();
