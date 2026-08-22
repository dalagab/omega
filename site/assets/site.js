(() => {
  const menuButton = document.querySelector('[data-menu-button]');
  const mobileMenu = document.querySelector('[data-mobile-menu]');
  if (menuButton && mobileMenu) {
    menuButton.addEventListener('click', () => {
      const open = menuButton.getAttribute('aria-expanded') === 'true';
      menuButton.setAttribute('aria-expanded', String(!open));
      mobileMenu.hidden = open;
      menuButton.querySelector('[data-menu-label]').textContent = open ? 'Menu' : 'Close';
    });
  }

  for (const slot of document.querySelectorAll('[data-screenshot-slot]')) {
    const filename = slot.getAttribute('data-screenshot-slot');
    const alt = slot.getAttribute('data-alt') || '';
    const image = new Image();
    image.src = `assets/screenshots/${filename}`;
    image.alt = alt;
    image.className = filename === 'dalamud-custom-repo.png'
      ? 'block h-full w-full object-contain p-8'
      : 'block h-full w-full object-cover object-top';
    image.addEventListener('load', () => slot.replaceChildren(image));
  }

  for (const button of document.querySelectorAll('[data-copy]')) {
    button.addEventListener('click', async () => {
      const selector = button.getAttribute('data-copy');
      const source = document.querySelector(selector);
      if (!source) return;
      const text = source.innerText.trim();
      try {
        await navigator.clipboard.writeText(text);
        const old = button.textContent;
        button.textContent = 'Copied';
        setTimeout(() => { button.textContent = old; }, 1400);
      } catch {
        button.textContent = 'Select & copy';
      }
    });
  }

  const installAcknowledgement = document.querySelector('[data-install-acknowledgement]');
  const installRepository = document.querySelector('[data-install-repository]');
  if (installAcknowledgement && installRepository) {
    installAcknowledgement.addEventListener('change', () => {
      installRepository.hidden = !installAcknowledgement.checked;
    });
  }

  for (const card of document.querySelectorAll('article')) {
    const label = card.querySelector('p');
    if (!label || label.textContent.trim().toLowerCase() !== 'iferniton') continue;
    if (card.querySelector('.manifesto-link')) continue;
    const description = card.querySelector('p:last-of-type');
    if (!description) continue;
    const link = document.createElement('a');
    link.className = 'manifesto-link';
    link.href = 'developers-manifesto.html';
    link.textContent = 'Read the developers’ manifesto →';
    description.insertAdjacentElement('afterend', link);
  }

  const progress = document.querySelector('[data-reading-progress]');
  const updateProgress = () => {
    if (!progress) return;
    const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
    progress.style.setProperty('--reading-progress', `${maxScroll > 0 ? (window.scrollY / maxScroll) * 100 : 0}%`);
  };
  window.addEventListener('scroll', updateProgress, { passive: true });
  updateProgress();

  const revealItems = document.querySelectorAll('[data-reveal]');
  if ('IntersectionObserver' in window) {
    const revealObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          revealObserver.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15 });
    revealItems.forEach((item) => revealObserver.observe(item));
  } else {
    revealItems.forEach((item) => item.classList.add('is-visible'));
  }

  const teamSection = document.querySelector('#team');
  const sigmascopeSection = document.querySelector('#sigmascope');
  if (teamSection && sigmascopeSection) {
    sigmascopeSection.insertAdjacentElement('afterend', teamSection);
  }

  const storyPanels = Array.from(document.querySelectorAll('[data-story-panel], #aetherfeed-note'))
    .filter((panel) => panel.getClientRects().length > 0);
  let storyScrollLocked = false;
  window.addEventListener('wheel', (event) => {
    if (storyScrollLocked || Math.abs(event.deltaY) < 8 || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const currentIndex = storyPanels.findIndex((panel) => {
      const bounds = panel.getBoundingClientRect();
      return bounds.top < 160 && bounds.bottom > window.innerHeight * 0.55;
    });
    if (currentIndex < 0) return;
    const currentBounds = storyPanels[currentIndex].getBoundingClientRect();
    const atDownwardBoundary = currentBounds.bottom <= window.innerHeight + 120;
    const atUpwardBoundary = currentBounds.top >= -120;
    if ((event.deltaY > 0 && !atDownwardBoundary) || (event.deltaY < 0 && !atUpwardBoundary)) return;
    const nextIndex = currentIndex + (event.deltaY > 0 ? 1 : -1);
    const target = storyPanels[nextIndex];
    if (!target) return;
    event.preventDefault();
    storyScrollLocked = true;
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    window.setTimeout(() => { storyScrollLocked = false; }, 650);
  }, { passive: false });
})();
