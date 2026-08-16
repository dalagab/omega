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
})();
