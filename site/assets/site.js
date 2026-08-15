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
