(() => {
  'use strict';

  const main = document.querySelector('#content');
  if (!main) return;

  const installButton = document.querySelector('[data-omega-install-start]');
  const installSteps = document.querySelector('[data-omega-install-steps]');
  if (installButton && installSteps) {
    installButton.addEventListener('click', () => {
      installSteps.hidden = false;
      installButton.hidden = true;
      installButton.setAttribute('aria-expanded', 'true');
    });
  }

  const isReviewScreenshot = (img) => {
    if (!(img instanceof HTMLImageElement)) return false;
    const src = img.getAttribute('src') || '';
    return src.startsWith('assets/screenshots/') || src.includes('/assets/screenshots/');
  };

  const prepareReviewScreenshot = (img) => {
    if (!isReviewScreenshot(img) || img.dataset.omegaReviewScreenshot === 'true') return;
    img.dataset.omegaReviewScreenshot = 'true';
    img.classList.add('omega-review-screenshot');
    img.tabIndex = 0;
    img.setAttribute('role', 'button');
    img.setAttribute('aria-label', `${img.alt || 'Screenshot'} — open full size`);
    img.setAttribute('title', 'Click to open full size');
  };

  for (const img of main.querySelectorAll('img')) prepareReviewScreenshot(img);

  const screenshotObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof Element)) continue;
        if (node instanceof HTMLImageElement) prepareReviewScreenshot(node);
        for (const img of node.querySelectorAll?.('img') || []) prepareReviewScreenshot(img);
      }
    }
  });
  screenshotObserver.observe(main, { childList: true, subtree: true });

  const lightbox = document.createElement('div');
  lightbox.className = 'omega-screenshot-lightbox';
  lightbox.hidden = true;
  lightbox.setAttribute('role', 'dialog');
  lightbox.setAttribute('aria-modal', 'true');
  lightbox.setAttribute('aria-label', 'Screenshot preview');
  lightbox.innerHTML = `
    <button type="button" class="omega-screenshot-lightbox__close" aria-label="Close screenshot">×</button>
    <figure class="omega-screenshot-lightbox__figure">
      <img class="omega-screenshot-lightbox__image" alt="">
      <figcaption class="omega-screenshot-lightbox__caption"></figcaption>
    </figure>
  `;
  document.body.appendChild(lightbox);

  const lightboxImage = lightbox.querySelector('.omega-screenshot-lightbox__image');
  const lightboxCaption = lightbox.querySelector('.omega-screenshot-lightbox__caption');
  const lightboxClose = lightbox.querySelector('.omega-screenshot-lightbox__close');
  let screenshotReturnFocus = null;

  const closeScreenshot = () => {
    if (lightbox.hidden) return;
    lightbox.hidden = true;
    document.body.classList.remove('omega-screenshot-open');
    lightboxImage.removeAttribute('src');
    screenshotReturnFocus?.focus();
    screenshotReturnFocus = null;
  };

  const openScreenshot = (img) => {
    if (!isReviewScreenshot(img)) return;
    screenshotReturnFocus = img;
    lightboxImage.src = img.currentSrc || img.src;
    lightboxImage.alt = img.alt || 'Omega screenshot';
    lightboxCaption.textContent = img.alt || '';
    lightbox.hidden = false;
    document.body.classList.add('omega-screenshot-open');
    lightboxClose.focus();
  };

  main.addEventListener('click', (event) => {
    const img = event.target.closest?.('img');
    if (isReviewScreenshot(img)) openScreenshot(img);
  });

  main.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const img = event.target.closest?.('img');
    if (!isReviewScreenshot(img)) return;
    event.preventDefault();
    openScreenshot(img);
  });

  lightboxClose.addEventListener('click', closeScreenshot);
  lightbox.addEventListener('click', (event) => {
    if (event.target === lightbox) closeScreenshot();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !lightbox.hidden) closeScreenshot();
  });
})();
