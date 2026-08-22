(() => {
  const target = document.querySelector('[data-manifesto]');
  if (!target) return;

  const escapeHtml = (value) => value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');

  const inline = (value) => escapeHtml(value)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

  const render = (markdown) => {
    const parts = [];
    let paragraph = [];
    const flushParagraph = () => {
      if (!paragraph.length) return;
      parts.push(`<p>${inline(paragraph.join(' '))}</p>`);
      paragraph = [];
    };

    for (const line of markdown.replace(/\r/g, '').split('\n')) {
      if (!line.trim()) {
        continue;
      } else if (line.startsWith('# ')) {
        flushParagraph();
        parts.push(`<h1>${inline(line.slice(2))}</h1>`);
      } else if (line.startsWith('## ')) {
        flushParagraph();
        parts.push(`<h2>${inline(line.slice(3))}</h2>`);
      } else if (line.startsWith('> ')) {
        flushParagraph();
        parts.push(`<blockquote><p>${inline(line.slice(2))}</p></blockquote>`);
      } else {
        paragraph.push(line.trim());
      }
    }
    flushParagraph();
    return parts.join('');
  };

  fetch('content/developers-manifesto.md')
    .then((response) => {
      if (!response.ok) throw new Error('Manifesto source is unavailable.');
      return response.text();
    })
    .then((markdown) => { target.innerHTML = render(markdown); })
    .catch((error) => { target.textContent = error.message; });
})();
