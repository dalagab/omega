# Omega site

The publishable static site lives in `site/`. GitHub Pages deploys that directory through `.github/workflows/deploy-pages.yml`.

## Preview locally

1. Run `npm install` once from this folder.
2. Double-click `preview.cmd`, or run `npm run preview` in a terminal.
3. Open [http://localhost:4173](http://localhost:4173) and keep the terminal window open while previewing.

Run `npm run build` after editing `site/assets/tailwind.css`. The committed `site/assets/site.css` is what GitHub Pages serves.
