# Omega public site build

`build_site.py` copies the static `site/` source into `_site`, injects Omega's current version and brand assets, optionally replaces screenshot slots, and checks that no catalog/database payload has entered the public artifact.

Tailwind CSS is then compiled separately with the v4 CLI:

```bash
npx @tailwindcss/cli -i ./site/assets/tailwind.css -o ./_site/assets/site.css --minify
```

Run the complete local pipeline with:

```bash
npm run build:pages
```

`validate_site.py` runs after Tailwind compilation and checks required assets, local references, and the no-catalog public boundary.
