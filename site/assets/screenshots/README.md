# Optional Omega screenshots

The site is complete without these files; it shows deliberate styled placeholders until real captures are added.

For the polished public site, capture these PNGs from the current Omega build:

1. `product-provenance.png`
   - Selected plugin product page.
   - Show the project/source/provenance area.
   - Crop tightly enough that the image demonstrates the UI rather than publishing a readable catalog list.

2. `security-findings.png`
   - Security section of a selected plugin.
   - Include the capability summary and the expandable “why these findings were reported” evidence area.
   - Do not imply the plugin shown is malicious; choose a normal example with understandable signals.

3. `dalamud-custom-repo.png`
   - `/xlsettings` → Experimental → Custom Plugin Repositories.
   - Show the Omega repository URL entered and enabled.
   - Blur/crop unrelated personal or repository entries if present.

4. `omega-home.png` (optional)
   - Omega Spotlight or Discover landing view.
   - Use primarily for atmosphere/product recognition, not as a web-browsable catalog substitute.

Recommended capture size: 1600×900 or larger, PNG, no chat logs or character/account-identifying overlays.

After adding one of the named PNGs, rerun `python tools/site/build_site.py`; the build automatically replaces the matching placeholder with the screenshot.
