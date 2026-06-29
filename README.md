# Jorge & Rebeca · Bergen & Fjord Road Trip

A private, password-protected website for a 10-day Norway itinerary
(29 June – 8 July 2026): Bergen, the western fjords, and the road between them.

## Privacy

The itinerary contains personal details (names, flight, booking reference,
hotel addresses and phone numbers), so the site is **encrypted at rest**:

- `index.html` is a small unlock screen plus the itinerary encrypted with
  **AES-256-GCM**, using a key derived from the password via **PBKDF2**
  (SHA-256, 250k iterations). Decryption happens entirely in the browser.
- Without the password, the page source — and therefore this repository —
  reveals nothing readable. The plaintext is **never committed** (it lives in
  a `.gitignore`d `itinerary.plain.html`).
- The password is not stored anywhere in the repo. Share it out of band.

This is meaningful protection for a static site, with the usual caveats:
anyone you give the password to sees everything, and a weak password could be
brute-forced (hence the slow key derivation — use a strong passphrase).

## Editing the itinerary

The password is supplied via the `SITE_PASSWORD` environment variable and is
never written to disk by the tooling.

```sh
# 1. Recover the editable plaintext from the encrypted page:
SITE_PASSWORD='your-passphrase' node build.mjs decrypt index.html itinerary.plain.html

# 2. Edit itinerary.plain.html (the full single-page app — inline CSS/JS,
#    no build step, no dependencies). Preview it locally:
python3 -m http.server 8000   # then open http://localhost:8000/itinerary.plain.html

# 3. Re-encrypt back into the published page:
SITE_PASSWORD='your-passphrase' node build.mjs encrypt itinerary.plain.html index.html
```

Then commit `index.html` (the encrypted page) only.

## What the site includes

Day-by-day itinerary, a sticky day strip, per-day "Guide suggests" stops and
"Claude recommends" extras (with Google Maps routes), bookings, a checklist
saved to the device, and an essentials section. Light/dark themes, mobile
first, hash-routed.

## Deployment

Pushes to this branch are published to GitHub Pages by
`.github/workflows/deploy.yml`. Because the site is hash-routed and fully
self-contained, no server-side routing or `404.html` fallback is needed.
