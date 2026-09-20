# Jev Humanizer

Browser extension preview for desktop Chromium and Firefox, including Firefox Android.

[Download the desktop + Android bundle](downloads/Jev-Humanizer-Extension.zip?raw=true) · [Installation guide](INSTALL.md)

Local English phrase editing works without an API key. Optional Jev evaluation uses your TypeSafe key to compare drafts and check meaning. Supported desktop Chrome installations may additionally expose a local AI rewriting model. Jev itself does not generate the rewritten prose.

Firefox Android requires Mozilla signing for a normal installation; this preview is unsigned. Temporary development installation instructions are included. The extension never automatically posts or replaces webpage text.

## Development

```sh
npm test
python3 build.py
```

Requires Node.js 20+ and Python 3; no npm dependencies. Build outputs appear in `dist/chrome`, `dist/firefox`, and browser-specific ZIP files. Select `dist/chrome` for Chromium's Load unpacked command.

23 automated tests passed. Live browser installation, physical Android testing, real Jev responses, and local Chrome model inference have not been verified. See [INSTALL.md](INSTALL.md) for limitations and privacy details.
