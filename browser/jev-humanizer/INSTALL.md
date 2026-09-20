# Jev Humanizer — desktop + Android preview

Version 0.1.0. A browser extension for making English prose clearer while preserving your meaning. This is a development preview, not a published or Mozilla-signed extension.

## What works without a key

Paste text, choose a tone, and select **Make local edits**. Compare the original with the available drafts, inspect the phrase changes, and copy the version you prefer. These are bundled phrase rules, not a general-purpose generative writing model. If no rules match, the original stays unchanged. Maximum input: 6,000 characters.

**Ask Jev to choose** requires your own TypeSafe API key. Jev evaluates the available drafts; it does not generate prose. Give consent for each request. Your original, drafts, and tone are sent to TypeSafe, and your account's usage charges may apply. You can preview its choice before copying it. Scores are model estimates, not measured accuracy or detector scores. Read every rewrite before using it.

The optional **Try browser AI** feature uses Chrome's built-in Rewriter API only when exposed and supported. It may need a large model download and suitable desktop hardware. This feature is unavailable on Android and Firefox; local phrase edits and optional Jev checks remain available there.

## Laptop: Chrome or a compatible Chromium browser

1. Extract the downloaded bundle.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Choose **Load unpacked**, then select the bundle's `chrome` folder, containing `manifest.json`.
4. Pin Jev Humanizer and open its toolbar button. Paste text or select text on a normal webpage and click **Use selected text**.

Other Chromium browsers may load the extension but may not expose Chrome's local Rewriter API. Use **Open editor** before pasting a long draft to keep it in a tab. Opening a new editor does not transfer an existing draft.

## Laptop: Firefox 140 or newer

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on** and select `firefox/manifest.json`.
3. Open the extension from the toolbar. Temporary installation lasts until Firefox restarts.

## Android: Firefox 140 or newer

Standard Chrome on Android cannot load this extension. Firefox Android needs a Mozilla-signed package for normal installation. The included `Jev-Humanizer-firefox.zip` is an unsigned submission package; renaming it to `.xpi` does not sign it.

For a normal phone installation, the developer must submit that ZIP through Mozilla's Add-on Developer Hub, enable Android compatibility, and obtain a signed add-on. This bundle has not been submitted, reviewed, or signed. No Mozilla credentials are included.

For temporary development testing with a laptop:

1. Install Node.js, Mozilla's `web-ext` (7.12 or newer), and Android SDK platform tools (`adb`) on the laptop.
2. Install Firefox on the phone. Enable Android Developer options and USB debugging. In Firefox's developer settings enable **Remote debugging via USB** (the hidden Firefox menu can be enabled by tapping its logo repeatedly under About Firefox).
3. Connect the phone by USB and accept its debugging prompt. Run `adb devices` and note the device ID.
4. From the extracted bundle's `firefox` folder, run:

   ```sh
   npx web-ext run -t firefox-android --adb-device YOUR_DEVICE_ID --firefox-apk org.mozilla.firefox
   ```

5. Open Jev Humanizer from Firefox's extensions menu. Keep the development session running; this is a temporary install.

Official instructions: https://extensionworkshop.com/documentation/develop/developing-extensions-for-firefox-for-android/

Signing: https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/

## Privacy and behavior

- Text, results, and API keys stay in the current editor's memory. Closing it discards them. Copy anything you want to keep first.
- Local phrase edits do not make network requests. Optional browser AI may download a model through the browser.
- Only an explicit, consented Jev check sends the supplied text to TypeSafe. Provider processing and retention are governed by your TypeSafe agreement; this extension cannot guarantee provider deletion.
- The extension reads selected text only after your click, using temporary active-tab access. It does not automatically read webpages, replace form content, or submit anything.
- Permissions allow selection import, clipboard copying, and requests to `api.typesafe.ai`. No analytics or remote executable code is included.
- Jev selection and meaning thresholds (0.55 and 0.90) are conservative interface rules, not validated guarantees. Uncertain responses do not produce a recommendation.

## Source and verification

The `source` folder contains the editable project. From that folder run `npm test` and `python3 build.py`. No npm dependencies are required for these commands. Build outputs appear under `dist`.

Automated tests cover editing rules, protected text, limits, candidate validation, Jev response validation, and mocked network failures. Packaging and JavaScript syntax were checked. This preview has not been tested on a physical Android phone or in a running browser extension session. No live TypeSafe request or local Chrome model inference was run during development.

TypeSafe API: https://docs.typesafe.ai/api

Chrome Rewriter API: https://developer.chrome.com/docs/ai/rewriter-api
