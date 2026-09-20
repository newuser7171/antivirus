# Veil — Android VPN + DNS ad blocker, powered by Jev

Personal preview for Android 11+. Native Java Android app. Import your own full-tunnel WireGuard profile, describe your filtering preference to Jev, review its recommendation, then connect.

## What Jev powers

An explicit **Ask Jev** request sends only the typed preference to TypeSafe's `jev-latest` model. Its typed Choice response selects ads/trackers, family filtering, profile DNS, or unsupported. The app validates the response, shows confidence, and requires confirmation before changing DNS. Unsupported answers and confidence below 0.75 cannot be applied. This threshold is a conservative product rule, not a calibrated safety guarantee. No VPN private keys, profiles, traffic, URLs, or DNS queries are automatically sent to Jev. Users must avoid entering private data in their preference text. Enter your own TypeSafe API key in the app; API charges may apply.

Jev does not encrypt traffic, inspect browsing, detect malware, supply VPN servers or perform on-device inference. WireGuard handles the VPN. AdGuard public DNS supplies domain filtering. Manual mode selection works without an AI key.

## Setup

1. Install the preview APK from the GitHub Actions build artifact.
2. Import a WireGuard `.conf` from your provider or server. No servers or subscriptions are bundled.
3. Choose a filtering mode manually, or enter your TypeSafe key and ask Jev.
4. Connect and grant Android VPN consent. Check for a confirmed handshake.
5. For protection after disconnection, use Android VPN settings to enable Always-on VPN and Block connections without VPN. Veil does not implement a separate kill switch.

Profiles must have one peer, an endpoint, an IPv4 interface address, and `0.0.0.0/0`. If any IPv6 address, route or DNS is configured, `::/0` is required. Otherwise the backend blocks IPv6 while active. Per-app and split routing are rejected. Profile DNS mode requires a DNS server in the profile. The original profile is retained so switching modes can restore its DNS. Settings changes require disconnection.

## Filtering and privacy

- Ads/trackers: `94.140.14.14`, `94.140.15.15`.
- Family: `94.140.14.15`, `94.140.15.16`.
- Profile DNS: original resolver, no added filtering.

Filtering DNS traffic travels through the configured tunnel. VPN provider and DNS provider privacy policies apply. App-specific DoH and Android Private DNS can bypass this filtering. DNS blocking cannot remove all ads, including same-domain/YouTube ads, and is not antivirus protection. No invented blocked-ad counter is shown. A recent handshake confirms the VPN peer responded; it does not certify Internet access or anonymity.

Profiles and API keys are AES-GCM encrypted using Android Keystore, excluded from backups, and never logged by app code. Veil records no browsing history or analytics. Screenshots are disabled for the app to protect pasted profiles and keys. Removing a profile/key clears the encrypted stored value.

## Build

Use JDK 17, Android SDK 35 and Gradle 8.11.1. Open this folder in Android Studio or run:

```sh
gradle testDebugUnitTest assembleDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`. CI workflow is provided in `ci/veil-android.yml` and installed at the repository root `.github/workflows/veil-android.yml`. Preview builds use a generated Android debug signing key; subsequent CI runs may require uninstalling the previous preview, which clears its data. Keep an independent copy of your provider's configuration. For a maintained release, configure your own private release signing key; never commit it.

## Verification scope

Unit tests cover routing restrictions, DNS replacement, key preservation and Jev response validation. Live Jev calls require a user key; none is bundled. A successful compile is not a device or real VPN test. See GitHub Actions for actual build/test results. Before relying on the preview, test consent, handshake, DNS, IPv6, reconnect/revoke, process restart, and always-on lockdown on your device with your provider.

## Upstream documentation and licenses

- [TypeSafe API](https://docs.typesafe.ai/introduction/quickstart)
- [Android VPN guide](https://developer.android.com/develop/connectivity/vpn)
- [AdGuard DNS addresses](https://adguard-dns.io/en/public-dns.html)
- [WireGuard Android](https://git.zx2c4.com/wireguard-android/) — Apache-2.0
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) — MIT; bundled Go runtime is BSD-3-Clause

The app is an independent project, not an official WireGuard, AdGuard or TypeSafe product.
