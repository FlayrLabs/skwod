// Everything the owner may need to change lives here. Nothing in this file is secret.

// The iPhone beta is INVITE-ONLY: friends are added as internal TestFlight testers, so there is
// no public link and this stays empty. While it is empty the iPhone card reads "iPhone beta ·
// invite only · hello@skwod.io / Ask who invited you" and opens an e-mail to CONTACT_EMAIL. Setting a public link here,
// e.g. 'https://testflight.apple.com/join/AbCdEfGh', turns the card into that link. So would a
// release published with SKWOD_TESTFLIGHT_URL set (its manifest.json then carries `ios.testflight`):
// leave that variable unset while the beta is invite-only.
export const TESTFLIGHT_URL = ''

// Where people ask for an iPhone invite (shown on the iPhone card).
export const CONTACT_EMAIL = 'hello@skwod.io'

// Binaries and update feeds (public). The newest release is always at RELEASES_URL.
export const RELEASES_REPO = 'FlayrLabs/skwod-releases'
export const RELEASES_URL = `https://github.com/${RELEASES_REPO}/releases/latest`

// Source code (public at launch; until then this link 404s for visitors).
export const SOURCE_URL = 'https://github.com/FlayrLabs/skwod'

// Where the site is served from (used for absolute URLs in <meta> tags only).
export const SITE_ORIGIN = 'https://skwod.io'

// App links / universal links (public/.well-known is generated from these at build time).
export const APPLE_TEAM_ID = 'NRNU83UJ68'
export const APPLE_APP_IDS = ['com.skwod.app'] // iOS. The Mac app (io.skwod.mac) opens invites through skwod://
export const ANDROID_PACKAGE = 'com.skwod.app'
// SHA-256 of the Android RELEASE signing certificate (public). Recompute with:
//   keytool -list -v -keystore apps/android/skwod-release.keystore -alias <alias> | grep SHA256
export const ANDROID_CERT_SHA256 = [
  '5A:A6:3F:F4:AF:89:29:87:E3:1A:E7:80:C0:76:F7:83:BD:E8:98:68:4A:6E:A2:CC:86:95:8B:85:EF:34:05:1F',
]
