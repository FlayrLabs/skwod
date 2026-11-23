// Where the download buttons point. `__SKWOD_RELEASE__` is filled in by vite.config.js when the
// site is BUILT (scripts/release.mjs reads the latest release's manifest.json): either
// { build, dmg, apk, testflight } or null. A missing file falls back to the releases page, which
// is always right. Nothing is looked up in the visitor's browser.
import { RELEASES_URL, SOURCE_URL, CONTACT_EMAIL, TESTFLIGHT_URL as CONFIGURED_TESTFLIGHT_URL } from '../site.config.js'

const release = __SKWOD_RELEASE__

export const MAC_URL = release?.dmg || RELEASES_URL
export const APK_URL = release?.apk || RELEASES_URL
/** '' while there is no public TestFlight link: the iPhone card then says the beta is invite-only. */
export const TESTFLIGHT_URL = CONFIGURED_TESTFLIGHT_URL || release?.testflight || ''
export { RELEASES_URL, SOURCE_URL, CONTACT_EMAIL }
