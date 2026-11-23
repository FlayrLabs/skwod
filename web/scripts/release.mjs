// Works out where the download buttons point, at BUILD time.
//
// Release files are named after the build (Skwod-41.dmg, skwod-41.apk), so GitHub's
// `releases/latest/download/<file>` shortcut cannot name them. Each release does publish a
// fixed-name `manifest.json`, which says which build is current. So:
//
//   1. the build reads  …/releases/latest/download/manifest.json  once;
//   2. if it describes a build whose files really exist, the buttons link straight to them
//      (…/releases/download/v41/Skwod-41.dmg);
//   3. in every other case (no release yet, GitHub unreachable, a manifest that looks wrong) the
//      buttons link to the releases page, …/releases/latest, which is always right.
//
// The visitor's browser never asks GitHub anything until they click a download: no client-side
// fetch (GitHub's asset redirects have no CORS headers anyway, and it would be a third-party
// request). The price is that direct links go stale when a new build ships: redeploy the site
// after each release (DEPLOY.md). A stale link still downloads a real, signed, older build, and
// the Mac and Android apps update themselves from there.

/** Pure: the direct links a manifest implies, or null if it is not exactly what a release writes. */
export function linksFromManifest(manifest, repo) {
  const a = manifest && typeof manifest === 'object' ? manifest.android : null
  if (!a || !Number.isInteger(a.build) || a.build < 1 || a.build > 1_000_000) return null
  const base = `https://github.com/${repo}/releases/download/v${a.build}`
  const apk = `${base}/skwod-${a.build}.apk`
  // The manifest's own url must be the one we would have built: never follow it anywhere else.
  if (a.url !== apk) return null
  const out = { build: a.build, apk, dmg: `${base}/Skwod-${a.build}.dmg`, testflight: null }
  const tf = manifest.ios && manifest.ios.testflight
  if (typeof tf === 'string' && /^https:\/\/testflight\.apple\.com\/join\/[A-Za-z0-9]{4,32}$/.test(tf)) out.testflight = tf
  return out
}

/** Reads the latest manifest and checks each file exists. Never throws; null means "use the releases page". */
export async function resolveRelease(repo, { fetchImpl = fetch, timeoutMs = 8000 } = {}) {
  if (process.env.SKWOD_SITE_OFFLINE === '1') return null
  const get = (url, method) => fetchImpl(url, { method, redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) })
  try {
    const res = await get(`https://github.com/${repo}/releases/latest/download/manifest.json`, 'GET')
    if (!res.ok) return null
    const links = linksFromManifest(await res.json(), repo)
    if (!links) return null
    const exists = async (url) => (await get(url, 'HEAD')).ok
    return {
      build: links.build,
      apk: (await exists(links.apk)) ? links.apk : null,
      dmg: (await exists(links.dmg)) ? links.dmg : null,
      testflight: links.testflight,
    }
  } catch {
    return null
  }
}
