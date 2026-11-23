import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import * as site from './site.config.js'
import { resolveRelease } from './scripts/release.mjs'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))

/** /.well-known/apple-app-site-association and assetlinks.json, generated from site.config.js. */
function wellKnown() {
  return {
    name: 'skwod-well-known',
    generateBundle() {
      const json = (fileName, value) => this.emitFile({ type: 'asset', fileName, source: JSON.stringify(value, null, 2) + '\n' })
      const appIDs = site.APPLE_APP_IDS.map((id) => `${site.APPLE_TEAM_ID}.${id}`)
      json('.well-known/apple-app-site-association', {
        applinks: {
          // The invite itself is in the fragment, which never reaches the server or this file.
          details: [{ appIDs, components: [{ '/': '/join*', comment: 'invite links' }] }],
        },
      })
      json('.well-known/assetlinks.json', [{
        relation: ['delegate_permission/common.handle_all_urls'],
        target: { namespace: 'android_app', package_name: site.ANDROID_PACKAGE, sha256_cert_fingerprints: site.ANDROID_CERT_SHA256 },
      }])
    },
  }
}

export default defineConfig(async ({ command }) => {
  // The download buttons are worked out here, once, when the site is built (scripts/release.mjs).
  // `vite dev` does not ask GitHub: the buttons then point at the releases page.
  const release = command === 'build' ? await resolveRelease(site.RELEASES_REPO) : null
  if (command === 'build') {
    console.log(release ? `download buttons -> build ${release.build}` : 'download buttons -> releases page (no published release found)')
  }
  return {
    plugins: [react(), wellKnown()],
    base: './',
    define: { __SKWOD_RELEASE__: JSON.stringify(release) },
    build: {
      // The Content-Security-Policy in public/_headers allows fonts and scripts from this origin
      // only, so nothing may be inlined as a data: URL and nothing may fetch().
      assetsInlineLimit: 0,
      modulePreload: { polyfill: false },
      // Two pages: the landing page and /join (Cloudflare Pages serves join.html at /join).
      rollupOptions: { input: { index: here('./index.html'), join: here('./join.html') } },
    },
  }
})
