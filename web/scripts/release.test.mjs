import test from 'node:test'
import assert from 'node:assert/strict'
import { linksFromManifest, resolveRelease } from './release.mjs'

const repo = 'FlayrLabs/skwod-releases'
const base = `https://github.com/${repo}/releases/download/v41`
const manifest = (over = {}) => ({
  android: { build: 41, version: '0.1.0', file: 'skwod-41.apk', url: `${base}/skwod-41.apk`, sha256: 'x', sig: 'y', ...over },
})

test('a release manifest gives direct, versioned links', () => {
  assert.deepEqual(linksFromManifest(manifest(), repo), {
    build: 41, apk: `${base}/skwod-41.apk`, dmg: `${base}/Skwod-41.dmg`, testflight: null,
  })
  const tf = 'https://testflight.apple.com/join/AbCd1234'
  assert.equal(linksFromManifest({ ...manifest(), ios: { testflight: tf } }, repo).testflight, tf)
  assert.equal(linksFromManifest({ ...manifest(), ios: { testflight: 'https://evil.example/join/x' } }, repo).testflight, null)
})

test('anything unexpected falls back (null)', () => {
  for (const bad of [null, {}, [], 'x', { android: {} }, manifest({ build: '41' }), manifest({ build: 0 }),
    manifest({ url: 'https://evil.example/skwod-41.apk' }), manifest({ url: `${base}/other.apk` }),
    manifest({ url: `https://github.com/someone/else/releases/download/v41/skwod-41.apk` })]) {
    assert.equal(linksFromManifest(bad, repo), null)
  }
})

test('resolveRelease keeps only files that exist and never throws', async () => {
  const ok = (body) => ({ ok: true, json: async () => body })
  const all = await resolveRelease(repo, { fetchImpl: async (url, o) => (o.method === 'GET' ? ok(manifest()) : { ok: true }) })
  assert.deepEqual(all, { build: 41, apk: `${base}/skwod-41.apk`, dmg: `${base}/Skwod-41.dmg`, testflight: null })
  const noDmg = await resolveRelease(repo, { fetchImpl: async (url, o) => (o.method === 'GET' ? ok(manifest()) : { ok: !url.endsWith('.dmg') }) })
  assert.equal(noDmg.dmg, null)
  assert.equal(noDmg.apk, `${base}/skwod-41.apk`)
  assert.equal(await resolveRelease(repo, { fetchImpl: async () => ({ ok: false }) }), null)
  assert.equal(await resolveRelease(repo, { fetchImpl: async () => { throw new Error('offline') } }), null)
})
