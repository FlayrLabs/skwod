import test from 'node:test'
import assert from 'node:assert/strict'
import { parseFragment, detectPlatform } from './invite.js'

const node = 'ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1u'

test('demo invites from the homepage preview are recognised, never opened', () => {
  for (const d of ['#demo-SKWD-AB12-CD34', 'demo', '#DEMO-x']) {
    assert.deepEqual(parseFragment(d), { ok: false, reason: 'demo' }, d)
  }
})

test('a share fragment becomes the app link', () => {
  const inv = parseFragment(`#${node}.SKWD-AB12-CD34`)
  assert.equal(inv.ok, true)
  assert.equal(inv.appLink, `skwod://join/${node}#SKWD-AB12-CD34`)
  assert.equal(inv.code, 'SKWD-AB12-CD34')
  assert.equal(inv.shortKey, 'ybndrf…qxot1u')
  assert.equal(parseFragment(node).appLink, `skwod://join/${node}`)
  assert.equal(parseFragment(`#${node}.`).appLink, `skwod://join/${node}`)
  assert.equal(parseFragment(`#${node.toUpperCase()}.abc`).appLink, `skwod://join/${node}#abc`)
})

test('optional parameters are kept only when clean', () => {
  assert.equal(parseFragment(`#${node}.abc&u=https://chat.example.org&l=0a1b`).appLink,
    `skwod://join/${node}?u=https://chat.example.org&l=0a1b#abc`)
  for (const junk of ['&u=http://evil.example', '&u=javascript:alert(1)', '&u=https://a.example/?x=1', '&u=https://a.example/#x',
    '&u=https://user@a.example', '&l=zz', '&x=1', '&u=https://a.example/"><script>']) {
    assert.equal(parseFragment(`#${node}.abc${junk}`).appLink, `skwod://join/${node}#abc`, junk)
  }
})

test('missing and malformed fragments are told apart and never produce a link', () => {
  for (const empty of ['', '#', undefined, null]) assert.deepEqual(parseFragment(empty), { ok: false, reason: 'missing' })
  for (const bad of ['#notakey.abc', `#${node}x.abc`, `#${node.slice(1)}.abc`, `#${node}.bad code`, `#${node}.a.b`,
    `#${node}.<script>`, `#${node}/../x`, `#${node}.${'a'.repeat(129)}`, `#${node}.abc&${'u=x&'.repeat(400)}`,
    '#javascript:alert(1)', `#skwod://join/${node}`, `#${node}%2Eabc`]) {
    assert.deepEqual(parseFragment(bad), { ok: false, reason: 'malformed' }, bad)
  }
})

test('platform detection', () => {
  assert.equal(detectPlatform({ userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X)', maxTouchPoints: 5 }), 'ios')
  assert.equal(detectPlatform({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', maxTouchPoints: 0 }), 'mac')
  assert.equal(detectPlatform({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', maxTouchPoints: 5 }), 'ios')
  assert.equal(detectPlatform({ userAgent: 'Mozilla/5.0 (Linux; Android 15; Pixel 9)', maxTouchPoints: 5 }), 'android')
  assert.equal(detectPlatform({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', maxTouchPoints: 0 }), 'other')
  assert.equal(detectPlatform(undefined), 'other')
})
