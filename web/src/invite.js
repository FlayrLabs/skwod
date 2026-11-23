// The share-link grammar, shared by the join page and its tests. Mirror of
// core/skwod-net/src/invite.rs (the Rust reference, in the native tree) — keep the two in step.
//
//   https://skwod.io/join#<node id>[.<join code>][&u=<https url>][&l=<hex>][&r=<relay url>]
//
//   <node id>    the host's public key: exactly 52 z-base-32 characters. It is the address.
//   <join code>  1 to 128 of A-Z a-z 0-9 - _
//   u            optional https address of the same skwod (hosts that also have a domain)
//   l            optional LAN-discovery key (hex)
//   r            optional home relay of the host: https://<region>.relay.n0.iroh.link/ only
//                (allow-listed; anything else is dropped). Lets the app dial without a lookup.
//
// All of it is the URL fragment. Browsers do not send fragments to servers, so skwod.io never
// receives the key or the code. The app form of the same invite is
//
//   skwod://join/<node id>[?u=…&l=…&r=…]#<join code>

const NODE_ID = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/
const CODE = /^[A-Za-z0-9_-]{1,128}$/
const FALLBACK = /^https:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(\/[A-Za-z0-9._~\/-]*)?$/
const LAN_KEY = /^[0-9a-f]{2,128}$/
// Same rule as is_allowed_relay in invite.rs: https, an n0 relay host, no port/path/query.
const RELAY = /^https:\/\/((?!-)[a-z0-9-]{1,63}(?<!-)\.)+relay\.n0\.iroh\.link\.?\/?$/i
const MAX_LENGTH = 1024

/**
 * Parse a location.hash ("#…" or without the "#").
 * Returns { ok: true, nodeId, code, appLink, shortKey } or { ok: false, reason: 'missing' | 'malformed' | 'demo' }.
 * Unknown parameters and malformed optional ones are dropped, never passed on.
 */
export function parseFragment(hash) {
  const raw = typeof hash === 'string' ? hash.replace(/^#/, '') : ''
  if (raw === '') return { ok: false, reason: 'missing' }
  // Invites minted by the website's Host demo. They lead nowhere, so say so.
  if (/^demo(-|$)/i.test(raw)) return { ok: false, reason: 'demo' }
  if (raw.length > MAX_LENGTH) return { ok: false, reason: 'malformed' }
  const amp = raw.indexOf('&')
  const head = amp < 0 ? raw : raw.slice(0, amp)
  const params = amp < 0 ? [] : raw.slice(amp + 1).split('&')
  const dot = head.indexOf('.')
  const nodeId = (dot < 0 ? head : head.slice(0, dot)).toLowerCase()
  const code = dot < 0 ? '' : head.slice(dot + 1)
  if (!NODE_ID.test(nodeId)) return { ok: false, reason: 'malformed' }
  if (code !== '' && !CODE.test(code)) return { ok: false, reason: 'malformed' }

  const query = []
  const value = (key) => {
    const hit = params.find((p) => p.startsWith(key + '='))
    return hit === undefined ? null : hit.slice(key.length + 1)
  }
  const u = value('u')
  if (u !== null && FALLBACK.test(u)) query.push('u=' + u)
  const l = value('l')
  if (l !== null && LAN_KEY.test(l)) query.push('l=' + l)
  const r = value('r')
  if (r !== null && RELAY.test(r)) query.push('r=' + canonicalRelay(r))

  const appLink = 'skwod://join/' + nodeId + (query.length ? '?' + query.join('&') : '') + (code ? '#' + code : '')
  return { ok: true, nodeId, code: code || null, appLink, shortKey: nodeId.slice(0, 6) + '…' + nodeId.slice(-6) }
}

/** `https://<host>/`, lowercase, no trailing dot — what the Rust parser keeps. */
function canonicalRelay(r) {
  const host = r.slice('https://'.length).replace(/\/$/, '').replace(/\.$/, '').toLowerCase()
  return 'https://' + host + '/'
}

/** 'ios' | 'android' | 'mac' | 'other'. Used only to order the buttons; never sent anywhere. */
export function detectPlatform(nav) {
  const ua = (nav && nav.userAgent) || ''
  if (/Android/i.test(ua)) return 'android'
  if (/iPhone|iPad|iPod/i.test(ua)) return 'ios'
  // iPadOS presents itself as a Mac; a Mac has no touch screen.
  if (/Macintosh/i.test(ua)) return nav.maxTouchPoints > 1 ? 'ios' : 'mac'
  return 'other'
}
