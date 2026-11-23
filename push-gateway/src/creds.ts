// Wake credentials: what a device gets from `/v1/register` and hands to ONE skwod.
//
// - The credential (`w1.…`) is an AES-256-GCM sealed blob only this gateway can open. It holds
//   the push tokens, so the skwod that carries it never learns them and cannot wake the device
//   by any other route once the device revokes it.
// - The revoke token (`r1.…`) goes to the device alone. It is a MAC under a second key over the
//   registration id, which exists in the clear only inside the sealed credential — a credential
//   holder can neither read the id nor forge the MAC.
// Nothing here is stored: the gateway keeps state only for revocations and minting counts, keyed
// by HMACs (see ratelimit.ts).

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export const MIN_SECRET_CHARS = 32;
export const DEFAULT_TTL_DAYS = 30;
const MAX_TTL_DAYS = 400;
export const MAX_TTL_SECONDS = MAX_TTL_DAYS * 86_400;
const ID_BYTES = 16;
const NONCE_BYTES = 12;
const MAC_BYTES = 32;
const SEAL_INFO = "skwod-push-gateway/credential/v1/seal";
const REVOKE_INFO = "skwod-push-gateway/credential/v1/revoke";
const CHALLENGE_INFO = "skwod-push-gateway/credential/v1/challenge";
const CHALLENGE_NONCE_BYTES = 16;
/** How long a registration challenge is good for after it was pushed. */
export const CHALLENGE_TTL_MS = 10 * 60 * 1000;
export const CHALLENGE_RE = /^c1\.[A-Za-z0-9_-]{75}$/;

export const CREDENTIAL_RE = /^w1\.[A-Za-z0-9_-]{40,1600}$/;
export const REVOKE_RE = /^r1\.[A-Za-z0-9_-]{75}$/;

export interface Registration {
  /**
   * Random registration id, hex. The DEVICE learns it (`"id"` from `/v1/register`, and it is in
   * the revoke token) and gets it back in every push sent for this credential (`skwod_cred`),
   * so it can tell a wake for a credential it registered from any other. The skwod, which holds
   * only the sealed credential, never sees it.
   */
  id: string;
  apns: string;
  voip: string | null;
  topic: string;
  tag?: string;
  /** Unix seconds. */
  exp: number;
  /** When it was minted, unix milliseconds: what `/v1/revoke-all` cuts off by. */
  issued: number;
}

interface Keys {
  seal: CryptoKey;
  revoke: CryptoKey;
  challenge: CryptoKey;
}

let cached: { secret: string; keys: Keys } | null = null;

export function hasCredentialSecret(secret: string | undefined): secret is string {
  return typeof secret === "string" && secret.length >= MIN_SECRET_CHARS;
}

export function ttlSeconds(raw: string | undefined): number {
  const n = Number(raw);
  const days = raw !== undefined && Number.isInteger(n) && n > 0 ? Math.min(n, MAX_TTL_DAYS) : DEFAULT_TTL_DAYS;
  return days * 86_400;
}

async function keys(secret: string): Promise<Keys> {
  if (cached && cached.secret === secret) return cached.keys;
  const master = await crypto.subtle.importKey("raw", enc.encode(secret), "HKDF", false, ["deriveKey"]);
  const hkdf = (info: string) => ({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode(info) });
  const seal = await crypto.subtle.deriveKey(hkdf(SEAL_INFO), master, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const mac = (info: string) =>
    crypto.subtle.deriveKey(hkdf(info), master, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign", "verify"]);
  const revoke = await mac(REVOKE_INFO);
  const challenge = await mac(CHALLENGE_INFO);
  cached = { secret, keys: { seal, revoke, challenge } };
  return cached.keys;
}

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(s: string): Uint8Array | null {
  try {
    return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** id (16) ‖ expiry (8, big-endian seconds): what the revoke MAC covers. */
function revokeBody(id: string, exp: number): Uint8Array {
  const body = new Uint8Array(ID_BYTES + 8);
  body.set(unhex(id), 0);
  new DataView(body.buffer).setBigUint64(ID_BYTES, BigInt(exp));
  return body;
}

/** A new random registration id (hex). */
export const newRegistrationId = () => hex(crypto.getRandomValues(new Uint8Array(ID_BYTES)));

/** The registration id as the device sees it: base64url of its 16 bytes (22 characters, nothing to escape). */
export const publicId = (id: string) => b64url(unhex(id));

export interface Minted {
  credential: string;
  revoke: string;
  registration: Registration;
}

export async function mint(
  secret: string,
  input: { apns: string; voip: string | null; topic: string; tag?: string },
  ttlS: number,
  nowMs: number = Date.now(),
  id: string = newRegistrationId(),
): Promise<Minted> {
  const k = await keys(secret);
  const registration: Registration = {
    id,
    apns: input.apns,
    voip: input.voip,
    topic: input.topic,
    exp: Math.floor(nowMs / 1000) + ttlS,
    issued: nowMs,
  };
  if (input.tag !== undefined) registration.tag = input.tag;
  const plain = JSON.stringify({
    i: registration.id,
    a: registration.apns,
    v: registration.voip,
    t: registration.topic,
    g: registration.tag ?? null,
    e: registration.exp,
    s: registration.issued,
  });
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k.seal, enc.encode(plain)));
  const blob = new Uint8Array(NONCE_BYTES + sealed.length);
  blob.set(nonce, 0);
  blob.set(sealed, NONCE_BYTES);

  const body = revokeBody(registration.id, registration.exp);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k.revoke, body));
  const token = new Uint8Array(body.length + MAC_BYTES);
  token.set(body, 0);
  token.set(mac, body.length);
  return { credential: `w1.${b64url(blob)}`, revoke: `r1.${b64url(token)}`, registration };
}

/** The registration inside a credential, or null if it is not one this gateway sealed. Expiry is the caller's check. */
export async function open(secret: string, credential: string): Promise<Registration | null> {
  if (!CREDENTIAL_RE.test(credential)) return null;
  const blob = unb64url(credential.slice(3));
  if (blob === null || blob.length <= NONCE_BYTES + 16) return null;
  const k = await keys(secret);
  let data: unknown;
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, NONCE_BYTES) }, k.seal, blob.subarray(NONCE_BYTES));
    data = JSON.parse(dec.decode(plain));
  } catch {
    return null;
  }
  const { i, a, v, t, g, e, s } = data as Record<string, unknown>;
  if (typeof i !== "string" || typeof a !== "string" || typeof t !== "string" || typeof e !== "number" || typeof s !== "number") return null;
  if (v !== null && typeof v !== "string") return null;
  const registration: Registration = { id: i, apns: a, voip: v, topic: t, exp: e, issued: s };
  if (typeof g === "string") registration.tag = g;
  return registration;
}

/** The (registration id, expiry) a revoke token names, or null if its MAC is not ours. */
export async function openRevoke(secret: string, token: string): Promise<{ id: string; exp: number } | null> {
  if (!REVOKE_RE.test(token)) return null;
  const bytes = unb64url(token.slice(3));
  if (bytes === null || bytes.length !== ID_BYTES + 8 + MAC_BYTES) return null;
  const k = await keys(secret);
  const body = bytes.subarray(0, ID_BYTES + 8);
  // `verify` compares in constant time.
  if (!(await crypto.subtle.verify("HMAC", k.revoke, bytes.subarray(ID_BYTES + 8), body))) return null;
  const exp = Number(new DataView(body.buffer, body.byteOffset, body.byteLength).getBigUint64(ID_BYTES));
  return { id: hex(body.subarray(0, ID_BYTES)), exp };
}

// ---- registration challenges: proof that the caller can receive pushes for a token ----
//
// `/v1/challenge` pushes one of these to the token; only the device that owns the token sees
// it, and `/v1/register` / `/v1/revoke-all` want it back. Stateless to issue: nonce ‖ expiry ‖
// HMAC(key, nonce ‖ expiry ‖ token). Single use is the caller's job (the nonce is what to record).

function challengeInput(nonce: Uint8Array, expMs: number, apnsToken: string): Uint8Array {
  const token = enc.encode(apnsToken);
  const body = new Uint8Array(CHALLENGE_NONCE_BYTES + 8 + token.length);
  body.set(nonce, 0);
  new DataView(body.buffer).setBigUint64(CHALLENGE_NONCE_BYTES, BigInt(expMs));
  body.set(token, CHALLENGE_NONCE_BYTES + 8);
  return body;
}

export async function mintChallenge(secret: string, apnsToken: string, nowMs: number = Date.now()): Promise<string> {
  const k = await keys(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(CHALLENGE_NONCE_BYTES));
  const input = challengeInput(nonce, nowMs + CHALLENGE_TTL_MS, apnsToken);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k.challenge, input));
  const out = new Uint8Array(CHALLENGE_NONCE_BYTES + 8 + MAC_BYTES);
  out.set(input.subarray(0, CHALLENGE_NONCE_BYTES + 8), 0);
  out.set(mac, CHALLENGE_NONCE_BYTES + 8);
  return `c1.${b64url(out)}`;
}

/** The challenge's nonce (hex) and expiry if it was issued by this gateway for exactly `apnsToken`; else null. Expiry is the caller's check. */
export async function openChallenge(secret: string, challenge: string, apnsToken: string): Promise<{ nonce: string; expMs: number } | null> {
  if (!CHALLENGE_RE.test(challenge)) return null;
  const bytes = unb64url(challenge.slice(3));
  if (bytes === null || bytes.length !== CHALLENGE_NONCE_BYTES + 8 + MAC_BYTES) return null;
  const k = await keys(secret);
  const nonce = bytes.subarray(0, CHALLENGE_NONCE_BYTES);
  const expMs = Number(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(CHALLENGE_NONCE_BYTES));
  const ok = await crypto.subtle.verify("HMAC", k.challenge, bytes.subarray(CHALLENGE_NONCE_BYTES + 8), challengeInput(nonce, expMs, apnsToken));
  return ok ? { nonce: hex(nonce), expMs } : null;
}
