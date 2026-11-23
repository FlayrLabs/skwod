import { CHALLENGE_RE, CREDENTIAL_RE, REVOKE_RE } from "./creds";

export type Kind = "message" | "call";

export interface Wake {
  token: string;
  kind: Kind;
  topic: string;
  /**
   * Optional. An opaque value the DEVICE chose for one of its servers when it registered there;
   * the server hands it back here and it is passed to the device unchanged, so a phone signed in
   * to several servers knows which one woke it. Means nothing to the gateway.
   */
  tag?: string;
  /**
   * Set by the gateway for a wake by credential, never by a caller: the registration id as the
   * device knows it (`"id"` from `/v1/register`). Sent to the device as `skwod_cred`.
   */
  cred?: string;
}

/** A wake by capability: the sealed credential a device registered (see creds.ts) and a kind. */
export interface CredentialWake {
  credential: string;
  kind: Kind;
}

/**
 * How a device shows a token is its own: the value the gateway pushed to it (`/v1/challenge`),
 * or the revoke token of a credential it already holds for it. Never a wake credential — the
 * skwod holds that, and it must not be able to mint or revoke with it.
 */
export type Proof = { challenge: string } | { revoke: string };

export interface Registering {
  proof: Proof;
  apns: string;
  voip: string | null;
  topic: string;
  tag?: string;
}

type Refused = { ok: false; status: number; error: string };

export type Parsed = { ok: true; wake: Wake } | { ok: true; credentialWake: CredentialWake } | Refused;
export type ParsedRegister = { ok: true; registering: Registering } | Refused;
export type ParsedRevoke = { ok: true; revoke: string } | Refused;
/** `/v1/challenge` (no challenge yet) and `/v1/revoke-all` (with one). */
export type ParsedToken = { ok: true; apns: string; topic: string; proof?: Proof } | Refused;

// Sized for the credential shape (a sealed blob of two tokens, a topic and a tag); the raw
// shape never comes near it.
export const MAX_BODY_BYTES = 2048;

// APNs device tokens are 32 bytes today; Apple says not to assume the length.
const TOKEN_RE = /^[0-9a-fA-F]{64,200}$/;
const TOPIC_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,154}$/;
// Short and from a fixed alphabet: enough for a random identifier, useless as a message channel.
const TAG_RE = /^[A-Za-z0-9_-]{16,32}$/;
const KEYS = ["kind", "token", "topic"];
const KEYS_TAGGED = ["kind", "tag", "token", "topic"];
const KEYS_CREDENTIAL = ["credential", "kind"];
const KEYS_REGISTER = ["apns_token", "topic", "voip_token"];
const KEYS_REGISTER_TAGGED = ["apns_token", "tag", "topic", "voip_token"];
const KEYS_CHALLENGE = ["apns_token", "topic"];

const bad = (status: number, error: string): Refused => ({ ok: false, status, error });

export function parseAllowedTopics(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0),
  );
}

/** Reads at most `max` bytes; returns null if the body is larger. */
async function readCapped(body: ReadableStream<Uint8Array>, max: number): Promise<Uint8Array | null> {
  const reader = body.getReader();
  const buf = new Uint8Array(max);
  let len = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (len + value.byteLength > max) {
      await reader.cancel();
      return null;
    }
    buf.set(value, len);
    len += value.byteLength;
  }
  return buf.subarray(0, len);
}

const sameKeys = (keys: string[], expected: string[]) => keys.length === expected.length && keys.every((k, i) => k === expected[i]);
const validToken = (t: unknown): t is string => typeof t === "string" && TOKEN_RE.test(t) && t.length % 2 === 0;

/** The request body as a JSON object and its sorted keys, or the refusal to answer with. */
async function readObject(request: Request): Promise<{ ok: true; data: Record<string, unknown>; keys: string[] } | Refused> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (mediaType !== "application/json") return bad(415, "unsupported_media_type");

  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) {
    return bad(413, "too_large");
  }
  if (request.body === null) return bad(400, "bad_request");
  // content-length can be absent (chunked) or wrong, so the stream is capped too.
  const bytes = await readCapped(request.body, MAX_BODY_BYTES);
  if (bytes === null) return bad(413, "too_large");

  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return bad(400, "bad_request");
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) return bad(400, "bad_request");
  return { ok: true, data: data as Record<string, unknown>, keys: Object.keys(data).sort() };
}

export async function parseWake(request: Request): Promise<Parsed> {
  const body = await readObject(request);
  if (!body.ok) return body;
  const { data, keys } = body;

  if (sameKeys(keys, KEYS_CREDENTIAL)) {
    const { credential, kind } = data;
    if (typeof credential !== "string" || !CREDENTIAL_RE.test(credential)) return bad(400, "bad_request");
    if (kind !== "message" && kind !== "call") return bad(400, "bad_request");
    return { ok: true, credentialWake: { credential, kind } };
  }

  const expected = keys.length === KEYS_TAGGED.length ? KEYS_TAGGED : KEYS;
  if (!sameKeys(keys, expected)) return bad(400, "bad_request");

  const { token, kind, topic, tag } = data;
  if (expected === KEYS_TAGGED && (typeof tag !== "string" || !TAG_RE.test(tag))) return bad(400, "bad_request");
  if (!validToken(token)) return bad(400, "bad_request");
  if (kind !== "message" && kind !== "call") return bad(400, "bad_request");
  if (typeof topic !== "string" || !TOPIC_RE.test(topic)) return bad(400, "bad_request");

  const wake: Wake = { token: token.toLowerCase(), kind, topic };
  if (typeof tag === "string") wake.tag = tag;
  return { ok: true, wake };
}

export async function parseRegister(request: Request): Promise<ParsedRegister> {
  const body = await readObject(request);
  if (!body.ok) return body;
  const { data, keys } = body;
  const proof = takeProof(data, keys);
  if (proof === null) return bad(400, "bad_request");
  const expected = keys.length === KEYS_REGISTER_TAGGED.length ? KEYS_REGISTER_TAGGED : KEYS_REGISTER;
  if (!sameKeys(keys, expected)) return bad(400, "bad_request");

  const { apns_token, voip_token, topic, tag } = data;
  if (expected === KEYS_REGISTER_TAGGED && (typeof tag !== "string" || !TAG_RE.test(tag))) return bad(400, "bad_request");
  if (!validToken(apns_token)) return bad(400, "bad_request");
  if (voip_token !== null && !validToken(voip_token)) return bad(400, "bad_request");
  if (typeof topic !== "string" || !TOPIC_RE.test(topic)) return bad(400, "bad_request");

  const registering: Registering = { proof, apns: apns_token.toLowerCase(), voip: voip_token === null ? null : voip_token.toLowerCase(), topic };
  if (typeof tag === "string") registering.tag = tag;
  return { ok: true, registering };
}

/**
 * Exactly one proof key — `challenge` or `revoke` — well formed; removed from `keys` so the
 * rest can be matched against a fixed set. Null for none, both, or a malformed one.
 */
function takeProof(data: Record<string, unknown>, keys: string[]): Proof | null {
  const present = ["challenge", "revoke"].filter((k) => keys.includes(k));
  if (present.length !== 1) return null;
  const name = present[0]!;
  keys.splice(keys.indexOf(name), 1);
  const value = data[name];
  if (typeof value !== "string") return null;
  if (name === "challenge") return CHALLENGE_RE.test(value) ? { challenge: value } : null;
  return REVOKE_RE.test(value) ? { revoke: value } : null;
}

export async function parseRevoke(request: Request): Promise<ParsedRevoke> {
  const body = await readObject(request);
  if (!body.ok) return body;
  const { revoke } = body.data;
  if (!sameKeys(body.keys, ["revoke"]) || typeof revoke !== "string" || !REVOKE_RE.test(revoke)) return bad(400, "bad_request");
  return { ok: true, revoke };
}

/** `{ apns_token, topic }`, plus exactly one proof when `withProof` (the body of `/v1/revoke-all`). */
export async function parseToken(request: Request, withProof: boolean): Promise<ParsedToken> {
  const body = await readObject(request);
  if (!body.ok) return body;
  const proof = withProof ? takeProof(body.data, body.keys) : undefined;
  if (proof === null) return bad(400, "bad_request");
  if (!sameKeys(body.keys, KEYS_CHALLENGE)) return bad(400, "bad_request");
  const { apns_token, topic } = body.data;
  if (!validToken(apns_token)) return bad(400, "bad_request");
  if (typeof topic !== "string" || !TOPIC_RE.test(topic)) return bad(400, "bad_request");
  const parsed: ParsedToken = { ok: true, apns: apns_token.toLowerCase(), topic };
  if (proof !== undefined) parsed.proof = proof;
  return parsed;
}
