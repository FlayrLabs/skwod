import type { Env } from "./env";
import type { Wake } from "./validate";

export type Outcome = "accepted" | "gone" | "upstream";

const APNS_PROD = "https://api.push.apple.com";
const APNS_SANDBOX = "https://api.sandbox.push.apple.com";

// APNs rejects provider tokens older than 60 min and rate-limits minting more
// often than every 20 min, so one token is reused for 45 min per isolate.
export const JWT_TTL_MS = 45 * 60 * 1000;
const MESSAGE_EXPIRY_S = 3600;
const APNS_TIMEOUT_MS = 10_000;

// "sound": without it the alert is delivered silently — no tone, no haptic — which on a
// sleeping phone reads as "no notification". The app's extension takes the sound off again
// for the one case that should be quiet (background-only traffic).
export const MESSAGE_PAYLOAD = '{"aps":{"alert":{"body":"New message"},"sound":"default","mutable-content":1}}';
export const CALL_PAYLOAD = '{"aps":{},"kind":"call"}';

/**
 * The payload for one wake: the constants above, plus `"tag"` when the wake carries one (an
 * opaque identifier the device itself chose — validated to 16–32 chars of [A-Za-z0-9_-], so it
 * needs no escaping and cannot carry a message), and `"skwod_cred"` when the wake was made with
 * a credential: the id of the registration behind it (base64url, set by the gateway alone). The
 * app knows the ids it registered; a ring that names none of them — or names nothing, once raw
 * wakes are off — was not asked for by any skwod it is in, and it ends it at once.
 */
export function payloadFor(wake: Wake): string {
  let out = (wake.kind === "call" ? CALL_PAYLOAD : MESSAGE_PAYLOAD).slice(0, -1);
  if (wake.tag !== undefined) out += `,"tag":"${wake.tag}"`;
  if (wake.cred !== undefined) out += `,"skwod_cred":"${wake.cred}"`;
  return `${out}}`;
}

/**
 * A registration challenge: a BACKGROUND push — nothing is shown or sounded — carrying the
 * one-time value under `skwod_challenge`. The value is base64url, so it needs no escaping.
 */
export const challengePayload = (challenge: string) => `{"aps":{"content-available":1},"skwod_challenge":"${challenge}"}`;

/** What one APNs request carries. */
interface Push {
  token: string;
  headers: Record<string, string>;
  body: string;
}

function pushFor(wake: Wake, nowMs: number): Push {
  const call = wake.kind === "call";
  return {
    token: wake.token,
    headers: {
      "apns-push-type": call ? "voip" : "alert",
      "apns-topic": call ? `${wake.topic}.voip` : wake.topic,
      "apns-priority": "10",
      "apns-expiration": call ? "0" : String(Math.floor(nowMs / 1000) + MESSAGE_EXPIRY_S),
    },
    body: payloadFor(wake),
  };
}

let cachedJwt: { jwt: string; mintedAt: number; ident: string } | null = null;

export function hasApnsConfig(env: Env): boolean {
  return Boolean(env.APNS_KEY_P8 && env.APNS_KEY_ID && env.APNS_TEAM_ID);
}

function b64url(data: ArrayBuffer | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/\\n/g, "\n") // secret pasted as a single line with escaped newlines
    .replace(/-----[A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export async function providerJwt(env: Env, nowMs: number): Promise<string> {
  const ident = `${env.APNS_KEY_ID}\n${env.APNS_TEAM_ID}\n${env.APNS_KEY_P8}`;
  if (cachedJwt && cachedJwt.ident === ident && nowMs >= cachedJwt.mintedAt && nowMs - cachedJwt.mintedAt < JWT_TTL_MS) {
    return cachedJwt.jwt;
  }
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(env.APNS_KEY_P8!),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const header = b64url(JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID }));
  const claims = b64url(JSON.stringify({ iss: env.APNS_TEAM_ID, iat: Math.floor(nowMs / 1000) }));
  const signingInput = `${header}.${claims}`;
  // WebCrypto ECDSA signatures are raw r||s, which is the JWS ES256 format.
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(signingInput));
  const jwt = `${signingInput}.${b64url(sig)}`;
  cachedJwt = { jwt, mintedAt: nowMs, ident };
  return jwt;
}

async function post(origin: string, push: Push, jwt: string): Promise<{ status: number; reason: string | null }> {
  const res = await fetch(`${origin}/3/device/${push.token}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${jwt}`,
      ...push.headers,
      "content-type": "application/json",
    },
    body: push.body,
    signal: AbortSignal.timeout(APNS_TIMEOUT_MS),
  });
  let reason: string | null = null;
  if (res.status === 200) {
    await res.body?.cancel();
  } else {
    const body = (await res.json().catch(() => null)) as { reason?: unknown } | null;
    if (typeof body?.reason === "string") reason = body.reason;
  }
  return { status: res.status, reason };
}

const isBadDeviceToken = (r: { status: number; reason: string | null }) =>
  r.status === 400 && r.reason === "BadDeviceToken";

export function sendWake(wake: Wake, env: Env, nowMs: number = Date.now()): Promise<Outcome> {
  return send(pushFor(wake, nowMs), env, nowMs);
}

/** Push a registration challenge to `token` — silently, at background priority. */
export function sendChallenge(token: string, topic: string, challenge: string, env: Env, nowMs: number = Date.now()): Promise<Outcome> {
  const push: Push = {
    token,
    headers: {
      "apns-push-type": "background",
      "apns-topic": topic,
      // Apple requires 5 for a background push; 10 is rejected.
      "apns-priority": "5",
      "apns-expiration": String(Math.floor(nowMs / 1000) + 120),
    },
    body: challengePayload(challenge),
  };
  return send(push, env, nowMs);
}

async function send(push: Push, env: Env, nowMs: number): Promise<Outcome> {
  try {
    const jwt = await providerJwt(env, nowMs);
    let res = await post(new URL(env.APNS_HOST || APNS_PROD).origin, push, jwt);
    if (isBadDeviceToken(res)) {
      // Production answers BadDeviceToken for tokens issued to dev-signed builds.
      res = await post(new URL(env.APNS_SANDBOX_HOST || APNS_SANDBOX).origin, push, jwt);
      if (isBadDeviceToken(res)) return "gone";
    }
    if (res.status === 200) return "accepted";
    if (res.status === 410) return "gone";
    if (res.status === 403 && res.reason === "ExpiredProviderToken") cachedJwt = null;
    return "upstream";
  } catch {
    return "upstream";
  }
}
