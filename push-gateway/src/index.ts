import { type Outcome, hasApnsConfig, sendChallenge, sendWake } from "./apns";
import type { Env } from "./env";
import {
  CHALLENGE_TTL_MS,
  MAX_TTL_SECONDS,
  hasCredentialSecret,
  mint,
  mintChallenge,
  newRegistrationId,
  open,
  openChallenge,
  openRevoke,
  publicId,
  ttlSeconds,
} from "./creds";
import {
  type ProofKeys,
  type TakeOptions,
  challengeKeyInput,
  credentialKeyInput,
  cutoffKeyInput,
  destKeyInput,
  deviceKeyInput,
  hasRateKeySalt,
  limiterKey,
  limitsFromEnv,
  liveKeyInput,
  mintKeyInput,
  pendingKeyInput,
  sourceKeyInput,
  sourceOf,
  spentKeyInput,
} from "./ratelimit";
import { type Parsed, type Proof, type Wake, parseAllowedTopics, parseRegister, parseRevoke, parseToken, parseWake } from "./validate";

export { RateLimiter } from "./ratelimit";

// Privacy invariants for this file and everything it calls: never log, never read request.cf,
// never store anything but the rate-limit rows, the short-lived dead-token marks, revocations,
// used challenges and minting counts — every one keyed by an HMAC (of a token, a registration
// id, a nonce or a source address), never by the value itself.
//
// The caller's address (`cf-connecting-ip`) is read in exactly one place, `sourceLimited`, and
// only to compute the HMAC its per-caller row is keyed by; that row lives for a minute. It is
// never logged, returned, or stored next to a token or credential. (It used to be never read
// at all, with the per-caller limit left to a Cloudflare rule — which cannot be put in front
// of a workers.dev address, where the publisher's gateway lives.)

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
}

const fail = (status: number, error: string, headers?: Record<string, string>) =>
  json(status, { ok: false, error }, headers);

const limiterOf = (env: Env) => env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName("global"));

/**
 * `POST /v1/challenge`, called by the DEVICE before it registers: push a one-time value to the
 * token, silently. Only the device that owns the token receives it, so sending it back proves
 * the caller is that device and not merely someone who knows the token.
 */
async function challenge(request: Request, env: Env): Promise<Response> {
  const parsed = await parseToken(request, false);
  if (!parsed.ok) return fail(parsed.status, parsed.error);
  if (!parseAllowedTopics(env.ALLOWED_TOPICS).has(parsed.topic)) return fail(403, "forbidden");
  if (!hasCredentialSecret(env.WAKE_CRED_SECRET) || !hasApnsConfig(env)) return fail(503, "unavailable");

  // One decision in the limiter: if a challenge is already on the device and still good, say
  // yes, send nothing, count nothing — a flood of requests for someone's token costs that
  // device one silent push per ten minutes and none of its budget. Otherwise the allowance is
  // checked and this push is counted and marked outstanding before it is sent.
  const pendingKey = await limiterKey(pendingKeyInput(parsed.apns), env.RATE_KEY_SALT);
  // The same mark a wake to a dead token leaves: a made-up token costs Apple one look, not one
  // per request.
  const deadKey = await limiterKey(parsed.apns, env.RATE_KEY_SALT);
  const issuedAt = Date.now();
  const untilMs = issuedAt + CHALLENGE_TTL_MS;
  const decision = await limiterOf(env).challengeBegin(
    pendingKey,
    await limiterKey(challengeKeyInput(parsed.apns), env.RATE_KEY_SALT),
    limitsFromEnv(env),
    untilMs,
    deadKey,
  );
  if (!decision.ok) {
    if ("gone" in decision) return fail(410, "gone");
    return fail(429, "rate_limited", { "retry-after": String(decision.retryAfterS) });
  }
  if (!decision.send) return json(202, { ok: true });

  let outcome: Outcome = "upstream";
  try {
    outcome = await sendChallenge(parsed.apns, parsed.topic, await mintChallenge(env.WAKE_CRED_SECRET, parsed.apns, issuedAt), env);
  } finally {
    // Not delivered: it is not outstanding, and the next request pushes again.
    if (outcome !== "accepted") await limiterOf(env).challengeFailed(pendingKey, untilMs, outcome === "gone" ? deadKey : undefined);
  }
  switch (outcome) {
    case "accepted":
      return json(202, { ok: true });
    case "gone":
      return fail(410, "gone");
    case "upstream":
      return fail(503, "upstream");
  }
}

/**
 * The proof a caller presents that `apns` is its own token, reduced to what the limiter checks
 * (and, for a challenge, uses up) in the same step as the thing it authorises. Null: it is not
 * even well formed for this token — forged, or for another one.
 *
 * - `challenge`: the value pushed to the token. Single use.
 * - `revoke`: the revoke token of a credential that is still outstanding for this very token.
 *   Only the device ever held it, so it stands in for a challenge when the device cannot get
 *   one (its challenge allowance was used up by someone else). It is not consumed.
 * A wake credential is never proof: the skwod holds it.
 */
async function proofKeys(env: Env, secret: string, proof: Proof, apns: string): Promise<ProofKeys | null> {
  if ("challenge" in proof) {
    const opened = await openChallenge(secret, proof.challenge, apns);
    if (opened === null) return null;
    return {
      spentKey: await limiterKey(spentKeyInput(opened.nonce), env.RATE_KEY_SALT),
      pendingKey: await limiterKey(pendingKeyInput(apns), env.RATE_KEY_SALT),
      expMs: opened.expMs,
    };
  }
  const named = await openRevoke(secret, proof.revoke);
  if (named === null || named.exp * 1000 <= Date.now()) return null;
  return { credentialKey: await limiterKey(credentialKeyInput(named.id), env.RATE_KEY_SALT) };
}

/**
 * `POST /v1/register`, called by the DEVICE: seal its push tokens into a credential it can hand
 * to one skwod, and give it (alone) the token that revokes that credential and the id its
 * pushes will carry. Needs proof for the APNs token.
 *
 * The credential is the PAIR (proven APNs token, VoIP token as given). The VoIP token cannot be
 * proven — a VoIP push rings — and is not owned by anyone here: two devices may name the same
 * one and neither affects the other. Everything that can end a credential (revoke, revoke-all,
 * eviction, expiry) hangs off its proven APNs token alone. What bounds rings to a VoIP token
 * its holder did not ask for is the per-VoIP-token ring budget and the app, which ends a ring
 * whose `skwod_cred` it did not register.
 */
async function register(request: Request, env: Env): Promise<Response> {
  const parsed = await parseRegister(request);
  if (!parsed.ok) return fail(parsed.status, parsed.error);
  const reg = parsed.registering;
  if (!parseAllowedTopics(env.ALLOWED_TOPICS).has(reg.topic)) return fail(403, "forbidden");
  if (!hasCredentialSecret(env.WAKE_CRED_SECRET)) return fail(503, "unavailable");
  const secret = env.WAKE_CRED_SECRET;
  const proof = await proofKeys(env, secret, reg.proof, reg.apns);
  if (proof === null) return fail(403, "forbidden");

  // The id first, so that proof, caps, admission and eviction are one step in the limiter;
  // sealing afterwards needs nothing from it but the moment it chose.
  const id = newRegistrationId();
  const ttlS = ttlSeconds(env.CRED_TTL_DAYS);
  const admitted = await limiterOf(env).register({
    proof,
    liveKey: await limiterKey(liveKeyInput(reg.apns), env.RATE_KEY_SALT),
    cutoffKey: await limiterKey(cutoffKeyInput(reg.apns), env.RATE_KEY_SALT),
    credentialKey: await limiterKey(credentialKeyInput(id), env.RATE_KEY_SALT),
    mintKey: await limiterKey(mintKeyInput(reg.apns), env.RATE_KEY_SALT),
    ttlS,
    limits: limitsFromEnv(env),
  });
  if (!admitted.ok) {
    if ("forbidden" in admitted) return fail(403, "forbidden");
    return fail(429, "rate_limited", { "retry-after": String(admitted.retryAfterS) });
  }
  const minted = await mint(secret, reg, ttlS, admitted.issued, id);
  return json(200, { ok: true, credential: minted.credential, revoke: minted.revoke, id: publicId(id), expires_at: minted.registration.exp });
}

/**
 * `POST /v1/revoke-all`, called by the device (erase; "cut off every skwod"): every credential
 * minted under this APNs token up to now is gone, whoever holds it — alerts and rings alike.
 * Credentials minted under any other APNs token are untouched, whatever VoIP token they name.
 * Needs a challenge, or the revoke token of a live credential.
 */
async function revokeAll(request: Request, env: Env): Promise<Response> {
  const parsed = await parseToken(request, true);
  if (!parsed.ok) return fail(parsed.status, parsed.error);
  if (!parseAllowedTopics(env.ALLOWED_TOPICS).has(parsed.topic)) return fail(403, "forbidden");
  if (!hasCredentialSecret(env.WAKE_CRED_SECRET)) return fail(503, "unavailable");
  const proof = await proofKeys(env, env.WAKE_CRED_SECRET, parsed.proof!, parsed.apns);
  if (proof === null) return fail(403, "forbidden");
  // Kept as long as any credential minted before now could still be alive.
  const done = await limiterOf(env).revokeAll(
    proof,
    await limiterKey(liveKeyInput(parsed.apns), env.RATE_KEY_SALT),
    await limiterKey(cutoffKeyInput(parsed.apns), env.RATE_KEY_SALT),
    MAX_TTL_SECONDS * 1000,
  );
  return done ? json(200, { ok: true }) : fail(403, "forbidden");
}

/** `POST /v1/revoke`, called by the device on sign-out, leave or erase. Idempotent. */
async function revoke(request: Request, env: Env): Promise<Response> {
  const parsed = await parseRevoke(request);
  if (!parsed.ok) return fail(parsed.status, parsed.error);
  if (!hasCredentialSecret(env.WAKE_CRED_SECRET)) return fail(503, "unavailable");
  const named = await openRevoke(env.WAKE_CRED_SECRET, parsed.revoke);
  if (named === null) return fail(403, "forbidden");
  // Already expired: nothing left to revoke.
  if (named.exp * 1000 > Date.now()) {
    await limiterOf(env).revoke(await limiterKey(credentialKeyInput(named.id), env.RATE_KEY_SALT), named.exp * 1000);
  }
  return json(200, { ok: true });
}

/** What a wake resolved to: where it goes, and which rows it is counted and refused under. */
interface Target {
  wake: Wake;
  budgetKey: string;
  options: TakeOptions & { deadKey: string; destKey: string };
}

async function resolve(parsed: Extract<Parsed, { ok: true }>, env: Env): Promise<Target | Response> {
  if ("wake" in parsed) {
    // The legacy shape: a raw token, known to every skwod that was ever handed it. It keeps its
    // own budget (keyed by the token alone — the tag is the caller's to invent), which no
    // credential's budget shares.
    if (env.LEGACY_RAW_WAKES === "0") return fail(410, "gone");
    if (!parseAllowedTopics(env.ALLOWED_TOPICS).has(parsed.wake.topic)) return fail(403, "forbidden");
    const key = await limiterKey(parsed.wake.token, env.RATE_KEY_SALT);
    const destKey = await limiterKey(destKeyInput(parsed.wake.token), env.RATE_KEY_SALT);
    return { wake: parsed.wake, budgetKey: key, options: { deadKey: key, destKey, revocable: false } };
  }
  const { credential, kind } = parsed.credentialWake;
  if (!hasCredentialSecret(env.WAKE_CRED_SECRET)) return fail(503, "unavailable");
  const reg = await open(env.WAKE_CRED_SECRET, credential);
  if (reg === null) return fail(403, "forbidden");
  if (reg.exp * 1000 <= Date.now()) return fail(410, "gone");
  // An empty allowlist yields an empty set, which refuses everything.
  if (!parseAllowedTopics(env.ALLOWED_TOPICS).has(reg.topic)) return fail(403, "forbidden");
  // The skwod cannot see whether a VoIP token was sealed in, so it asks for the kind it means.
  // A call for a registration made before PushKit delivered a token is sent as a message wake
  // — an alert to the APNs token, counted as a message — rather than dropped: the phone still
  // learns something is up, and the device registers again once it has a VoIP token.
  const effective: Wake["kind"] = kind === "call" && reg.voip === null ? "message" : kind;
  const token = effective === "call" ? reg.voip! : reg.apns;
  // `cred`: the device gets the registration's id with the push and checks it is one of its own.
  const wake: Wake = { token, kind: effective, topic: reg.topic, cred: publicId(reg.id) };
  if (reg.tag !== undefined) wake.tag = reg.tag;
  return {
    wake,
    budgetKey: await limiterKey(credentialKeyInput(reg.id), env.RATE_KEY_SALT),
    options: {
      deadKey: await limiterKey(token, env.RATE_KEY_SALT),
      // The device ceiling, shared by every credential of the same PROVEN device: its APNs
      // token for an alert, the (APNs token, VoIP token) pair for a ring. Another device's
      // credentials naming the same VoIP token count under their own pair, and raw wakes under
      // the raw rows — nobody else can spend this.
      destKey: await limiterKey(deviceKeyInput(reg.apns, effective === "call" ? reg.voip : null), env.RATE_KEY_SALT),
      revocable: true,
      // Cut off only by the owner of the APNs token it was minted under — both halves, the
      // alert and the ring. Never by anything keyed on the VoIP token.
      cutoffKey: await limiterKey(cutoffKeyInput(reg.apns), env.RATE_KEY_SALT),
      issuedMs: reg.issued,
    },
  };
}

async function wakeRoute(request: Request, env: Env): Promise<Response> {
  const parsed = await parseWake(request);
  if (!parsed.ok) return fail(parsed.status, parsed.error);
  const target = await resolve(parsed, env);
  if (target instanceof Response) return target;
  const { wake, budgetKey, options } = target;
  if (!hasApnsConfig(env)) return fail(503, "unavailable");

  const limiter = limiterOf(env);
  const decision = await limiter.take(budgetKey, wake.kind, limitsFromEnv(env), Date.now(), options);
  if (!decision.ok) {
    // Revoked, or recently reported dead by APNs: same answer, without asking APNs again.
    if ("gone" in decision) return fail(410, "gone");
    return fail(429, "rate_limited", { "retry-after": String(decision.retryAfterS) });
  }

  switch (await sendWake(wake, env)) {
    case "accepted":
      return json(202, { ok: true });
    case "gone":
      // A dead token must not consume rate budget, or junk tokens could.
      await limiter.markDead(budgetKey, wake.kind, decision.ts, Date.now(), options.deadKey, options.destKey);
      return fail(410, "gone");
    case "upstream":
      return fail(503, "upstream");
  }
}

const ROUTES: Record<string, (request: Request, env: Env) => Promise<Response>> = {
  "/v1/wake": wakeRoute,
  "/v1/challenge": challenge,
  "/v1/register": register,
  "/v1/revoke": revoke,
  "/v1/revoke-all": revokeAll,
};

/**
 * The per-caller limit: null to go on, or the 429 to answer with. Applied to every POST route
 * before the body is read — so before any APNs request and before a made-up token is looked
 * at. No address (not behind Cloudflare: local dev, tests) or a limit of 0: not limited.
 */
async function sourceLimited(request: Request, env: Env, pathname: string): Promise<Response | null> {
  const source = sourceOf(request.headers.get("cf-connecting-ip"));
  if (source === null) return null;
  const routeClass = pathname === "/v1/wake" ? "wake" : "device";
  const limits = limitsFromEnv(env);
  const max = routeClass === "wake" ? limits.sourceWakePerMinute : limits.sourceDevicePerMinute;
  if (max === 0) return null;
  const decision = await limiterOf(env).sourceTake(await limiterKey(sourceKeyInput(routeClass, source), env.RATE_KEY_SALT), max);
  return decision.ok ? null : fail(429, "rate_limited", { "retry-after": String(decision.retryAfterS) });
}

async function handle(request: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(request.url);
  const method = request.method;

  // No CORS, so preflights are refused everywhere: callers are servers and the app, never a page.
  if (method === "OPTIONS") return fail(405, "method_not_allowed");
  if (pathname === "/health") {
    return method === "GET" ? json(200, { status: "ok" }) : fail(405, "method_not_allowed", { allow: "GET" });
  }
  const route = Object.hasOwn(ROUTES, pathname) ? ROUTES[pathname] : undefined;
  if (route === undefined) return fail(404, "not_found");
  if (method !== "POST") return fail(405, "method_not_allowed", { allow: "POST" });
  // Fail closed: without the secret that keys every stored row there is no limiter, and no
  // public constant stands in for it. Nothing is parsed, counted or sent.
  if (!hasRateKeySalt(env.RATE_KEY_SALT)) return fail(503, "unavailable");
  const limited = await sourceLimited(request, env, pathname);
  if (limited !== null) return limited;
  return route(request, env);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handle(request, env);
    } catch {
      // Deliberately silent: an error object could carry request-derived data.
      return fail(503, "unavailable");
    }
  },
} satisfies ExportedHandler<Env>;
