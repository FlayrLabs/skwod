import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";
import type { Kind } from "./validate";

export interface Limits {
  messageBurst: number;
  messageBurstWindowS: number;
  messagePerTenMinutes: number;
  messagePerHour: number;
  callPerMinute: number;
  globalPerMinute: number;
  /** Credentials minted per proven APNs token per day (`/v1/register`). */
  registerPerDay: number;
  /**
   * Per-DEVICE ceilings, counted per PROVEN device across all of its credentials: per proven
   * APNs token for alerts, per (proven APNs token, VoIP token) pair for rings. Never per VoIP
   * token alone — that would be a budget a stranger naming the token could spend. Message rules
   * are the per-credential ones times this factor.
   */
  destMessageFactor: number;
  /** Rings per (proven APNs token, VoIP token) pair, across every credential minted for it. */
  destCallPerMinute: number;
  destCallPerHour: number;
  /** Registration challenges pushed per APNs token (`/v1/challenge`). */
  challengePerTenMinutes: number;
  challengePerDay: number;
  /** Outstanding credentials per APNs token; one more evicts the oldest. */
  liveCredentials: number;
  /** Requests per minute from one source address (0 = off): wakes, and the device routes together. */
  sourceWakePerMinute: number;
  sourceDevicePerMinute: number;
}

export const DEFAULT_LIMITS: Limits = {
  messageBurst: 1,
  messageBurstWindowS: 5,
  // The sustained rate. A Skwod server coalesces: at most one message wake per token roughly
  // every 21–26 s while a chat is busy, i.e. ≤ 28 per 10 minutes. 30 per 10 minutes therefore
  // never refuses a single busy server — the old shape (60 per HOUR and nothing shorter) let a
  // lively chat spend its hour in ~25 minutes and then left the phone silent for the other 35.
  messagePerTenMinutes: 30,
  // A ceiling for a token that several servers wake at once: 30 / 10 min sustained is 180 / h.
  messagePerHour: 180,
  callPerMinute: 6,
  // 0 = off (the default). See README "Why there is no global cap".
  globalPerMinute: 0,
  // A device registers once per skwod and again when a token changes or a credential nears its
  // expiry; 24 a day leaves room for a phone in many skwods and is useless for mass minting.
  registerPerDay: 24,
  // Several skwods legitimately wake one phone, so the message ceiling sits well above one
  // credential's budget: no single credential can reach it alone, and so none can starve the
  // others. What it stops is multiplication — however many credentials a proven device has,
  // it gets at most this many alerts.
  destMessageFactor: 4,
  // Rings are different. A VoIP token cannot be proven (a VoIP push rings), so a credential can
  // name a VoIP token that is not its holder's. Each proven device therefore gets its own low
  // ring share for the VoIP token it names: a stranger's credentials spend the stranger's
  // share, never the owner's, and the app ends at once any ring whose `skwod_cred` it does not
  // know. (One credential can fill its device's minute — the two are equal.)
  destCallPerMinute: 6,
  destCallPerHour: 20,
  // A challenge is a silent push; this keeps the endpoint useless for pestering a device.
  challengePerTenMinutes: 3,
  challengePerDay: 10,
  // More skwods than anyone is in. Only the device can mint (the challenge), so when it is
  // full the oldest goes rather than the newest being refused: a phone that lost what it had
  // stored can always get back in, and what it lost stops working.
  liveCredentials: 16,
  // Per CALLER, whatever tokens it names: what bounds a stranger sending made-up tokens (each
  // one would otherwise cost requests to Apple under the publisher's key). A busy self-hosted
  // server sends a few wakes a minute; a phone makes a handful of device calls a day.
  sourceWakePerMinute: 120,
  sourceDevicePerMinute: 10,
};

export type Decision = { ok: true; ts: number } | { ok: false; retryAfterS: number } | { ok: false; gone: true };

/**
 * What a wake is checked against besides its own budget row. `deadKey`: the HMAC of the push
 * token it would go to (default: the budget key, which for a raw wake IS the token's HMAC).
 * `revocable`: the budget key names a registration, so a revocation of it answers "gone".
 */
export interface TakeOptions {
  deadKey?: string;
  revocable?: boolean;
  /** The per-device ceiling is counted under this when given: HMAC of the proven device (credentials) or of the token (raw path). */
  destKey?: string;
  /** With `issuedMs`: refuse ("gone") a credential minted before a `/v1/revoke-all` recorded under this (its own proven APNs token, never a VoIP token). */
  cutoffKey?: string;
  issuedMs?: number;
}

export type Rule = [windowMs: number, max: number];

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
// Longest window any rule looks back over; rows older than this are deleted.
const RETENTION_MS = HOUR_MS;
const SWEEP_INTERVAL_MS = MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
// With only long-lived rows left (revocations, minting counts) there is nothing to do every minute.
const SLOW_SWEEP_INTERVAL_MS = HOUR_MS;
// How long a token APNs called dead is answered "gone" without asking APNs again.
export const DEAD_TTL_MS = 10 * MINUTE_MS;
/** `RATE_KEY_SALT` must be at least this long (`openssl rand -hex 32` gives 64). */
export const MIN_SALT_CHARS = 16;

/**
 * Is the secret that keys every stored row set? It is REQUIRED: with a public constant in its
 * place (what an unset salt used to mean), anyone who can read the stored rows — the account
 * owner, Cloudflare — could test whether a token they know was woken, minted or revoked.
 */
export function hasRateKeySalt(salt: string | undefined): salt is string {
  return typeof salt === "string" && salt.length >= MIN_SALT_CHARS;
}

function positiveInt(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return raw !== undefined && Number.isInteger(n) && n > 0 ? n : fallback;
}

function nonNegativeInt(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return raw !== undefined && raw !== "" && Number.isInteger(n) && n >= 0 ? n : fallback;
}

export function limitsFromEnv(env: Env): Limits {
  const d = DEFAULT_LIMITS;
  return {
    messageBurst: positiveInt(env.RL_MESSAGE_BURST, d.messageBurst),
    messageBurstWindowS: Math.min(positiveInt(env.RL_MESSAGE_BURST_WINDOW_S, d.messageBurstWindowS), RETENTION_MS / 1000),
    messagePerTenMinutes: positiveInt(env.RL_MESSAGE_PER_10MIN, d.messagePerTenMinutes),
    messagePerHour: positiveInt(env.RL_MESSAGE_PER_HOUR, d.messagePerHour),
    callPerMinute: positiveInt(env.RL_CALL_PER_MINUTE, d.callPerMinute),
    globalPerMinute: nonNegativeInt(env.RL_GLOBAL_PER_MINUTE, d.globalPerMinute),
    registerPerDay: positiveInt(env.RL_REGISTER_PER_DAY, d.registerPerDay),
    destMessageFactor: positiveInt(env.RL_DEST_MESSAGE_FACTOR, d.destMessageFactor),
    destCallPerMinute: positiveInt(env.RL_DEST_CALL_PER_MINUTE, d.destCallPerMinute),
    destCallPerHour: positiveInt(env.RL_DEST_CALL_PER_HOUR, d.destCallPerHour),
    challengePerTenMinutes: positiveInt(env.RL_CHALLENGE_PER_10MIN, d.challengePerTenMinutes),
    challengePerDay: positiveInt(env.RL_CHALLENGE_PER_DAY, d.challengePerDay),
    liveCredentials: positiveInt(env.LIVE_CREDENTIALS_PER_TOKEN, d.liveCredentials),
    sourceWakePerMinute: nonNegativeInt(env.RL_SOURCE_WAKE_PER_MINUTE, d.sourceWakePerMinute),
    sourceDevicePerMinute: nonNegativeInt(env.RL_SOURCE_DEVICE_PER_MINUTE, d.sourceDevicePerMinute),
  };
}

/**
 * Domain prefixes for limiter keys that are not a bare token. A token is hex, so none of these
 * can collide with one: a raw wake's budget, a credential's budget and a token's minting count
 * are three separate rows no caller can steer into each other.
 */
export const credentialKeyInput = (registrationId: string) => `credential\0${registrationId}`;
export const mintKeyInput = (token: string) => `mint\0${token}`;
/** The raw path's own ceiling row for a token. No credential's wake is ever counted under it. */
export const destKeyInput = (token: string) => `destination\0${token}`;
/**
 * A proven device's ceiling row: its proven APNs token for alerts, the (proven APNs token,
 * VoIP token) pair for rings. Two devices naming the same VoIP token get two rows.
 */
export const deviceKeyInput = (apnsToken: string, voipToken: string | null = null) =>
  voipToken === null ? `device\0${apnsToken}` : `device\0${apnsToken}\0${voipToken}`;
export const challengeKeyInput = (apnsToken: string) => `challenge\0${apnsToken}`;
export const pendingKeyInput = (apnsToken: string) => `pending\0${apnsToken}`;
export const spentKeyInput = (nonce: string) => `spent\0${nonce}`;
export const cutoffKeyInput = (apnsToken: string) => `revoke-all\0${apnsToken}`;
export const liveKeyInput = (apnsToken: string) => `live\0${apnsToken}`;
/** A caller's row: the route class and its source address (see `sourceOf`). Only its HMAC is stored, for a minute. */
export const sourceKeyInput = (routeClass: "wake" | "device", source: string) => `source\0${routeClass}\0${source}`;

/**
 * What one caller is counted under: an IPv4 address as given; for IPv6 the /64 (the first four
 * groups) — one subscriber has a whole /64 to pick addresses from. Null: not an address.
 */
export function sourceOf(ip: string | null): string | null {
  if (ip === null) return null;
  const s = ip.trim().toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s;
  if (!/^[0-9a-f:.]{2,45}$/.test(s) || !s.includes(":")) return null;
  const [head = "", tail] = s.split("::");
  const left = head === "" ? [] : head.split(":");
  const right = tail === undefined || tail === "" ? [] : tail.split(":");
  const groups = tail === undefined ? left : [...left, ...Array<string>(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right];
  if (groups.length < 4) return null;
  return groups
    .slice(0, 4)
    .map((g) => g.replace(/^0+(?=.)/, ""))
    .join(":");
}

/**
 * A caller's proof that an APNs token is its own, as the limiter sees it (HMACs only):
 * a challenge to use up, or a credential that must still be outstanding for that token.
 */
export type ProofKeys = { spentKey: string; pendingKey: string; expMs: number } | { credentialKey: string };

export interface Admitting {
  proof: ProofKeys;
  /** HMACs of the proven APNs token (outstanding credentials; revoke-all) and of the new registration id. */
  liveKey: string;
  cutoffKey: string;
  credentialKey: string;
  mintKey: string;
  /** Lifetime of the credential, seconds. */
  ttlS: number;
  limits: Limits;
}

/** `issued`: the moment the credential counts as minted — the limiter's clock, which is also what revoke-all cuts by. */
export type Admission = { ok: true; issued: number; evicted: number } | { ok: false; forbidden: true } | { ok: false; retryAfterS: number };
export type ChallengeDecision = { ok: true; send: boolean } | { ok: false; retryAfterS: number } | { ok: false; gone: true };

/**
 * HMAC-SHA256 of the device token under `RATE_KEY_SALT`; the only token-derived value that
 * leaves the request handler. Throws without a usable salt — there is no fallback key, and the
 * Worker answers 503 before it gets here (index.ts).
 */
export async function limiterKey(token: string, salt: string | undefined): Promise<string> {
  if (!hasRateKeySalt(salt)) throw new Error("RATE_KEY_SALT is not set");
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(salt), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(token)));
  return Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Single instance holding a sliding-window log: one row (key hash, kind,
 * timestamp) per wake that was let through AND that APNs did not call dead.
 * Refused wakes write nothing; a wake to a dead token is un-counted again and
 * the token's hash is remembered as dead for DEAD_TTL_MS, so junk tokens cost
 * one APNs round trip each and then nothing.
 *
 * ATOMICITY. Every decision that reads state and then writes it — a budget, a cap, a
 * challenge's single use, a proof and what it authorises — is ONE public method here, whose
 * reads and writes run inside one `transactionSync` with no `await` in between. A Durable
 * Object runs one synchronous stretch at a time, so two requests can never both pass a check
 * that only one of them should; and a throw part-way rolls every write back. The Worker never
 * asks "may I?" in one call and writes in another. The only `await` in these methods is
 * setting the sweep alarm, after the transaction.
 */
export class RateLimiter extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    sql.exec("CREATE TABLE IF NOT EXISTS hits (h TEXT NOT NULL, k INTEGER NOT NULL, ts INTEGER NOT NULL)");
    sql.exec("CREATE INDEX IF NOT EXISTS hits_key ON hits (h, k, ts)");
    sql.exec("CREATE INDEX IF NOT EXISTS hits_ts ON hits (ts)");
    sql.exec("CREATE TABLE IF NOT EXISTS dead (h TEXT PRIMARY KEY, until INTEGER NOT NULL)");
    // Revoked registrations (HMAC of the registration id), kept until the credential would
    // have expired anyway; and one row per credential minted (HMAC of the APNs token), kept a day.
    sql.exec("CREATE TABLE IF NOT EXISTS revoked (h TEXT PRIMARY KEY, until INTEGER NOT NULL)");
    sql.exec("CREATE TABLE IF NOT EXISTS mints (h TEXT NOT NULL, ts INTEGER NOT NULL)");
    sql.exec("CREATE INDEX IF NOT EXISTS mints_key ON mints (h, ts)");
    // The per-device ceiling: one row per accepted wake, keyed by the HMAC of the token it went to.
    sql.exec("CREATE TABLE IF NOT EXISTS dest (h TEXT NOT NULL, k INTEGER NOT NULL, ts INTEGER NOT NULL)");
    sql.exec("CREATE INDEX IF NOT EXISTS dest_key ON dest (h, k, ts)");
    // Used registration challenges (HMAC of the nonce), until they would have expired.
    sql.exec("CREATE TABLE IF NOT EXISTS spent (h TEXT PRIMARY KEY, until INTEGER NOT NULL)");
    // `/v1/revoke-all`: credentials for this APNs token (HMAC) minted at or before `before` are gone.
    sql.exec("CREATE TABLE IF NOT EXISTS cutoff (h TEXT PRIMARY KEY, before INTEGER NOT NULL, until INTEGER NOT NULL)");
    // Outstanding credentials: (HMAC of APNs token, HMAC of registration id, minted, expiry).
    sql.exec("CREATE TABLE IF NOT EXISTS live (t TEXT NOT NULL, c TEXT PRIMARY KEY, issued INTEGER NOT NULL, until INTEGER NOT NULL)");
    sql.exec("CREATE INDEX IF NOT EXISTS live_token ON live (t, issued)");
    // A challenge that was pushed and not used yet (HMAC of the token), until it expires.
    sql.exec("CREATE TABLE IF NOT EXISTS pending (h TEXT PRIMARY KEY, until INTEGER NOT NULL)");
    // An earlier build paired VoIP tokens with APNs tokens here. Nothing is keyed on a VoIP
    // token any more except its ring budget.
    sql.exec("DROP TABLE IF EXISTS bind");
    // The per-caller limit: (HMAC of route class + source address, timestamp), kept one minute.
    sql.exec("CREATE TABLE IF NOT EXISTS source (h TEXT NOT NULL, ts INTEGER NOT NULL)");
    sql.exec("CREATE INDEX IF NOT EXISTS source_key ON source (h, ts)");
  }

  /**
   * The per-caller limit, checked before anything else about a request: has this source (an
   * HMAC — the address never gets here) made `max` requests in the last minute? If not, this
   * one is counted. One step, like every other decision here. Refused requests are not counted.
   */
  async sourceTake(sourceKey: string, max: number, nowMs: number = Date.now()): Promise<{ ok: true } | { ok: false; retryAfterS: number }> {
    const decision = this.ctx.storage.transactionSync((): { ok: true } | { ok: false; retryAfterS: number } => {
      const sql = this.ctx.storage.sql;
      const row = sql
        .exec<{ n: number; oldest: number | null }>("SELECT count(*) AS n, min(ts) AS oldest FROM source WHERE h = ? AND ts > ?", sourceKey, nowMs - MINUTE_MS)
        .one();
      if (row.n >= max && row.oldest !== null) return { ok: false, retryAfterS: Math.max(1, Math.ceil((row.oldest + MINUTE_MS - nowMs) / 1000)) };
      sql.exec("INSERT INTO source (h, ts) VALUES (?, ?)", sourceKey, nowMs);
      return { ok: true };
    });
    if (decision.ok) await this.schedule(SWEEP_INTERVAL_MS);
    return decision;
  }

  private async schedule(delayMs: number): Promise<void> {
    const at = Date.now() + delayMs;
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) await this.ctx.storage.setAlarm(at);
  }

  /** One wake: every refusal check and, if none refuses, the rows that count it. */
  async take(keyHash: string, kind: Kind, limits: Limits, nowMs: number = Date.now(), options: TakeOptions = {}): Promise<Decision> {
    const decision = this.ctx.storage.transactionSync(() => this.takeSync(keyHash, kind, limits, nowMs, options));
    if (decision.ok) await this.schedule(SWEEP_INTERVAL_MS);
    return decision;
  }

  private takeSync(keyHash: string, kind: Kind, limits: Limits, nowMs: number, options: TakeOptions): Decision {
    const sql = this.ctx.storage.sql;
    const k = kind === "call" ? 1 : 0;
    if (
      options.revocable &&
      sql.exec<{ n: number }>("SELECT count(*) AS n FROM revoked WHERE h = ? AND until > ?", keyHash, nowMs).one().n > 0
    ) {
      return { ok: false, gone: true };
    }
    if (
      options.issuedMs !== undefined &&
      options.cutoffKey !== undefined &&
      sql.exec<{ n: number }>("SELECT count(*) AS n FROM cutoff WHERE h = ? AND before >= ?", options.cutoffKey, options.issuedMs).one().n > 0
    ) {
      return { ok: false, gone: true };
    }
    const deadKey = options.deadKey ?? keyHash;
    if (sql.exec<{ n: number }>("SELECT count(*) AS n FROM dead WHERE h = ? AND until > ?", deadKey, nowMs).one().n > 0) {
      return { ok: false, gone: true };
    }
    const rules: Rule[] =
      kind === "call"
        ? [[MINUTE_MS, limits.callPerMinute]]
        : [
            [limits.messageBurstWindowS * 1000, limits.messageBurst],
            [10 * MINUTE_MS, limits.messagePerTenMinutes],
            [HOUR_MS, limits.messagePerHour],
          ];

    let waitMs = 0;
    const check = (windowMs: number, max: number, row: { n: number; oldest: number | null }) => {
      if (row.n >= max && row.oldest !== null) waitMs = Math.max(waitMs, row.oldest + windowMs - nowMs);
    };
    for (const [windowMs, max] of rules) {
      check(
        windowMs,
        max,
        sql
          .exec<{ n: number; oldest: number | null }>(
            "SELECT count(*) AS n, min(ts) AS oldest FROM hits WHERE h = ? AND k = ? AND ts > ?",
            keyHash,
            k,
            nowMs - windowMs,
          )
          .one(),
      );
    }
    if (options.destKey !== undefined) {
      const destRules: Rule[] =
        kind === "call"
          ? [
              [MINUTE_MS, limits.destCallPerMinute],
              [HOUR_MS, limits.destCallPerHour],
            ]
          : rules.map(([w, max]) => [w, max * limits.destMessageFactor]);
      for (const [windowMs, max] of destRules) {
        check(
          windowMs,
          max,
          sql
            .exec<{ n: number; oldest: number | null }>(
              "SELECT count(*) AS n, min(ts) AS oldest FROM dest WHERE h = ? AND k = ? AND ts > ?",
              options.destKey,
              k,
              nowMs - windowMs,
            )
            .one(),
        );
      }
    }
    // Optional, off by default: a hard cap shared by unauthenticated callers is
    // something any one of them can exhaust for everybody.
    if (limits.globalPerMinute > 0) {
      check(
        MINUTE_MS,
        limits.globalPerMinute,
        sql
          .exec<{ n: number; oldest: number | null }>(
            "SELECT count(*) AS n, min(ts) AS oldest FROM hits WHERE ts > ?",
            nowMs - MINUTE_MS,
          )
          .one(),
      );
    }
    if (waitMs > 0) return { ok: false, retryAfterS: Math.max(1, Math.ceil(waitMs / 1000)) };

    sql.exec("INSERT INTO hits (h, k, ts) VALUES (?, ?, ?)", keyHash, k, nowMs);
    if (options.destKey !== undefined) sql.exec("INSERT INTO dest (h, k, ts) VALUES (?, ?, ?)", options.destKey, k, nowMs);
    return { ok: true, ts: nowMs };
  }

  // ---- synchronous pieces; each is called only from inside a `transactionSync` ----

  /** How long until `key` is under every one of `rules` again (rows in `mints`); 0 if it is now. */
  private overMs(key: string, rules: Rule[], nowMs: number): number {
    let waitMs = 0;
    for (const [windowMs, max] of rules) {
      const row = this.ctx.storage.sql
        .exec<{ n: number; oldest: number | null }>("SELECT count(*) AS n, min(ts) AS oldest FROM mints WHERE h = ? AND ts > ?", key, nowMs - windowMs)
        .one();
      if (row.n >= max && row.oldest !== null) waitMs = Math.max(waitMs, row.oldest + windowMs - nowMs);
    }
    return waitMs;
  }

  /** Is the proof good right now? Reads only. */
  private proofGood(proof: ProofKeys, liveKey: string, nowMs: number): boolean {
    const sql = this.ctx.storage.sql;
    if ("spentKey" in proof) {
      return proof.expMs > nowMs && sql.exec<{ n: number }>("SELECT count(*) AS n FROM spent WHERE h = ? AND until > ?", proof.spentKey, nowMs).one().n === 0;
    }
    // A revoke token: its credential must still be outstanding for this very APNs token.
    return sql.exec<{ n: number }>("SELECT count(*) AS n FROM live WHERE c = ? AND t = ? AND until > ?", proof.credentialKey, liveKey, nowMs).one().n > 0;
  }

  /** Use a good proof: a challenge is spent (and its token may ask for another); a revoke token is not consumed. */
  private useProof(proof: ProofKeys): void {
    if (!("spentKey" in proof)) return;
    const sql = this.ctx.storage.sql;
    sql.exec("INSERT INTO spent (h, until) VALUES (?, ?) ON CONFLICT (h) DO UPDATE SET until = excluded.until", proof.spentKey, proof.expMs);
    sql.exec("DELETE FROM pending WHERE h = ?", proof.pendingKey);
  }

  /**
   * `/v1/challenge`, before the push: is one already outstanding (then send nothing), is the
   * token within its allowance (else refuse) — and if a push is due, count it and mark it
   * outstanding, all at once. Concurrent requests for one token therefore produce one push.
   * If APNs then does not accept it, `challengeFailed` takes the mark back.
   * `deadKey` (HMAC of the token): a token APNs called dead in the last DEAD_TTL_MS is refused
   * ("gone") without another request to Apple — the same mark a wake to it leaves and obeys.
   */
  async challengeBegin(pendingKey: string, challengeKey: string, limits: Limits, untilMs: number, deadKey?: string): Promise<ChallengeDecision> {
    const decision = this.ctx.storage.transactionSync((): ChallengeDecision => {
      const sql = this.ctx.storage.sql;
      const nowMs = Date.now();
      if (deadKey !== undefined && sql.exec<{ n: number }>("SELECT count(*) AS n FROM dead WHERE h = ? AND until > ?", deadKey, nowMs).one().n > 0) {
        return { ok: false, gone: true };
      }
      if (sql.exec<{ n: number }>("SELECT count(*) AS n FROM pending WHERE h = ? AND until > ?", pendingKey, nowMs).one().n > 0) {
        return { ok: true, send: false };
      }
      const waitMs = this.overMs(
        challengeKey,
        [
          [10 * MINUTE_MS, limits.challengePerTenMinutes],
          [DAY_MS, limits.challengePerDay],
        ],
        nowMs,
      );
      if (waitMs > 0) return { ok: false, retryAfterS: Math.max(1, Math.ceil(waitMs / 1000)) };
      sql.exec("INSERT INTO mints (h, ts) VALUES (?, ?)", challengeKey, nowMs);
      sql.exec("INSERT INTO pending (h, until) VALUES (?, ?) ON CONFLICT (h) DO UPDATE SET until = excluded.until", pendingKey, untilMs);
      return { ok: true, send: true };
    });
    if (decision.ok && decision.send) await this.schedule(SLOW_SWEEP_INTERVAL_MS);
    return decision;
  }

  /**
   * The challenge marked outstanding by `challengeBegin` (same `untilMs`) never reached APNs.
   * With `deadKey`: because APNs called the token dead — it is remembered as dead for a while.
   */
  async challengeFailed(pendingKey: string, untilMs: number, deadKey?: string): Promise<void> {
    this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      sql.exec("DELETE FROM pending WHERE h = ? AND until = ?", pendingKey, untilMs);
      if (deadKey !== undefined) {
        sql.exec("INSERT INTO dead (h, until) VALUES (?, ?) ON CONFLICT (h) DO UPDATE SET until = excluded.until", deadKey, Date.now() + DEAD_TTL_MS);
      }
    });
    if (deadKey !== undefined) await this.schedule(SWEEP_INTERVAL_MS);
  }

  /**
   * `/v1/register`, everything that decides and records it: the proof (and its single use), the
   * per-token mint cap, the new credential entering `live`, and the eviction of the oldest
   * beyond the cap. Refused → nothing was written (a challenge refused for the cap is still good).
   */
  async register(r: Admitting): Promise<Admission> {
    const result = this.ctx.storage.transactionSync((): Admission => {
      const sql = this.ctx.storage.sql;
      const nowMs = Date.now();
      sql.exec("DELETE FROM live WHERE until <= ?", nowMs);
      if (!this.proofGood(r.proof, r.liveKey, nowMs)) return { ok: false, forbidden: true };
      const waitMs = this.overMs(r.mintKey, [[DAY_MS, r.limits.registerPerDay]], nowMs);
      if (waitMs > 0) return { ok: false, retryAfterS: Math.max(1, Math.ceil(waitMs / 1000)) };

      // Strictly after any revoke-all already recorded for this token, even within one
      // millisecond: "minted after" must never be read as "minted before".
      const cut = sql.exec<{ before: number }>("SELECT before FROM cutoff WHERE h = ?", r.cutoffKey).toArray()[0];
      const issued = cut === undefined ? nowMs : Math.max(nowMs, cut.before + 1);
      const untilMs = (Math.floor(issued / 1000) + r.ttlS) * 1000;

      this.useProof(r.proof);
      sql.exec("INSERT INTO mints (h, ts) VALUES (?, ?)", r.mintKey, nowMs);
      sql.exec("INSERT INTO live (t, c, issued, until) VALUES (?, ?, ?, ?)", r.liveKey, r.credentialKey, issued, untilMs);
      const all = sql.exec<{ c: string; until: number }>("SELECT c, until FROM live WHERE t = ? ORDER BY issued DESC, rowid DESC", r.liveKey).toArray();
      const evicted = all.slice(r.limits.liveCredentials);
      for (const old of evicted) {
        sql.exec("INSERT INTO revoked (h, until) VALUES (?, ?) ON CONFLICT (h) DO UPDATE SET until = excluded.until", old.c, old.until);
        sql.exec("DELETE FROM live WHERE c = ?", old.c);
        sql.exec("DELETE FROM hits WHERE h = ?", old.c);
      }
      return { ok: true, issued, evicted: evicted.length };
    });
    if (result.ok) await this.schedule(SLOW_SWEEP_INTERVAL_MS);
    return result;
  }

  /**
   * `/v1/revoke-all`: the proof and the cut in one step. Every credential minted under the
   * proven APNs token up to now is gone — both halves of it, the alert and the ring — and
   * nothing else is: no row is keyed on a VoIP token, so a credential minted under another
   * APNs token that names the same VoIP token is not touched. False: the proof was not good.
   */
  async revokeAll(proof: ProofKeys, liveKey: string, cutoffKey: string, keepMs: number): Promise<boolean> {
    const done = this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      const nowMs = Date.now();
      if (!this.proofGood(proof, liveKey, nowMs)) return false;
      this.useProof(proof);
      // The cut covers everything outstanding, whatever the clock says: a credential admitted
      // just after an earlier revoke-all is stamped past it (see `register`), possibly past now.
      const newest = sql.exec<{ at: number | null }>("SELECT max(issued) AS at FROM live WHERE t = ?", liveKey).one().at;
      sql.exec(
        "INSERT INTO cutoff (h, before, until) VALUES (?, ?, ?) ON CONFLICT (h) DO UPDATE SET before = max(cutoff.before, excluded.before), until = excluded.until",
        cutoffKey,
        Math.max(nowMs, newest ?? 0),
        nowMs + keepMs,
      );
      // None is outstanding any more — so none of their revoke tokens is proof any more.
      sql.exec("DELETE FROM live WHERE t = ?", liveKey);
      return true;
    });
    if (done) await this.schedule(SLOW_SWEEP_INTERVAL_MS);
    return done;
  }

  /** The device revoked a registration: its credential answers "gone" until it would have expired. */
  async revoke(credentialKey: string, untilMs: number): Promise<void> {
    this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      sql.exec("INSERT INTO revoked (h, until) VALUES (?, ?) ON CONFLICT (h) DO UPDATE SET until = excluded.until", credentialKey, untilMs);
      sql.exec("DELETE FROM hits WHERE h = ?", credentialKey);
      sql.exec("DELETE FROM live WHERE c = ?", credentialKey);
    });
    await this.schedule(SLOW_SWEEP_INTERVAL_MS);
  }

  /** APNs said this token is dead: take the wake back out of the counters and remember the hash briefly. */
  async markDead(keyHash: string, kind: Kind, ts: number, nowMs: number = Date.now(), deadKey: string = keyHash, destKey?: string): Promise<void> {
    this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      sql.exec("DELETE FROM hits WHERE h = ? AND k = ? AND ts = ?", keyHash, kind === "call" ? 1 : 0, ts);
      if (destKey !== undefined) sql.exec("DELETE FROM dest WHERE h = ? AND k = ? AND ts = ?", destKey, kind === "call" ? 1 : 0, ts);
      sql.exec("INSERT INTO dead (h, until) VALUES (?, ?) ON CONFLICT (h) DO UPDATE SET until = excluded.until", deadKey, nowMs + DEAD_TTL_MS);
    });
    await this.schedule(SWEEP_INTERVAL_MS);
  }

  override async alarm(): Promise<void> {
    const sql = this.ctx.storage.sql;
    sql.exec("DELETE FROM hits WHERE ts <= ?", Date.now() - RETENTION_MS);
    sql.exec("DELETE FROM dead WHERE until <= ?", Date.now());
    sql.exec("DELETE FROM revoked WHERE until <= ?", Date.now());
    sql.exec("DELETE FROM mints WHERE ts <= ?", Date.now() - DAY_MS);
    sql.exec("DELETE FROM dest WHERE ts <= ?", Date.now() - RETENTION_MS);
    sql.exec("DELETE FROM spent WHERE until <= ?", Date.now());
    sql.exec("DELETE FROM cutoff WHERE until <= ?", Date.now());
    sql.exec("DELETE FROM live WHERE until <= ?", Date.now());
    sql.exec("DELETE FROM pending WHERE until <= ?", Date.now());
    sql.exec("DELETE FROM source WHERE ts <= ?", Date.now() - MINUTE_MS);
    const { n } = sql
      .exec<{ n: number }>("SELECT (SELECT count(*) FROM hits) + (SELECT count(*) FROM dead) + (SELECT count(*) FROM dest) + (SELECT count(*) FROM source) AS n")
      .one();
    const { slow } = sql
      .exec<{ slow: number }>(
        "SELECT (SELECT count(*) FROM revoked) + (SELECT count(*) FROM mints) + (SELECT count(*) FROM spent) + (SELECT count(*) FROM cutoff) + (SELECT count(*) FROM live) + (SELECT count(*) FROM pending) AS slow",
      )
      .one();
    if (n > 0) await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
    else if (slow > 0) await this.ctx.storage.setAlarm(Date.now() + SLOW_SWEEP_INTERVAL_MS);
  }
}
