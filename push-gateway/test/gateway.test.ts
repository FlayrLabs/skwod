import { reset, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env as baseEnv } from "cloudflare:workers";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CALL_PAYLOAD, JWT_TTL_MS, MESSAGE_PAYLOAD, providerJwt } from "../src/apns";
import type { Env } from "../src/env";
import worker from "../src/index";
import wranglerToml from "../wrangler.toml?raw";
import { CHALLENGE_TTL_MS, mint as mintCredential, mintChallenge } from "../src/creds";
import { DEFAULT_LIMITS, credentialKeyInput, cutoffKeyInput, destKeyInput, deviceKeyInput, limiterKey, liveKeyInput, mintKeyInput, sourceKeyInput, sourceOf } from "../src/ratelimit";

const TOPIC = "com.example.skwod";
const KEY_ID = "TESTKEYID1";
const TEAM_ID = "TESTTEAM01";
const SALT = "test-rate-key-salt-0123456789abcdef";
const PROD = "http://apns.test";
const SANDBOX = "http://sandbox.apns.test";

let pem: string;
let publicKey: CryptoKey;

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}
let seen: Seen[];
let respond: (req: Seen) => Response;

const apnsError = (status: number, reason: string) => () => Response.json({ reason }, { status });

const hexOf = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const b64urlEncode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function randomToken(bytes = 32): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
}

function testEnv(overrides: Partial<Env> = {}): Env {
  return {
    RATE_LIMITER: baseEnv.RATE_LIMITER,
    ALLOWED_TOPICS: TOPIC,
    RATE_KEY_SALT: SALT,
    APNS_KEY_P8: pem,
    APNS_KEY_ID: KEY_ID,
    APNS_TEAM_ID: TEAM_ID,
    APNS_HOST: PROD,
    APNS_SANDBOX_HOST: SANDBOX,
    ...overrides,
  };
}

function wakeRequest(body: unknown, init: RequestInit = {}): Request {
  return new Request("https://gateway.test/v1/wake", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
    ...init,
  });
}

const wake = (body: unknown, overrides: Partial<Env> = {}) => worker.fetch(wakeRequest(body), testEnv(overrides));

const limiterStub = () => baseEnv.RATE_LIMITER.get(baseEnv.RATE_LIMITER.idFromName("global"));

const storedRows = () =>
  runInDurableObject(limiterStub(), (_instance, state) =>
    state.storage.sql.exec<{ h: string; k: number; ts: number }>("SELECT * FROM hits").toArray(),
  );

beforeAll(async () => {
  // Generated per run; no private key is ever committed.
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  publicKey = pair.publicKey;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const b64 = btoa(String.fromCharCode(...der));
  pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
});

beforeEach(async () => {
  await reset();
  seen = [];
  respond = () => new Response(null, { status: 200 });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = new Request(input, init);
      const record: Seen = {
        url: req.url,
        method: req.method,
        headers: Object.fromEntries(req.headers),
        body: await req.text(),
      };
      seen.push(record);
      return respond(record);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("routing and validation", () => {
  const good = () => ({ token: randomToken(), kind: "message", topic: TOPIC });

  it("serves /health with nothing but a status", async () => {
    const res = await worker.fetch(new Request("https://gateway.test/health"), testEnv());
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('{"status":"ok"}');
  });

  it.each([
    ["GET /v1/wake", new Request("https://gateway.test/v1/wake"), 405],
    ["PUT /v1/wake", new Request("https://gateway.test/v1/wake", { method: "PUT", body: "{}" }), 405],
    ["OPTIONS /v1/wake", new Request("https://gateway.test/v1/wake", { method: "OPTIONS" }), 405],
    ["OPTIONS /", new Request("https://gateway.test/", { method: "OPTIONS" }), 405],
    ["POST /health", new Request("https://gateway.test/health", { method: "POST" }), 405],
    ["POST /", new Request("https://gateway.test/", { method: "POST" }), 404],
    ["POST /v1/wake/", new Request("https://gateway.test/v1/wake/", { method: "POST" }), 404],
    ["POST /v1/wakeup", new Request("https://gateway.test/v1/wakeup", { method: "POST" }), 404],
  ])("%s -> %i", async (_name, request, status) => {
    const res = await worker.fetch(request, testEnv());
    expect(res.status).toBe(status);
    expect(seen).toHaveLength(0);
  });

  it("never sends CORS headers", async () => {
    const preflight = await worker.fetch(
      new Request("https://gateway.test/v1/wake", {
        method: "OPTIONS",
        headers: { origin: "https://evil.example", "access-control-request-method": "POST" },
      }),
      testEnv(),
    );
    const ok = await worker.fetch(
      wakeRequest(good(), { headers: { "content-type": "application/json", origin: "https://evil.example" } }),
      testEnv(),
    );
    expect(ok.status).toBe(202);
    for (const res of [preflight, ok]) {
      expect([...res.headers.keys()].filter((h) => h.startsWith("access-control-"))).toEqual([]);
    }
  });

  it.each([
    ["missing content-type", { headers: {} }, 415],
    ["text/plain", { headers: { "content-type": "text/plain" } }, 415],
    ["form", { headers: { "content-type": "application/x-www-form-urlencoded" } }, 415],
  ])("content-type: %s -> %i", async (_name, init, status) => {
    const res = await worker.fetch(wakeRequest(good(), init), testEnv());
    expect(res.status).toBe(status);
    expect(seen).toHaveLength(0);
  });

  it("accepts application/json with a charset parameter", async () => {
    const res = await worker.fetch(
      wakeRequest(good(), { headers: { "content-type": "Application/JSON; charset=utf-8" } }),
      testEnv(),
    );
    expect(res.status).toBe(202);
  });

  it("rejects a declared content-length over 2 KB", async () => {
    const res = await worker.fetch(
      wakeRequest(good(), { headers: { "content-type": "application/json", "content-length": "2049" } }),
      testEnv(),
    );
    expect(res.status).toBe(413);
    expect(seen).toHaveLength(0);
  });

  it("rejects a streamed body over 2 KB that declares no content-length", async () => {
    const chunk = new TextEncoder().encode(" ".repeat(1100));
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk);
        controller.enqueue(chunk);
        controller.close();
      },
    });
    const request = new Request("https://gateway.test/v1/wake", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(request.headers.get("content-length")).toBeNull();
    const res = await worker.fetch(request, testEnv());
    expect(res.status).toBe(413);
    expect(seen).toHaveLength(0);
  });

  it("rejects a body over 2 KB whose content-length lies", async () => {
    const padded = JSON.stringify(good()) + " ".repeat(2100);
    const res = await worker.fetch(
      wakeRequest(padded, { headers: { "content-type": "application/json", "content-length": "10" } }),
      testEnv(),
    );
    expect(res.status).toBe(413);
    expect(seen).toHaveLength(0);
  });

  const t = randomToken();
  it.each<[string, unknown]>([
    ["not JSON", "{nope"],
    ["empty body", ""],
    ["array", JSON.stringify([t, "message", TOPIC])],
    ["null", "null"],
    ["string", '"hello"'],
    ["unknown key", { token: t, kind: "message", topic: TOPIC, sender: "alice" }],
    ["missing token", { kind: "message", topic: TOPIC }],
    ["missing kind", { token: t, topic: TOPIC }],
    ["missing topic", { token: t, kind: "message" }],
    ["token not a string", { token: 12345, kind: "message", topic: TOPIC }],
    ["token not hex", { token: "g".repeat(64), kind: "message", topic: TOPIC }],
    ["token too short", { token: "ab".repeat(31), kind: "message", topic: TOPIC }],
    ["token odd length", { token: "a".repeat(65), kind: "message", topic: TOPIC }],
    ["token too long", { token: "ab".repeat(101), kind: "message", topic: TOPIC }],
    ["token with path chars", { token: `${"ab".repeat(31)}/../`, kind: "message", topic: TOPIC }],
    ["token with trailing newline", { token: `${"ab".repeat(32)}\n`, kind: "message", topic: TOPIC }],
    ["bad kind", { token: t, kind: "background", topic: TOPIC }],
    ["kind wrong case", { token: t, kind: "Message", topic: TOPIC }],
    ["kind not a string", { token: t, kind: 1, topic: TOPIC }],
    ["topic empty", { token: t, kind: "message", topic: "" }],
    ["topic leading dot", { token: t, kind: "message", topic: ".com.example.skwod" }],
    ["topic with space", { token: t, kind: "message", topic: "com.example skwod" }],
    ["topic with newline", { token: t, kind: "message", topic: "com.example.skwod\nx-evil: 1" }],
    ["topic too long", { token: t, kind: "message", topic: "a".repeat(156) }],
    ["topic not a string", { token: t, kind: "message", topic: [TOPIC] }],
  ])("400: %s", async (_name, body) => {
    const res = await wake(body);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ ok: false, error: "bad_request" });
    expect(seen).toHaveLength(0);
  });

  it("accepts the longest and shortest valid tokens and lower-cases them", async () => {
    const short = randomToken(32).toUpperCase();
    const long = randomToken(100).toUpperCase();
    expect((await wake({ token: short, kind: "message", topic: TOPIC })).status).toBe(202);
    expect((await wake({ token: long, kind: "message", topic: TOPIC })).status).toBe(202);
    expect(seen.map((s) => s.url)).toEqual([
      `${PROD}/3/device/${short.toLowerCase()}`,
      `${PROD}/3/device/${long.toLowerCase()}`,
    ]);
  });

  it("403 for a topic that is not allowlisted", async () => {
    const res = await wake({ token: randomToken(), kind: "message", topic: "com.attacker.app" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ ok: false, error: "forbidden" });
    expect(seen).toHaveLength(0);
  });

  it("403 for the .voip form of an allowlisted topic (only base bundle ids are accepted)", async () => {
    const res = await wake({ token: randomToken(), kind: "call", topic: `${TOPIC}.voip` });
    expect(res.status).toBe(403);
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["only separators", " , ,"],
  ])("fails closed when the allowlist is %s", async (_name, allow) => {
    const res = await wake(good(), { ALLOWED_TOPICS: allow });
    expect(res.status).toBe(403);
    expect(seen).toHaveLength(0);
  });

  it("supports several allowlisted topics with whitespace", async () => {
    const res = await wake(
      { token: randomToken(), kind: "message", topic: "io.other.app" },
      { ALLOWED_TOPICS: "com.example.skwod, io.other.app" },
    );
    expect(res.status).toBe(202);
  });

  it("503 unavailable (and no APNs call, no limiter row) when a secret is missing", async () => {
    const res = await wake(good(), { APNS_KEY_ID: undefined });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ ok: false, error: "unavailable" });
    expect(seen).toHaveLength(0);
    expect(await storedRows()).toEqual([]);
  });
});

describe("APNs request", () => {
  async function verifyJwt(authorization: string | undefined) {
    expect(authorization).toMatch(/^bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    const [h, c, s] = authorization!.slice("bearer ".length).split(".") as [string, string, string];
    const dec = new TextDecoder();
    expect(JSON.parse(dec.decode(b64urlDecode(h)))).toEqual({ alg: "ES256", kid: KEY_ID });
    const claims = JSON.parse(dec.decode(b64urlDecode(c))) as { iss: string; iat: number };
    expect(Object.keys(claims).sort()).toEqual(["iat", "iss"]);
    expect(claims.iss).toBe(TEAM_ID);
    const now = Math.floor(Date.now() / 1000);
    expect(claims.iat).toBeLessThanOrEqual(now);
    expect(claims.iat).toBeGreaterThan(now - 120);
    const sig = b64urlDecode(s);
    expect(sig.byteLength).toBe(64);
    expect(
      await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, sig, new TextEncoder().encode(`${h}.${c}`)),
    ).toBe(true);
  }

  it("message -> alert push with the exact shape", async () => {
    const token = randomToken();
    const before = Math.floor(Date.now() / 1000);
    const res = await wake({ token, kind: "message", topic: TOPIC });
    const after = Math.floor(Date.now() / 1000);
    expect(res.status).toBe(202);
    expect(await res.text()).toBe('{"ok":true}');

    expect(seen).toHaveLength(1);
    const req = seen[0]!;
    expect(req.url).toBe(`${PROD}/3/device/${token}`);
    expect(req.method).toBe("POST");
    expect(Object.keys(req.headers).sort()).toEqual([
      "apns-expiration",
      "apns-priority",
      "apns-push-type",
      "apns-topic",
      "authorization",
      "content-type",
    ]);
    expect(req.headers["apns-push-type"]).toBe("alert");
    expect(req.headers["apns-topic"]).toBe(TOPIC);
    expect(req.headers["apns-priority"]).toBe("10");
    expect(req.headers["content-type"]).toBe("application/json");
    const expiration = Number(req.headers["apns-expiration"]);
    expect(expiration).toBeGreaterThanOrEqual(before + 3600);
    expect(expiration).toBeLessThanOrEqual(after + 3600);
    expect(req.body).toBe('{"aps":{"alert":{"body":"New message"},"sound":"default","mutable-content":1}}');
    expect(req.body).toBe(MESSAGE_PAYLOAD);
    await verifyJwt(req.headers["authorization"]);
  });

  it("passes the device's own tag through, and nothing else", async () => {
    const token = randomToken();
    const tag = "Zk3_device-chosen-tag";
    expect((await wake({ token, kind: "call", topic: TOPIC, tag })).status).toBe(202);
    expect(seen[0]!.body).toBe(`{"aps":{},"kind":"call","tag":"${tag}"}`);
    seen.length = 0;
    expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC, tag })).status).toBe(202);
    expect(seen[0]!.body).toBe(`{"aps":{"alert":{"body":"New message"},"sound":"default","mutable-content":1},"tag":"${tag}"}`);
    expect(JSON.parse(seen[0]!.body)).toEqual({ aps: { alert: { body: "New message" }, sound: "default", "mutable-content": 1 }, tag });
    seen.length = 0;
    // Not a message channel: too short, too long, or anything outside the alphabet is refused,
    // and so is any other extra key.
    for (const bad of ["short", "x".repeat(33), "has spaces and words in", 'quote"injection-attempt', "ünïcödé-tag-value-here", 42, null]) {
      expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC, tag: bad })).status).toBe(400);
    }
    expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC, note: "Zk3_device-chosen-tag" })).status).toBe(400);
    expect(seen).toHaveLength(0);
  });

  it("call -> VoIP push with the exact shape", async () => {
    const token = randomToken();
    const res = await wake({ token, kind: "call", topic: TOPIC });
    expect(res.status).toBe(202);
    expect(await res.text()).toBe('{"ok":true}');

    expect(seen).toHaveLength(1);
    const req = seen[0]!;
    expect(req.url).toBe(`${PROD}/3/device/${token}`);
    expect(req.method).toBe("POST");
    const { authorization, ...rest } = req.headers;
    expect(rest).toEqual({
      "apns-push-type": "voip",
      "apns-topic": `${TOPIC}.voip`,
      "apns-priority": "10",
      "apns-expiration": "0",
      "content-type": "application/json",
    });
    expect(req.body).toBe('{"aps":{},"kind":"call"}');
    expect(req.body).toBe(CALL_PAYLOAD);
    await verifyJwt(authorization);
  });

  it("accepts the .p8 with \\n-escaped newlines", async () => {
    const res = await wake(
      { token: randomToken(), kind: "message", topic: TOPIC },
      { APNS_KEY_P8: pem.trim().replace(/\n/g, "\\n") },
    );
    expect(res.status).toBe(202);
    await verifyJwt(seen[0]!.headers["authorization"]);
  });

  it("reuses the provider JWT across wakes", async () => {
    await wake({ token: randomToken(), kind: "message", topic: TOPIC });
    await wake({ token: randomToken(), kind: "call", topic: TOPIC });
    expect(seen).toHaveLength(2);
    expect(seen[0]!.headers["authorization"]).toBe(seen[1]!.headers["authorization"]);
  });

  it("re-mints the provider JWT once it is 45 minutes old", async () => {
    const e = testEnv();
    const t0 = Date.now() + 10 * JWT_TTL_MS; // fresh cache entry regardless of earlier tests
    const first = await providerJwt(e, t0);
    expect(await providerJwt(e, t0 + JWT_TTL_MS - 1)).toBe(first);
    const second = await providerJwt(e, t0 + JWT_TTL_MS);
    expect(second).not.toBe(first);
    const iat = (jwt: string) => JSON.parse(new TextDecoder().decode(b64urlDecode(jwt.split(".")[1]!))).iat;
    expect(iat(second) - iat(first)).toBe(JWT_TTL_MS / 1000);
    expect(JWT_TTL_MS).toBeGreaterThanOrEqual(40 * 60_000);
    expect(JWT_TTL_MS).toBeLessThanOrEqual(50 * 60_000);
  });

  it("defaults to Apple's hosts when no override is set", async () => {
    respond = apnsError(400, "BadDeviceToken");
    const token = randomToken();
    await wake({ token, kind: "message", topic: TOPIC }, { APNS_HOST: undefined, APNS_SANDBOX_HOST: undefined });
    // fetch is stubbed, so nothing leaves the test process.
    expect(seen.map((s) => s.url)).toEqual([
      `https://api.push.apple.com/3/device/${token}`,
      `https://api.sandbox.push.apple.com/3/device/${token}`,
    ]);
  });
});

describe("APNs response mapping", () => {
  const body = () => ({ token: randomToken(), kind: "message", topic: TOPIC });

  it("retries once on the sandbox host after BadDeviceToken from production", async () => {
    respond = (req) => (req.url.startsWith(PROD) ? apnsError(400, "BadDeviceToken")() : new Response(null, { status: 200 }));
    const b = { token: randomToken(), kind: "call", topic: TOPIC };
    const res = await wake(b);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ ok: true });
    expect(seen.map((s) => s.url)).toEqual([`${PROD}/3/device/${b.token}`, `${SANDBOX}/3/device/${b.token}`]);
    expect(seen[1]!.method).toBe("POST");
    expect(seen[1]!.headers).toEqual(seen[0]!.headers);
    expect(seen[1]!.body).toBe(seen[0]!.body);
  });

  it("410 gone when both hosts say BadDeviceToken", async () => {
    respond = apnsError(400, "BadDeviceToken");
    const res = await wake(body());
    expect(res.status).toBe(410);
    expect(await res.json()).toEqual({ ok: false, error: "gone" });
    expect(seen).toHaveLength(2);
  });

  it("410 gone on Unregistered, without a sandbox retry", async () => {
    respond = apnsError(410, "Unregistered");
    const res = await wake(body());
    expect(res.status).toBe(410);
    expect(await res.json()).toEqual({ ok: false, error: "gone" });
    expect(seen).toHaveLength(1);
  });

  it("410 gone when the sandbox retry says Unregistered", async () => {
    respond = (req) => (req.url.startsWith(PROD) ? apnsError(400, "BadDeviceToken")() : apnsError(410, "Unregistered")());
    expect((await wake(body())).status).toBe(410);
  });

  it.each([
    ["429 TooManyRequests", 429, "TooManyRequests"],
    ["500 InternalServerError", 500, "InternalServerError"],
    ["503 ServiceUnavailable", 503, "ServiceUnavailable"],
    ["403 InvalidProviderToken", 403, "InvalidProviderToken"],
    ["403 ExpiredProviderToken", 403, "ExpiredProviderToken"],
    ["400 BadTopic", 400, "BadTopic"],
    ["400 DeviceTokenNotForTopic", 400, "DeviceTokenNotForTopic"],
  ])("503 upstream on APNs %s, without leaking the reason", async (_name, status, reason) => {
    respond = apnsError(status, reason);
    const res = await wake(body());
    expect(res.status).toBe(503);
    const text = await res.text();
    expect(text).toBe('{"ok":false,"error":"upstream"}');
    expect(text).not.toContain(reason);
    expect(seen).toHaveLength(1);
  });

  it("503 upstream when the sandbox retry fails upstream", async () => {
    respond = (req) => (req.url.startsWith(PROD) ? apnsError(400, "BadDeviceToken")() : apnsError(500, "InternalServerError")());
    expect((await wake(body())).status).toBe(503);
  });

  it("503 upstream when APNs is unreachable or answers garbage", async () => {
    respond = () => {
      throw new TypeError("network down");
    };
    const unreachable = await wake(body());
    expect(unreachable.status).toBe(503);
    expect(await unreachable.json()).toEqual({ ok: false, error: "upstream" });

    respond = () => new Response("<html>bad gateway</html>", { status: 400 });
    expect((await wake(body())).status).toBe(503);
  });

  it("mints a fresh JWT after APNs says ExpiredProviderToken", async () => {
    await wake(body());
    respond = apnsError(403, "ExpiredProviderToken");
    await wake(body());
    respond = () => new Response(null, { status: 200 });
    // iat has one-second resolution; wait so the re-minted token differs.
    await new Promise((r) => setTimeout(r, 1100));
    await wake(body());
    expect(seen[1]!.headers["authorization"]).toBe(seen[0]!.headers["authorization"]);
    expect(seen[2]!.headers["authorization"]).not.toBe(seen[0]!.headers["authorization"]);
  });
});

describe("rate limiting", () => {
  it("limits messages per token and leaves other tokens alone", async () => {
    const a = { token: randomToken(), kind: "message", topic: TOPIC };
    const b = { token: randomToken(), kind: "message", topic: TOPIC };
    expect((await wake(a)).status).toBe(202);

    const limited = await wake(a);
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({ ok: false, error: "rate_limited" });
    const retryAfter = Number(limited.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(DEFAULT_LIMITS.messageBurstWindowS);

    expect((await wake(b)).status).toBe(202);
    expect(seen).toHaveLength(2); // the refused wake never reached APNs
  });

  it("treats upper- and lower-case spellings of a token as the same token", async () => {
    const token = randomToken();
    expect((await wake({ token, kind: "message", topic: TOPIC })).status).toBe(202);
    expect((await wake({ token: token.toUpperCase(), kind: "message", topic: TOPIC })).status).toBe(429);
  });

  it("allows 6 calls a minute per token, independent of the message limit", async () => {
    const token = randomToken();
    expect((await wake({ token, kind: "message", topic: TOPIC })).status).toBe(202);
    for (let i = 0; i < DEFAULT_LIMITS.callPerMinute; i++) {
      expect((await wake({ token, kind: "call", topic: TOPIC })).status).toBe(202);
    }
    const limited = await wake({ token, kind: "call", topic: TOPIC });
    expect(limited.status).toBe(429);
    const retryAfter = Number(limited.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(60);
    expect((await wake({ token: randomToken(), kind: "call", topic: TOPIC })).status).toBe(202);
  });

  it("honours env-configured limits", async () => {
    const token = randomToken();
    const overrides = { RL_MESSAGE_BURST: "3", RL_CALL_PER_MINUTE: "1" };
    for (let i = 0; i < 3; i++) {
      expect((await wake({ token, kind: "message", topic: TOPIC }, overrides)).status).toBe(202);
    }
    expect((await wake({ token, kind: "message", topic: TOPIC }, overrides)).status).toBe(429);
    expect((await wake({ token, kind: "call", topic: TOPIC }, overrides)).status).toBe(202);
    expect((await wake({ token, kind: "call", topic: TOPIC }, overrides)).status).toBe(429);
  });

  it("has no global cap by default: many distinct tokens never block each other", async () => {
    expect(DEFAULT_LIMITS.globalPerMinute).toBe(0);
    for (let i = 0; i < 40; i++) {
      expect((await wake({ token: randomToken(), kind: i % 2 ? "call" : "message", topic: TOPIC })).status).toBe(202);
    }
    expect(seen).toHaveLength(40);
  });

  it("applies the optional global brake only when an operator sets one", async () => {
    const overrides = { RL_GLOBAL_PER_MINUTE: "2" };
    expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC }, overrides)).status).toBe(202);
    expect((await wake({ token: randomToken(), kind: "call", topic: TOPIC }, overrides)).status).toBe(202);
    const limited = await wake({ token: randomToken(), kind: "message", topic: TOPIC }, overrides);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    expect(seen).toHaveLength(2);
    expect(await storedRows()).toHaveLength(2); // refused wakes store nothing
  });

  it("does not count dead tokens, and answers gone from a short negative cache without asking APNs", async () => {
    // Junk tokens cannot fill even an operator-set global brake.
    const overrides = { RL_GLOBAL_PER_MINUTE: "3" };
    respond = apnsError(410, "Unregistered");
    const dead = randomToken();
    for (let i = 0; i < 6; i++) {
      expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC }, overrides)).status).toBe(410);
    }
    expect((await wake({ token: dead, kind: "message", topic: TOPIC }, overrides)).status).toBe(410);
    expect(await storedRows()).toEqual([]); // nothing counted
    const asked = seen.length;
    // Repeats for the dead token: 410 again (also for the other kind), APNs not contacted.
    expect((await wake({ token: dead, kind: "message", topic: TOPIC }, overrides)).status).toBe(410);
    expect((await wake({ token: dead, kind: "call", topic: TOPIC }, overrides)).status).toBe(410);
    expect(seen).toHaveLength(asked);
    // A live token is unaffected.
    respond = () => new Response(null, { status: 200 });
    expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC }, overrides)).status).toBe(202);

    // The mark holds only the HMAC, and expires.
    const marks = await runInDurableObject(limiterStub(), (_i, state) => state.storage.sql.exec("SELECT * FROM dead").toArray());
    expect(marks).toHaveLength(7);
    expect(JSON.stringify(marks)).not.toContain(dead);
    expect(marks.map((m) => m["h"])).toContain(await limiterKey(dead, SALT));
    await runInDurableObject(limiterStub(), (_i, state) => {
      state.storage.sql.exec("UPDATE dead SET until = ?", Date.now() - 1);
    });
    expect((await wake({ token: dead, kind: "message", topic: TOPIC }, overrides)).status).toBe(202);
  });

  it("enforces the hourly message cap and frees it as the window slides", async () => {
    const limiter = limiterStub();
    const limits = { ...DEFAULT_LIMITS, messagePerHour: 3 };
    const t0 = Date.now();
    for (let i = 0; i < 3; i++) {
      expect(await limiter.take("k1", "message", limits, t0 + i * 10_000)).toEqual({ ok: true, ts: t0 + i * 10_000 });
    }
    expect(await limiter.take("k1", "message", limits, t0 + 30_000)).toEqual({ ok: false, retryAfterS: 3570 });
    expect(await limiter.take("k2", "message", limits, t0 + 30_000)).toEqual({ ok: true, ts: t0 + 30_000 });
    expect(await limiter.take("k1", "message", limits, t0 + 3_600_000)).toEqual({ ok: true, ts: t0 + 3_600_000 });
  });

  it("keeps a busy chat waking: the sustained rate never goes dark for long", async () => {
    const limiter = limiterStub();
    const limits = DEFAULT_LIMITS;
    const t0 = Date.now();
    // A server in a lively chat asks for a wake every 22 s for two hours.
    let sent = 0;
    let lastOk = t0;
    let longestGapMs = 0;
    for (let t = t0; t < t0 + 2 * 3_600_000; t += 22_000) {
      const d = await limiter.take("busy", "message", limits, t);
      if (d.ok) {
        longestGapMs = Math.max(longestGapMs, t - lastOk);
        lastOk = t;
        sent++;
      }
    }
    // The old 60-per-hour cap passed 120 of these and was silent for ~35 minutes of each hour.
    expect(longestGapMs).toBeLessThanOrEqual(60_000);
    expect(sent).toBeGreaterThan(300);
    // The per-token limits are still limits: a flood (a request every 5 s, the burst window)
    // is held to the 10-minute and hourly shapes.
    let flood = 0;
    for (let t = t0; t < t0 + 3_600_000; t += 5_000) {
      if ((await limiter.take("flood", "message", limits, t)).ok) flood++;
    }
    expect(flood).toBe(limits.messagePerHour);
    const tenMin = { ...limits, messagePerHour: 10_000 };
    let burst = 0;
    for (let t = t0; t < t0 + 600_000; t += 5_000) {
      if ((await limiter.take("flood10", "message", tenMin, t)).ok) burst++;
    }
    expect(burst).toBe(limits.messagePerTenMinutes);
  }, 60_000);

  it("stores only {hmac, kind, timestamp} and never the token", async () => {
    const OTHER_SALT = "another-rate-key-salt-fedcba9876543210";
    const token = randomToken();
    const salted = randomToken();
    await wake({ token, kind: "message", topic: TOPIC });
    await wake({ token, kind: "call", topic: TOPIC });
    await wake({ token: salted, kind: "message", topic: TOPIC }, { RATE_KEY_SALT: OTHER_SALT });

    const dump = await runInDurableObject(limiterStub(), (_instance, state) => {
      const sql = state.storage.sql;
      return {
        tables: sql
          .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\'")
          .toArray()
          .map((r) => r.name),
        rows: sql.exec("SELECT * FROM hits ORDER BY rowid").toArray(),
      };
    });
    expect(dump.tables.sort()).toEqual(["cutoff", "dead", "dest", "hits", "live", "mints", "pending", "revoked", "source", "spent"]);
    expect(dump.rows).toHaveLength(3);
    for (const row of dump.rows) expect(Object.keys(row).sort()).toEqual(["h", "k", "ts"]);

    const serialized = JSON.stringify(dump);
    for (const secret of [token, salted, TOPIC]) expect(serialized).not.toContain(secret);

    // Independent HMAC-SHA256 computation: key = RATE_KEY_SALT, msg = token.
    const hmac = async (key: string, msg: string) => {
      const enc = new TextEncoder();
      const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
      return Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("");
    };
    const keyed = await hmac(SALT, token);
    expect(dump.rows.map((r) => [r["h"], r["k"]])).toEqual([
      [keyed, 0],
      [keyed, 1],
      [await hmac(OTHER_SALT, salted), 0],
    ]);
    expect(await limiterKey(token, SALT)).toBe(keyed);
    expect(await limiterKey(token, OTHER_SALT)).not.toBe(keyed);
    // No fallback key: the old public constant is gone, and a missing or short salt is an error.
    expect(dump.rows.map((r) => r["h"])).not.toContain(await hmac("skwod-push-gateway/ratelimit/v1", token));
    for (const none of [undefined, "", "pepper"]) await expect(limiterKey(token, none)).rejects.toThrow();
  });

  // Audit C7: RATE_KEY_SALT was optional, and without it every stored row was keyed by a
  // constant printed in this repository.
  it("without RATE_KEY_SALT (or with a short one) every route answers 503 and nothing is stored or sent", async () => {
    const token = randomToken();
    for (const salt of [undefined, "", "short-salt"]) {
      const off = { RATE_KEY_SALT: salt, WAKE_CRED_SECRET: "test-wake-credential-secret-0123456789abcdef" };
      const post = (path: string, body: unknown) =>
        worker.fetch(
          new Request(`https://gateway.test${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
          testEnv(off),
        );
      for (const [path, body] of [
        ["/v1/wake", { token, kind: "message", topic: TOPIC }],
        ["/v1/wake", { credential: `w1.${"A".repeat(60)}`, kind: "call" }],
        ["/v1/challenge", { apns_token: token, topic: TOPIC }],
        ["/v1/register", { apns_token: token, voip_token: null, topic: TOPIC, challenge: `c1.${"A".repeat(75)}` }],
        ["/v1/revoke", { revoke: `r1.${"A".repeat(75)}` }],
        ["/v1/revoke-all", { apns_token: token, topic: TOPIC, revoke: `r1.${"A".repeat(75)}` }],
      ] as const) {
        const res = await post(path, body);
        expect(res.status, `${path} with salt ${JSON.stringify(salt)}`).toBe(503);
        expect(await res.json()).toEqual({ ok: false, error: "unavailable" });
      }
      // Liveness still answers: the operator can tell "deployed, not configured" from "down".
      expect((await worker.fetch(new Request("https://gateway.test/health"), testEnv(off))).status).toBe(200);
    }
    expect(seen).toEqual([]);
    expect(await storedRows()).toEqual([]);
  });

  // Audit A1: nothing bounded ONE caller naming many made-up tokens (each costs requests to
  // Apple) except a Cloudflare rule that cannot exist on workers.dev. The limit is in the Worker.
  it("limits each source address before anything else, keeps other sources working, and never stores the address", async () => {
    const from = (ip: string, path: string, body: unknown) =>
      worker.fetch(
        new Request(`https://gateway.test${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": ip },
          body: JSON.stringify(body),
        }),
        testEnv({ RL_SOURCE_WAKE_PER_MINUTE: "5", RL_SOURCE_DEVICE_PER_MINUTE: "2", WAKE_CRED_SECRET: "test-wake-credential-secret-0123456789abcdef" }),
      );
    const flooder = "203.0.113.77";
    const junk = () => ({ token: randomToken(), kind: "message", topic: TOPIC });
    respond = apnsError(400, "BadDeviceToken");
    for (let i = 0; i < 5; i++) expect((await from(flooder, "/v1/wake", junk())).status).toBe(410);
    const asked = seen.length;
    expect(asked).toBe(10); // five made-up tokens, production then sandbox
    for (let i = 0; i < 20; i++) {
      const res = await from(flooder, "/v1/wake", junk());
      expect(res.status).toBe(429);
      expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
    }
    // Refused before the body is read: not even a malformed request gets a 400…
    expect((await from(flooder, "/v1/wake", "not json")).status).toBe(429);
    expect(seen).toHaveLength(asked); // …and Apple was not asked again.

    // Another source is untouched, and so is the flooder's other route class — until it is full.
    respond = () => new Response(null, { status: 200 });
    expect((await from("198.51.100.8", "/v1/wake", junk())).status).toBe(202);
    expect((await from(flooder, "/v1/challenge", { apns_token: randomToken(), topic: TOPIC })).status).toBe(202);
    expect((await from(flooder, "/v1/challenge", { apns_token: randomToken(), topic: TOPIC })).status).toBe(202);
    expect((await from(flooder, "/v1/challenge", { apns_token: randomToken(), topic: TOPIC })).status).toBe(429);
    expect((await from(flooder, "/v1/revoke", { revoke: `r1.${"A".repeat(75)}` })).status).toBe(429);
    // IPv6: one /64 is one caller, however the address is written.
    for (const ip of ["2001:db8:1:2::1", "2001:0db8:0001:0002:ffff:ffff:ffff:ffff", "2001:db8:1:2:3:4:5:6", "2001:DB8:1:2::9", "2001:db8:1:2:0:0:0:a"]) {
      expect((await from(ip, "/v1/wake", junk())).status).toBe(202);
    }
    expect((await from("2001:db8:1:2::b", "/v1/wake", junk())).status).toBe(429);
    expect((await from("2001:db8:1:3::b", "/v1/wake", junk())).status).toBe(202);

    // What is stored: HMACs under the salt, and nothing that contains an address.
    const dump = await runInDurableObject(limiterStub(), (_i, state) => ({
      source: state.storage.sql.exec<{ h: string; ts: number }>("SELECT * FROM source").toArray(),
      everything: ["hits", "dest", "dead", "mints", "pending", "source"].map((t) => state.storage.sql.exec(`SELECT * FROM ${t}`).toArray()),
    }));
    expect(dump.source.map((r) => r.h)).toContain(await limiterKey(sourceKeyInput("wake", flooder), SALT));
    expect(dump.source.map((r) => r.h)).toContain(await limiterKey(sourceKeyInput("device", flooder), SALT));
    expect(dump.source.map((r) => r.h)).toContain(await limiterKey(sourceKeyInput("wake", "2001:db8:1:2"), SALT));
    for (const row of dump.source) expect(Object.keys(row).sort()).toEqual(["h", "ts"]);
    const stored = JSON.stringify(dump);
    for (const address of [flooder, "198.51.100.8", "2001:db8", "203.0.113"]) expect(stored).not.toContain(address);
    // The rows go after a minute.
    await runInDurableObject(limiterStub(), (_i, state) => {
      state.storage.sql.exec("UPDATE source SET ts = ?", Date.now() - 60_001);
    });
    await runDurableObjectAlarm(limiterStub());
    expect(await runInDurableObject(limiterStub(), (_i, state) => state.storage.sql.exec("SELECT * FROM source").toArray())).toEqual([]);
    expect((await from(flooder, "/v1/wake", junk())).status).toBe(202);
    // No address (not behind Cloudflare), or the limit switched off: not limited.
    for (let i = 0; i < 8; i++) expect((await wake(junk(), { RL_SOURCE_WAKE_PER_MINUTE: "5" })).status).toBe(202);
    expect(sourceOf(null)).toBeNull();
    expect(sourceOf("not an address")).toBeNull();
    expect(sourceOf("::1")).toBe("0:0:0:0");
  });

  // Audit A1: a cap shared by unauthenticated callers is a switch any one of them can flip.
  // The shipped config keeps it off, and says how to leave workers.dev (where no per-source
  // limit can exist) without cutting off the builds that have that address baked in.
  it("ships a config with no shared cap and the way off workers.dev", () => {
    expect(wranglerToml).toMatch(/^RL_GLOBAL_PER_MINUTE = "0"$/m);
    expect(wranglerToml).toMatch(/^# routes = \[\{ pattern = "push\.example\.org", custom_domain = true \}\]$/m);
    expect(wranglerToml).toMatch(/^workers_dev = true$/m);
    expect(wranglerToml).toContain("DO NOT just flip this");
    expect(wranglerToml).toMatch(/^RL_SOURCE_WAKE_PER_MINUTE = "120"$/m);
  });

  it("deletes expired rows from an alarm and stops rescheduling when empty", async () => {
    const limiter = limiterStub();
    const now = Date.now();
    await limiter.take("old", "message", DEFAULT_LIMITS, now - 3_600_001);
    await limiter.take("fresh", "message", DEFAULT_LIMITS, now);
    expect(await runInDurableObject(limiter, (_i, state) => state.storage.getAlarm())).not.toBeNull();

    expect(await runDurableObjectAlarm(limiter)).toBe(true);
    expect((await storedRows()).map((r) => r.h)).toEqual(["fresh"]);
    expect(await runInDurableObject(limiter, (_i, state) => state.storage.getAlarm())).not.toBeNull();

    await runInDurableObject(limiter, (_i, state) => {
      state.storage.sql.exec("UPDATE hits SET ts = ?", now - 3_600_001);
    });
    expect(await runDurableObjectAlarm(limiter)).toBe(true);
    expect(await storedRows()).toEqual([]);
    expect(await runInDurableObject(limiter, (_i, state) => state.storage.getAlarm())).toBeNull();
  });
});

describe("wake credentials", () => {
  const SECRET = "test-wake-credential-secret-0123456789abcdef";
  const TAG = "Zk3_device-chosen-tag";
  const withSecret = (overrides: Partial<Env> = {}): Partial<Env> => ({ WAKE_CRED_SECRET: SECRET, ...overrides });

  const post = (path: string, body: unknown, overrides: Partial<Env> = {}) =>
    worker.fetch(
      new Request(`https://gateway.test${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: typeof body === "string" ? body : JSON.stringify(body),
      }),
      testEnv(withSecret(overrides)),
    );

  interface Registered {
    ok: true;
    credential: string;
    revoke: string;
    id: string;
    expires_at: number;
  }

  async function registerDevice(body: Record<string, unknown> = {}, overrides: Partial<Env> = {}) {
    const apns = randomToken();
    const voip = randomToken();
    const full: Record<string, unknown> = { apns_token: apns, voip_token: voip, topic: TOPIC, ...body };
    // The challenge as the device would have received it by push (the push itself has its own tests).
    full["challenge"] ??= await challengeFor(full["apns_token"] as string);
    const res = await post("/v1/register", full, overrides);
    expect(res.status).toBe(200);
    const reg = (await res.json()) as Registered;
    const liveKey = await limiterKey(credentialKeyInput(hexOf(b64urlDecode(reg.id))), SALT);
    return { apns: (full["apns_token"] as string).toLowerCase(), voip: (full["voip_token"] as string | null)?.toLowerCase() ?? null, liveKey, ...reg };
  }

  const challengeFor = (apns: string, nowMs?: number) => mintChallenge(SECRET, apns.toLowerCase(), nowMs);
  /** A registration body with a valid challenge for a fresh (or the given) APNs token. */
  const regBody = async (apns: string = randomToken(), voip: string | null = null) => ({
    apns_token: apns,
    voip_token: voip,
    topic: TOPIC,
    challenge: await challengeFor(apns),
  });

  const credWake = (credential: string, kind: "message" | "call" = "message", overrides: Partial<Env> = {}) =>
    wake({ credential, kind }, withSecret(overrides));

  const allRows = () =>
    runInDurableObject(limiterStub(), (_i, state) => ({
      hits: state.storage.sql.exec("SELECT * FROM hits").toArray(),
      dest: state.storage.sql.exec("SELECT * FROM dest").toArray(),
      spent: state.storage.sql.exec("SELECT * FROM spent").toArray(),
      cutoff: state.storage.sql.exec("SELECT * FROM cutoff").toArray(),
      live: state.storage.sql.exec("SELECT * FROM live").toArray(),
      pending: state.storage.sql.exec("SELECT * FROM pending").toArray(),
      dead: state.storage.sql.exec("SELECT * FROM dead").toArray(),
      revoked: state.storage.sql.exec("SELECT * FROM revoked").toArray(),
      mints: state.storage.sql.exec("SELECT * FROM mints").toArray(),
    }));

  it("register -> an opaque credential, a revoke token and an expiry 30 days out", async () => {
    const before = Math.floor(Date.now() / 1000);
    const reg = await registerDevice({ tag: TAG });
    expect(reg.ok).toBe(true);
    expect(reg.credential).toMatch(/^w1\.[A-Za-z0-9_-]+$/);
    expect(reg.revoke).toMatch(/^r1\.[A-Za-z0-9_-]+$/);
    expect(reg.expires_at).toBeGreaterThanOrEqual(before + 30 * 86_400);
    expect(reg.expires_at).toBeLessThanOrEqual(before + 30 * 86_400 + 5);
    // Opaque: neither token, the topic nor the tag is readable in what the skwod will hold.
    const raw = new TextDecoder("latin1").decode(b64urlDecode(reg.credential.slice(3)));
    for (const secret of [reg.apns, reg.voip!, TOPIC, TAG]) {
      expect(reg.credential).not.toContain(secret);
      expect(raw).not.toContain(secret);
    }
    // Two registrations of the same tokens are unlinkable strings.
    const again = await registerDevice({ apns_token: reg.apns, voip_token: reg.voip, tag: TAG });
    expect(again.credential).not.toBe(reg.credential);
    expect(seen).toHaveLength(0); // registering never contacts APNs
    expect((await registerDevice({}, { CRED_TTL_DAYS: "7" })).expires_at).toBeLessThanOrEqual(before + 7 * 86_400 + 5);
  });

  it("a credential wake reaches APNs with the registered token, topic and tag, for both kinds", async () => {
    const reg = await registerDevice({ tag: TAG });
    expect((await credWake(reg.credential, "message")).status).toBe(202);
    expect(seen[0]!.url).toBe(`${PROD}/3/device/${reg.apns}`);
    expect(seen[0]!.headers["apns-topic"]).toBe(TOPIC);
    expect(seen[0]!.headers["apns-push-type"]).toBe("alert");
    expect(JSON.parse(seen[0]!.body)).toEqual({ aps: { alert: { body: "New message" }, sound: "default", "mutable-content": 1 }, tag: TAG, skwod_cred: reg.id });

    expect((await credWake(reg.credential, "call")).status).toBe(202);
    expect(seen[1]!.url).toBe(`${PROD}/3/device/${reg.voip}`);
    expect(seen[1]!.headers["apns-topic"]).toBe(`${TOPIC}.voip`);
    expect(seen[1]!.headers["apns-push-type"]).toBe("voip");
    expect(seen[1]!.body).toBe(`{"aps":{},"kind":"call","tag":"${TAG}","skwod_cred":"${reg.id}"}`);

    // Without a tag the payloads are the constants plus the id; tokens are lower-cased at registration.
    seen.length = 0;
    const upper = randomToken().toUpperCase();
    const plain = await registerDevice({ apns_token: upper });
    expect((await credWake(plain.credential)).status).toBe(202);
    expect(seen[0]!.url).toBe(`${PROD}/3/device/${upper.toLowerCase()}`);
    expect(seen[0]!.body).toBe(`${MESSAGE_PAYLOAD.slice(0, -1)},"skwod_cred":"${plain.id}"}`);
  });

  it("a call wake for a registration without a VoIP token is delivered as a message wake", async () => {
    const reg = await registerDevice({ voip_token: null, tag: TAG });
    const call = await credWake(reg.credential, "call");
    expect(call.status).toBe(202);
    expect(await call.json()).toEqual({ ok: true });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(`${PROD}/3/device/${reg.apns}`);
    expect(seen[0]!.headers["apns-push-type"]).toBe("alert");
    expect(seen[0]!.headers["apns-topic"]).toBe(TOPIC);
    expect(JSON.parse(seen[0]!.body)).toEqual({ aps: { alert: { body: "New message" }, sound: "default", "mutable-content": 1 }, tag: TAG, skwod_cred: reg.id });
    // Counted as a message: the burst rule now refuses a message wake and another such call,
    // and it never touched a call budget.
    expect((await credWake(reg.credential, "message")).status).toBe(429);
    expect((await credWake(reg.credential, "call")).status).toBe(429);
    const rows = await allRows();
    expect(rows.hits.map((r) => r["k"])).toEqual([0]);
    expect(rows.dest.map((r) => r["k"])).toEqual([0]);
  });

  it("a dead VoIP token answers 410 to calls only: message wakes for the same credential carry on", async () => {
    const reg = await registerDevice();
    respond = (req) => (req.url.endsWith(reg.voip!) ? Response.json({ reason: "Unregistered" }, { status: 410 }) : new Response(null, { status: 200 }));
    expect((await credWake(reg.credential, "call")).status).toBe(410);
    expect((await credWake(reg.credential, "call")).status).toBe(410); // from the dead mark
    // The skwod keeps its row on a call 410 — and is right to: the alert token is alive.
    expect((await credWake(reg.credential, "message")).status).toBe(202);
  });

  it.each<[string, Record<string, unknown>]>([
    ["missing voip_token", { apns_token: "a".repeat(64), topic: TOPIC }],
    ["non-hex apns token", { apns_token: "z".repeat(64), voip_token: null, topic: TOPIC }],
    ["short apns token", { apns_token: "ab".repeat(31), voip_token: null, topic: TOPIC }],
    ["non-hex voip token", { apns_token: "a".repeat(64), voip_token: "nope", topic: TOPIC }],
    ["bad tag", { apns_token: "a".repeat(64), voip_token: null, topic: TOPIC, tag: "short" }],
    ["extra key", { apns_token: "a".repeat(64), voip_token: null, topic: TOPIC, server: "skwod.example" }],
    ["the wake shape", { token: "a".repeat(64), kind: "message", topic: TOPIC }],
  ])("register refuses %s", async (_name, body) => {
    const withChallenge = { ...body, challenge: await challengeFor("a".repeat(64)) };
    expect((await post("/v1/register", withChallenge)).status).toBe(400);
    expect((await allRows()).mints).toEqual([]);
  });

  it("register refuses a topic that is not allowlisted, and other methods", async () => {
    expect((await post("/v1/register", { ...(await regBody()), topic: "com.attacker.app" })).status).toBe(403);
    for (const path of ["/v1/register", "/v1/revoke", "/v1/challenge", "/v1/revoke-all"]) {
      expect((await worker.fetch(new Request(`https://gateway.test${path}`), testEnv(withSecret()))).status).toBe(405);
    }
  });

  it("refuses garbage, tampered and foreign credentials without touching APNs or the limiter", async () => {
    const reg = await registerDevice();
    const body = reg.credential.slice(3);
    const flipped = (i: number) => `w1.${body.slice(0, i)}${body[i] === "A" ? "B" : "A"}${body.slice(i + 1)}`;
    // Any changed character — nonce, ciphertext or tag — fails authentication.
    for (const i of [0, 20, Math.floor(body.length / 2), body.length - 2]) {
      expect((await credWake(flipped(i))).status).toBe(403);
    }
    expect((await credWake(`w1.${body.slice(0, -8)}`)).status).toBe(403);
    expect((await credWake(`w1.${"A".repeat(120)}`)).status).toBe(403);
    // Sealed under another gateway's secret.
    const foreign = await mintCredential("another-gateway-secret-0123456789abcdef!!", { apns: reg.apns, voip: null, topic: TOPIC }, 3600);
    expect((await credWake(foreign.credential)).status).toBe(403);
    // Not the shape at all.
    for (const bad of ["", "w1.", "w2." + body, body, "w1.has spaces", 42, null, reg.revoke]) {
      expect((await wake({ credential: bad, kind: "message" }, withSecret())).status).toBe(400);
    }
    expect((await wake({ credential: reg.credential, kind: "ring" }, withSecret())).status).toBe(400);
    // A credential plus raw fields is neither shape.
    expect((await wake({ credential: reg.credential, kind: "message", topic: TOPIC }, withSecret())).status).toBe(400);
    expect((await wake({ credential: reg.credential, kind: "message", tag: TAG }, withSecret())).status).toBe(400);
    expect(seen).toHaveLength(0);
    expect((await allRows()).hits).toEqual([]);
  });

  it("an expired credential answers gone", async () => {
    const past = Date.now() - 100 * 86_400_000;
    const expired = await mintCredential(SECRET, { apns: randomToken(), voip: randomToken(), topic: TOPIC }, 90 * 86_400, past);
    for (const kind of ["message", "call"] as const) {
      const res = await credWake(expired.credential, kind);
      expect(res.status).toBe(410);
      expect(await res.json()).toEqual({ ok: false, error: "gone" });
    }
    expect(seen).toHaveLength(0);
    // Revoking an expired registration is accepted and stores nothing.
    expect((await post("/v1/revoke", { revoke: expired.revoke })).status).toBe(200);
    expect((await allRows()).revoked).toEqual([]);
  });

  it("a credential for a topic that left the allowlist is refused", async () => {
    const reg = await registerDevice();
    expect((await credWake(reg.credential, "message", { ALLOWED_TOPICS: "com.other.app" })).status).toBe(403);
    expect(seen).toHaveLength(0);
  });

  it("revoke -> the credential is gone for good; other registrations of the same device carry on", async () => {
    const a = await registerDevice();
    const b = await registerDevice({ apns_token: a.apns, voip_token: a.voip });
    expect((await credWake(a.credential)).status).toBe(202);
    const res = await post("/v1/revoke", { revoke: a.revoke });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    const asked = seen.length;
    for (const kind of ["message", "call"] as const) {
      const woken = await credWake(a.credential, kind);
      expect(woken.status).toBe(410);
      expect(await woken.json()).toEqual({ ok: false, error: "gone" });
    }
    expect(seen).toHaveLength(asked); // APNs is not asked on behalf of a revoked credential
    // Idempotent.
    expect((await post("/v1/revoke", { revoke: a.revoke })).status).toBe(200);
    expect((await credWake(a.credential)).status).toBe(410);
    // The same phone's registration with another skwod is untouched.
    expect((await credWake(b.credential)).status).toBe(202);

    // What is stored: one HMAC row, kept until the credential's own expiry, then swept.
    const { revoked } = await allRows();
    expect(revoked).toHaveLength(1);
    expect(revoked[0]!["until"]).toBe(a.expires_at * 1000);
    expect(JSON.stringify(revoked)).not.toContain(a.apns);
    await runInDurableObject(limiterStub(), (_i, state) => {
      state.storage.sql.exec("UPDATE revoked SET until = ?", Date.now() - 1);
    });
    await runDurableObjectAlarm(limiterStub());
    expect((await allRows()).revoked).toEqual([]);
  });

  it("only the revoke token revokes: the credential, a forgery or another device's token do not", async () => {
    const a = await registerDevice();
    const b = await registerDevice();
    // The skwod holds the credential — that is not a revoke token, in either field.
    expect((await post("/v1/revoke", { revoke: a.credential })).status).toBe(400);
    expect((await post("/v1/revoke", { revoke: `r1.${a.credential.slice(3, 78)}` })).status).toBe(403);
    expect((await post("/v1/revoke", { credential: a.credential })).status).toBe(400);
    // A tampered token, and one minted under another secret.
    const body = a.revoke.slice(3);
    for (const i of [0, 10, 30, body.length - 2]) {
      const forged = `r1.${body.slice(0, i)}${body[i] === "A" ? "B" : "A"}${body.slice(i + 1)}`;
      expect((await post("/v1/revoke", { revoke: forged })).status).toBe(403);
    }
    const foreign = await mintCredential("another-gateway-secret-0123456789abcdef!!", { apns: a.apns, voip: null, topic: TOPIC }, 3600);
    expect((await post("/v1/revoke", { revoke: foreign.revoke })).status).toBe(403);
    expect((await allRows()).revoked).toEqual([]);
    expect((await credWake(a.credential)).status).toBe(202);
    // B's token revokes B only.
    expect((await post("/v1/revoke", { revoke: b.revoke })).status).toBe(200);
    expect((await credWake(b.credential)).status).toBe(410);
    expect((await credWake(a.credential, "call")).status).toBe(202);
    // The revoke token is not derivable from the credential: nothing of it appears there.
    expect(a.credential).not.toContain(body.slice(0, 16));
  });

  it("budgets are per credential: one skwod's wakes never use up another's for the same phone", async () => {
    const a = await registerDevice();
    const b = await registerDevice({ apns_token: a.apns, voip_token: a.voip });
    expect((await credWake(a.credential)).status).toBe(202);
    const limited = await credWake(a.credential);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    // Same phone, other skwod: untouched.
    expect((await credWake(b.credential)).status).toBe(202);
    // Calls too: A rings to its own limit and B still has its own six — as far as the proven
    // device's ring ceiling allows (raised here; by default it equals one credential's six a minute).
    const roomy = { RL_DEST_CALL_PER_MINUTE: "12" };
    for (let i = 0; i < DEFAULT_LIMITS.callPerMinute; i++) expect((await credWake(a.credential, "call", roomy)).status).toBe(202);
    expect((await credWake(a.credential, "call", roomy)).status).toBe(429);
    for (let i = 0; i < DEFAULT_LIMITS.callPerMinute; i++) expect((await credWake(b.credential, "call", roomy)).status).toBe(202);
  });

  it("raw wakes and credential wakes have separate budgets, in both directions", async () => {
    const reg = await registerDevice();
    const rawMessage = { token: reg.apns, kind: "message", topic: TOPIC };
    const rawCall = { token: reg.voip, kind: "call", topic: TOPIC };
    // A holder of the raw tokens exhausts everything the raw shape allows…
    expect((await wake(rawMessage, withSecret())).status).toBe(202);
    expect((await wake(rawMessage, withSecret())).status).toBe(429);
    for (let i = 0; i < DEFAULT_LIMITS.callPerMinute; i++) expect((await wake(rawCall, withSecret())).status).toBe(202);
    expect((await wake(rawCall, withSecret())).status).toBe(429);
    // …inventing tags buys nothing…
    expect((await wake({ ...rawMessage, tag: "invented-tag-0000001" }, withSecret())).status).toBe(429);
    expect((await wake({ ...rawCall, tag: "invented-tag-0000002" }, withSecret())).status).toBe(429);
    // …and the credential still wakes, alert and ring: the raw path's rows are its own, and no
    // proven device's ceiling is counted under them.
    expect((await credWake(reg.credential)).status).toBe(202);
    for (let i = 0; i < DEFAULT_LIMITS.callPerMinute; i++) expect((await credWake(reg.credential, "call")).status).toBe(202);

    // The other way round: a credential at its limit does not silence a legacy skwod.
    const other = await registerDevice();
    expect((await credWake(other.credential)).status).toBe(202);
    expect((await credWake(other.credential)).status).toBe(429);
    expect((await wake({ token: other.apns, kind: "message", topic: TOPIC }, withSecret())).status).toBe(202);
  });

  it("a token APNs calls dead is gone for every credential that points at it, and costs no budget", async () => {
    const a = await registerDevice();
    const b = await registerDevice({ apns_token: a.apns, voip_token: a.voip });
    respond = apnsError(410, "Unregistered");
    expect((await credWake(a.credential)).status).toBe(410);
    const asked = seen.length;
    expect((await credWake(b.credential)).status).toBe(410);
    expect((await wake({ token: a.apns, kind: "message", topic: TOPIC }, withSecret())).status).toBe(410);
    expect(seen).toHaveLength(asked);
    const rows = await allRows();
    expect(rows.hits).toEqual([]);
    expect(rows.dead.map((d) => d["h"])).toEqual([await limiterKey(a.apns, SALT)]);
  });

  it("caps registrations per APNs token per day, and per VoIP token", async () => {
    const apns = randomToken();
    for (let i = 0; i < DEFAULT_LIMITS.registerPerDay; i++) expect((await post("/v1/register", await regBody(apns))).status).toBe(200);
    const refused = await post("/v1/register", await regBody(apns));
    expect(refused.status).toBe(429);
    expect(await refused.json()).toEqual({ ok: false, error: "rate_limited" });
    expect(Number(refused.headers.get("retry-after"))).toBeGreaterThan(86_000);
    // Per token: another phone registers freely; and the cap is configurable.
    expect((await post("/v1/register", await regBody())).status).toBe(200);
    const two = randomToken();
    const capped = { RL_REGISTER_PER_DAY: "2" };
    for (let i = 0; i < 2; i++) expect((await post("/v1/register", await regBody(two), capped)).status).toBe(200);
    expect((await post("/v1/register", await regBody(two), capped)).status).toBe(429);

    // The VoIP token is NOT counted: nobody owns one here, so a cap on it would be something
    // anyone who knows a phone's VoIP token could use up to keep that phone from registering.
    const sharedVoip = randomToken();
    for (let i = 0; i < 5; i++) expect((await post("/v1/register", await regBody(randomToken(), sharedVoip), capped)).status).toBe(200);

    // Stored: HMAC rows only, swept after a day.
    const { mints } = await allRows();
    expect(JSON.stringify(mints)).not.toContain(apns);
    expect(JSON.stringify(mints)).not.toContain(sharedVoip);
    expect(mints.map((m) => m["h"])).toContain(await limiterKey(mintKeyInput(apns), SALT));
    expect(mints.map((m) => m["h"])).not.toContain(await limiterKey(mintKeyInput(sharedVoip), SALT));
    await runInDurableObject(limiterStub(), (_i, state) => {
      state.storage.sql.exec("UPDATE mints SET ts = ?", Date.now() - 86_400_001);
    });
    await runDurableObjectAlarm(limiterStub());
    expect((await allRows()).mints).toEqual([]);
    expect((await post("/v1/register", await regBody(apns))).status).toBe(200);
  });

  it("keeps at most 16 live credentials per APNs token: the 17th evicts the oldest", async () => {
    const apns = randomToken();
    const voip = randomToken();
    const made: string[] = [];
    for (let i = 0; i < DEFAULT_LIMITS.liveCredentials + 1; i++) {
      const res = await post("/v1/register", await regBody(apns, voip));
      expect(res.status).toBe(200);
      made.push(((await res.json()) as Registered).credential);
      // Distinct mint times, so "oldest" is well defined.
      await new Promise((r) => setTimeout(r, 2));
    }
    const noBurst = { RL_MESSAGE_BURST: "100", RL_DEST_MESSAGE_FACTOR: "100" };
    const evicted = await credWake(made[0]!, "message", noBurst);
    expect(evicted.status).toBe(410);
    expect(await evicted.json()).toEqual({ ok: false, error: "gone" });
    expect((await credWake(made[0]!, "call", noBurst)).status).toBe(410);
    expect(seen).toHaveLength(0);
    // The sixteen newest all work.
    expect((await credWake(made[1]!, "message", noBurst)).status).toBe(202);
    expect((await credWake(made[16]!, "message", noBurst)).status).toBe(202);
    const rows = await allRows();
    expect(rows.live).toHaveLength(DEFAULT_LIMITS.liveCredentials);
    expect(rows.revoked).toHaveLength(1);
    expect(JSON.stringify(rows.live)).not.toContain(apns);
    // Another phone's credentials are not in that count.
    const other = await registerDevice();
    expect((await credWake(other.credential)).status).toBe(202);
    // Revoking one frees its slot; expired rows are swept.
    await runInDurableObject(limiterStub(), (_i, state) => {
      state.storage.sql.exec("UPDATE live SET until = ?", Date.now() - 1);
    });
    await runDurableObjectAlarm(limiterStub());
    expect((await allRows()).live).toEqual([]);
  });

  it("many credentials for one phone never exceed the phone's ring or message ceiling", async () => {
    const apns = randomToken();
    const voip = randomToken();
    const creds: string[] = [];
    for (let i = 0; i < 8; i++) {
      const res = await post("/v1/register", await regBody(apns, voip));
      creds.push(((await res.json()) as Registered).credential);
    }
    // Rings: 8 credentials x 6 a minute would be 48; the phone gets 6.
    let rings = 0;
    for (const c of creds) {
      for (let i = 0; i < DEFAULT_LIMITS.callPerMinute; i++) {
        const res = await credWake(c, "call");
        if (res.status === 202) rings++;
        else expect(res.status).toBe(429);
      }
    }
    expect(rings).toBe(DEFAULT_LIMITS.destCallPerMinute);
    expect(seen.filter((r) => r.url.endsWith(voip))).toHaveLength(DEFAULT_LIMITS.destCallPerMinute);
    // The raw path has rows of its own (it has no proven device): not counted here, not filled by it.
    expect((await wake({ token: voip, kind: "call", topic: TOPIC }, withSecret())).status).toBe(202);

    // Alerts: one each from 8 credentials within the burst window would be 8; the phone gets 4.
    let alerts = 0;
    for (const c of creds) if ((await credWake(c, "message")).status === 202) alerts++;
    expect(alerts).toBe(DEFAULT_LIMITS.messageBurst * DEFAULT_LIMITS.destMessageFactor);
    expect((await wake({ token: apns, kind: "message", topic: TOPIC }, withSecret())).status).toBe(202);
    // Refused wakes stored nothing, and another phone is unaffected.
    const rows = await allRows();
    expect(rows.dest).toHaveLength(DEFAULT_LIMITS.destCallPerMinute + alerts + 2); // + the two raw wakes
    expect(rows.dest.every((r) => /^[0-9a-f]{64}$/.test(String(r["h"])))).toBe(true);
    // Keyed per proven device: the pair for rings, the APNs token for alerts; the raw rows apart.
    const destKeys = new Set(rows.dest.map((r) => r["h"]));
    expect(destKeys).toEqual(
      new Set([
        await limiterKey(deviceKeyInput(apns, voip), SALT),
        await limiterKey(deviceKeyInput(apns), SALT),
        await limiterKey(destKeyInput(voip), SALT),
        await limiterKey(destKeyInput(apns), SALT),
      ]),
    );
    const other = await registerDevice();
    expect((await credWake(other.credential, "call")).status).toBe(202);
  });

  it("the sustained device ceiling: hourly and 10-minute message caps hold across credentials", async () => {
    const limiter = limiterStub();
    const limits = { ...DEFAULT_LIMITS, messageBurst: 1000, messagePerTenMinutes: 3, messagePerHour: 5, destMessageFactor: 2 };
    const t0 = 1_800_000_000_000;
    let ok = 0;
    // Ten credentials, three wakes each inside ten minutes: 30 asked, 6 (3 x 2) delivered.
    for (let c = 0; c < 10; c++) {
      for (let i = 0; i < 3; i++) {
        if ((await limiter.take(`cred${c}`, "message", limits, t0 + c * 1000 + i, { destKey: "phone" })).ok) ok++;
      }
    }
    expect(ok).toBe(6);
    // Next 10-minute window: the hourly ceiling (5 x 2 = 10) leaves four more.
    ok = 0;
    for (let c = 10; c < 20; c++) {
      if ((await limiter.take(`cred${c}`, "message", limits, t0 + 11 * 60_000 + c, { destKey: "phone" })).ok) ok++;
    }
    expect(ok).toBe(4);
    // Another phone, same instant: untouched.
    expect((await limiter.take("credX", "message", limits, t0 + 11 * 60_000 + 50, { destKey: "other-phone" })).ok).toBe(true);
  });

  it("stores nothing but HMAC-keyed rows for a credential wake", async () => {
    const reg = await registerDevice({ tag: TAG });
    expect((await credWake(reg.credential)).status).toBe(202);
    const rows = await allRows();
    expect(rows.hits).toHaveLength(1);
    expect(rows.hits[0]!["h"]).toMatch(/^[0-9a-f]{64}$/);
    // Not the token's own row: the budget belongs to the registration.
    expect(rows.hits[0]!["h"]).not.toBe(await limiterKey(reg.apns, SALT));
    expect(rows.hits[0]!["h"]).not.toBe(await limiterKey(credentialKeyInput(reg.apns), SALT));
    const stored = JSON.stringify(rows);
    for (const secret of [reg.apns, reg.voip!, reg.credential, reg.credential.slice(3), reg.revoke.slice(3), TAG, TOPIC]) {
      expect(stored).not.toContain(secret);
    }
  });

  // Audit A1: `/v1/challenge` is open to anyone, and every made-up token cost two requests to
  // Apple (production, then sandbox) under the publisher's key — each time it was asked.
  it("a challenge for a token APNs calls dead is asked of Apple once, then answered 410 from the mark", async () => {
    const junk = randomToken();
    respond = apnsError(400, "BadDeviceToken");
    expect((await post("/v1/challenge", { apns_token: junk, topic: TOPIC })).status).toBe(410);
    expect(seen).toHaveLength(2);
    for (let i = 0; i < 5; i++) expect((await post("/v1/challenge", { apns_token: junk, topic: TOPIC })).status).toBe(410);
    expect(seen).toHaveLength(2);
    // The mark is the wake path's: a raw wake to it is refused without asking either…
    expect((await wake({ token: junk, kind: "message", topic: TOPIC })).status).toBe(410);
    expect(seen).toHaveLength(2);
    const rows = await allRows();
    expect(rows.dead.map((d) => d["h"])).toEqual([await limiterKey(junk, SALT)]);
    expect(rows.pending).toEqual([]);
    // …and it expires: a token that is real after all gets its challenge.
    await runInDurableObject(limiterStub(), (_i, state) => {
      state.storage.sql.exec("UPDATE dead SET until = ?", Date.now() - 1);
    });
    respond = () => new Response(null, { status: 200 });
    expect((await post("/v1/challenge", { apns_token: junk, topic: TOPIC })).status).toBe(202);
    expect(seen).toHaveLength(3);
  });

  it("without WAKE_CRED_SECRET (or with a short one): 503 for credentials, raw wakes still work", async () => {
    const reg = await registerDevice();
    for (const secret of [undefined, "", "too-short"]) {
      const off = { WAKE_CRED_SECRET: secret };
      const r = await post("/v1/register", await regBody(), off);
      expect(r.status).toBe(503);
      expect((await post("/v1/challenge", { apns_token: randomToken(), topic: TOPIC }, off)).status).toBe(503);
      expect((await post("/v1/revoke-all", { apns_token: reg.apns, topic: TOPIC, challenge: await challengeFor(reg.apns) }, off)).status).toBe(503);
      expect(await r.json()).toEqual({ ok: false, error: "unavailable" });
      expect((await wake({ credential: reg.credential, kind: "message" }, off)).status).toBe(503);
      expect((await post("/v1/revoke", { revoke: reg.revoke }, off)).status).toBe(503);
      expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC }, off)).status).toBe(202);
    }
    const rows = await allRows();
    expect(rows.mints).toHaveLength(1); // the one registration above, counted under its APNs token
    expect(rows.revoked).toEqual([]);
    expect(rows.cutoff).toEqual([]);
  });

  it("LEGACY_RAW_WAKES=0 refuses the raw shape and leaves credentials working", async () => {
    const reg = await registerDevice();
    const off = { LEGACY_RAW_WAKES: "0" };
    for (const body of [
      { token: reg.apns, kind: "message", topic: TOPIC },
      { token: reg.voip, kind: "call", topic: TOPIC, tag: TAG },
    ]) {
      const res = await wake(body, withSecret(off));
      expect(res.status).toBe(410);
      expect(await res.json()).toEqual({ ok: false, error: "gone" });
    }
    expect(seen).toHaveLength(0);
    expect((await credWake(reg.credential, "message", off)).status).toBe(202);
    // Default and "1": accepted.
    expect((await wake({ token: randomToken(), kind: "message", topic: TOPIC }, withSecret({ LEGACY_RAW_WAKES: "1" }))).status).toBe(202);
  });

  describe("proof of possession", () => {
    const pushed = () => JSON.parse(seen[seen.length - 1]!.body) as { aps: Record<string, unknown>; skwod_challenge: string };

    it("challenge -> a silent background push carrying the one-time value, and nothing in the response", async () => {
      const apns = randomToken();
      const res = await post("/v1/challenge", { apns_token: apns.toUpperCase(), topic: TOPIC });
      expect(res.status).toBe(202);
      expect(await res.json()).toEqual({ ok: true }); // the value travels by push only
      expect(seen).toHaveLength(1);
      const req = seen[0]!;
      expect(req.url).toBe(`${PROD}/3/device/${apns}`);
      expect(req.headers["apns-push-type"]).toBe("background");
      expect(req.headers["apns-priority"]).toBe("5");
      expect(req.headers["apns-topic"]).toBe(TOPIC);
      const body = pushed();
      // Nothing to see or hear: no alert, no sound, no badge.
      expect(body.aps).toEqual({ "content-available": 1 });
      expect(Object.keys(body).sort()).toEqual(["aps", "skwod_challenge"]);
      expect(body.skwod_challenge).toMatch(/^c1\.[A-Za-z0-9_-]{75}$/);
      // Stored: a counter row keyed by an HMAC, nothing else.
      const rows = await allRows();
      expect(rows.mints).toHaveLength(1);
      expect(JSON.stringify(rows)).not.toContain(apns);
      expect(JSON.stringify(rows)).not.toContain(body.skwod_challenge.slice(3));

      // The pushed value registers that token.
      const reg = await post("/v1/register", { apns_token: apns, voip_token: null, topic: TOPIC, challenge: body.skwod_challenge });
      expect(reg.status).toBe(200);
    });

    it.each<[string, Record<string, unknown>]>([
      ["missing topic", { apns_token: "a".repeat(64) }],
      ["bad token", { apns_token: "nope", topic: TOPIC }],
      ["extra key", { apns_token: "a".repeat(64), topic: TOPIC, voip_token: null }],
    ])("challenge refuses %s", async (_name, body) => {
      expect((await post("/v1/challenge", body)).status).toBe(400);
      expect(seen).toHaveLength(0);
    });

    it("challenge refuses a foreign topic, and reports a dead token or an APNs failure", async () => {
      expect((await post("/v1/challenge", { apns_token: randomToken(), topic: "com.attacker.app" })).status).toBe(403);
      expect(seen).toHaveLength(0);
      respond = apnsError(410, "Unregistered");
      expect((await post("/v1/challenge", { apns_token: randomToken(), topic: TOPIC })).status).toBe(410);
      respond = apnsError(500, "InternalServerError");
      expect((await post("/v1/challenge", { apns_token: randomToken(), topic: TOPIC })).status).toBe(503);
      expect((await post("/v1/challenge", { apns_token: randomToken(), topic: TOPIC }, { APNS_KEY_ID: "" })).status).toBe(503);
    });

    /** As if the outstanding challenge had been used or had run out: the next request pushes again. */
    const forgetOutstanding = () =>
      runInDurableObject(limiterStub(), (_i, state) => {
        state.storage.sql.exec("DELETE FROM pending");
      });

    it("limits challenges per token: 3 per 10 minutes, 10 per day", async () => {
      const apns = randomToken();
      const ask = async (overrides: Partial<Env> = {}) => {
        await forgetOutstanding();
        return post("/v1/challenge", { apns_token: apns, topic: TOPIC }, overrides);
      };
      for (let i = 0; i < DEFAULT_LIMITS.challengePerTenMinutes; i++) expect((await ask()).status).toBe(202);
      const refused = await ask();
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get("retry-after"))).toBeGreaterThan(500);
      expect(seen).toHaveLength(DEFAULT_LIMITS.challengePerTenMinutes); // a refused challenge pushes nothing
      // Another phone is not affected.
      expect((await post("/v1/challenge", { apns_token: randomToken(), topic: TOPIC })).status).toBe(202);
      // The daily cap, with the short one out of the way.
      const lax = { RL_CHALLENGE_PER_10MIN: "100" };
      for (let i = DEFAULT_LIMITS.challengePerTenMinutes; i < DEFAULT_LIMITS.challengePerDay; i++) expect((await ask(lax)).status).toBe(202);
      const day = await ask(lax);
      expect(day.status).toBe(429);
      expect(Number(day.headers.get("retry-after"))).toBeGreaterThan(86_000);
    });

    it("a flood of challenge requests costs the device one silent push and none of its budget, and does not stop the owner", async () => {
      const apns = randomToken();
      const voip = randomToken();
      // Someone else asks first, and keeps asking.
      for (let i = 0; i < 50; i++) expect((await post("/v1/challenge", { apns_token: apns, topic: TOPIC })).status).toBe(202);
      expect(seen).toHaveLength(1); // one push reached the phone; 49 requests did nothing
      let rows = await allRows();
      expect(rows.mints).toHaveLength(1); // one unit of the token's challenge budget, not 50
      expect(rows.pending).toHaveLength(1);
      expect(JSON.stringify(rows.pending)).not.toContain(apns);

      // The owner asks too — also "yes, nothing sent" — and already holds the delivered value.
      expect((await post("/v1/challenge", { apns_token: apns, topic: TOPIC })).status).toBe(202);
      expect(seen).toHaveLength(1);
      const delivered = pushed().skwod_challenge;
      const res = await post("/v1/register", { apns_token: apns, voip_token: voip, topic: TOPIC, challenge: delivered });
      expect(res.status).toBe(200);
      const reg = (await res.json()) as Registered;
      expect((await credWake(reg.credential)).status).toBe(202);

      // Used: the next request pushes a new one (the flood resumes; still one push per use).
      seen.length = 0;
      for (let i = 0; i < 20; i++) expect((await post("/v1/challenge", { apns_token: apns, topic: TOPIC })).status).toBe(202);
      expect(seen).toHaveLength(1);
      // And the owner can revoke with it — or without any challenge at all, by revoke token.
      expect((await post("/v1/revoke-all", { apns_token: apns, topic: TOPIC, challenge: pushed().skwod_challenge })).status).toBe(200);
      expect((await credWake(reg.credential)).status).toBe(410);
      rows = await allRows();
      expect(rows.mints.filter((m) => m["ts"] !== undefined)).toHaveLength(3); // 2 challenges + the registration

      // An outstanding challenge that ran out no longer suppresses.
      // (Each of these is a real push, so it does draw on the 3-per-10-minutes allowance.)
      seen.length = 0;
      const lax = { RL_CHALLENGE_PER_10MIN: "10" };
      expect((await post("/v1/challenge", { apns_token: apns, topic: TOPIC }, lax)).status).toBe(202);
      await runInDurableObject(limiterStub(), (_i, state) => {
        state.storage.sql.exec("UPDATE pending SET until = ?", Date.now() - 1);
      });
      expect((await post("/v1/challenge", { apns_token: apns, topic: TOPIC }, lax)).status).toBe(202);
      expect(seen).toHaveLength(2);
      // A challenge APNs did not accept is not "outstanding".
      const other = randomToken();
      respond = apnsError(500, "InternalServerError");
      expect((await post("/v1/challenge", { apns_token: other, topic: TOPIC })).status).toBe(503);
      respond = () => new Response(null, { status: 200 });
      seen.length = 0;
      expect((await post("/v1/challenge", { apns_token: other, topic: TOPIC })).status).toBe(202);
      expect(seen).toHaveLength(1);
    });

    it("with the challenge budget used up by others, the owner renews and revokes by revoke token", async () => {
      const mine = await registerDevice({ tag: TAG });
      // The token's challenge allowance is gone for the day.
      const exhausted = { RL_CHALLENGE_PER_DAY: "1" };
      expect((await post("/v1/challenge", { apns_token: mine.apns, topic: TOPIC }, exhausted)).status).toBe(202);
      await forgetOutstanding();
      expect((await post("/v1/challenge", { apns_token: mine.apns, topic: TOPIC }, exhausted)).status).toBe(429);
      seen.length = 0;

      // Renewal: the same tokens, proven by the revoke token of the credential already held.
      const renewal = await post("/v1/register", { apns_token: mine.apns, voip_token: mine.voip, topic: TOPIC, tag: TAG, revoke: mine.revoke }, exhausted);
      expect(renewal.status).toBe(200);
      const renewed = (await renewal.json()) as Registered;
      expect(renewed.credential).not.toBe(mine.credential);
      expect((await credWake(renewed.credential)).status).toBe(202);
      expect(seen[0]!.url).toBe(`${PROD}/3/device/${mine.apns}`);
      // Not consumed: it works again, and the old credential is still the device's to revoke.
      expect((await post("/v1/register", { apns_token: mine.apns, voip_token: null, topic: TOPIC, revoke: mine.revoke })).status).toBe(200);
      // Renewal counts against the registration cap like any other.
      const capped = { RL_REGISTER_PER_DAY: "3" };
      expect((await post("/v1/register", { apns_token: mine.apns, voip_token: null, topic: TOPIC, revoke: renewed.revoke }, capped)).status).toBe(429);

      // What is NOT proof.
      const base = { apns_token: mine.apns, voip_token: mine.voip, topic: TOPIC };
      // The wake credential — the skwod holds that; it must never mint or revoke with it.
      expect((await post("/v1/register", { ...base, credential: mine.credential })).status).toBe(400);
      expect((await post("/v1/revoke-all", { apns_token: mine.apns, topic: TOPIC, credential: mine.credential })).status).toBe(400);
      // Two proofs, or none.
      expect((await post("/v1/register", { ...base, revoke: mine.revoke, challenge: await challengeFor(mine.apns) })).status).toBe(400);
      expect((await post("/v1/register", base)).status).toBe(400);
      // A revoke token for ANOTHER phone's credential.
      const theirs = await registerDevice();
      expect((await post("/v1/register", { ...base, revoke: theirs.revoke })).status).toBe(403);
      expect((await post("/v1/revoke-all", { apns_token: mine.apns, topic: TOPIC, revoke: theirs.revoke })).status).toBe(403);
      // A forged one.
      expect((await post("/v1/register", { ...base, revoke: `r1.${"A".repeat(75)}` })).status).toBe(403);
      // The revoke token of a credential that was itself revoked proves nothing any more.
      expect((await post("/v1/revoke", { revoke: mine.revoke })).status).toBe(200);
      expect((await post("/v1/register", { ...base, revoke: mine.revoke })).status).toBe(403);
      expect((await post("/v1/revoke-all", { apns_token: mine.apns, topic: TOPIC, revoke: mine.revoke })).status).toBe(403);
      expect((await credWake(renewed.credential, "call")).status).toBe(202);

      // revoke-all by revoke token: everything for this phone is gone, the other phone is not.
      await new Promise((r) => setTimeout(r, 3));
      const all = await post("/v1/revoke-all", { apns_token: mine.apns, topic: TOPIC, revoke: renewed.revoke }, exhausted);
      expect(all.status).toBe(200);
      expect((await credWake(renewed.credential)).status).toBe(410);
      expect((await credWake(mine.credential)).status).toBe(410);
      expect((await credWake(theirs.credential)).status).toBe(202);
      // …after which that revoke token is spent too: its credential is no longer outstanding.
      expect((await post("/v1/revoke-all", { apns_token: mine.apns, topic: TOPIC, revoke: renewed.revoke })).status).toBe(403);
    });

    it("nobody owns a VoIP token: two devices register the same one and neither affects the other", async () => {
      const voip = randomToken();
      const a = await registerDevice({ voip_token: voip });
      // A second device — or a stale server with a device of its own — names the same VoIP token.
      const b = await registerDevice({ voip_token: voip.toUpperCase() });
      // …and A registers it again afterwards, as often as it likes: nothing was taken.
      const a2 = await registerDevice({ apns_token: a.apns, voip_token: voip });
      for (const c of [a, b, a2]) expect((await credWake(c.credential, "call")).status).toBe(202);
      expect(seen.every((r) => r.url === `${PROD}/3/device/${voip}`)).toBe(true);
      await new Promise((r) => setTimeout(r, 3));

      // A cuts off everything minted under ITS APNs token — both halves of each credential.
      expect((await post("/v1/revoke-all", { apns_token: a.apns, topic: TOPIC, revoke: a.revoke })).status).toBe(200);
      for (const c of [a, a2]) {
        expect((await credWake(c.credential, "call")).status).toBe(410);
        expect((await credWake(c.credential, "message")).status).toBe(410);
      }
      // B's credential, same VoIP token, is untouched: still rings, still alerts, still B's to renew.
      expect((await credWake(b.credential, "call")).status).toBe(202);
      expect((await credWake(b.credential, "message")).status).toBe(202);
      expect((await post("/v1/register", { apns_token: b.apns, voip_token: voip, topic: TOPIC, revoke: b.revoke })).status).toBe(200);
      let rows = await allRows();
      expect(rows.cutoff).toHaveLength(1);
      expect(rows.cutoff[0]!["h"]).toBe(await limiterKey(cutoffKeyInput(a.apns), SALT));
      // No table holds anything derived from the VoIP token but its ring count.
      const voipHmacs = [voip, destKeyInput(voip), mintKeyInput(voip), cutoffKeyInput(voip), liveKeyInput(voip)];
      const keysOf = (t: Record<string, unknown>[]) => t.flatMap((r) => [r["h"], r["t"], r["c"]]);
      for (const table of [rows.cutoff, rows.live, rows.mints, rows.revoked, rows.spent, rows.pending]) {
        for (const input of voipHmacs) expect(keysOf(table)).not.toContain(await limiterKey(input, SALT));
      }

      // The other way round: B's revoke-all and single revoke do nothing to A.
      await new Promise((r) => setTimeout(r, 3));
      const a3 = await registerDevice({ apns_token: a.apns, voip_token: voip });
      expect((await post("/v1/revoke-all", { apns_token: b.apns, topic: TOPIC, challenge: await challengeFor(b.apns) })).status).toBe(200);
      expect((await credWake(b.credential, "call")).status).toBe(410);
      expect((await credWake(a3.credential, "call")).status).toBe(202);
      expect((await credWake(a3.credential, "message")).status).toBe(202);
      // B is not locked out of the VoIP token either, and nor is anyone else.
      await new Promise((r) => setTimeout(r, 3));
      expect((await post("/v1/register", await regBody(b.apns, voip))).status).toBe(200);
      expect((await post("/v1/register", await regBody(randomToken(), voip))).status).toBe(200);
      rows = await allRows();
      expect(rows.cutoff).toHaveLength(2); // A's and B's APNs tokens
    });

    it("a stranger's credentials naming the owner's VoIP token spend the stranger's ring share, never the owner's", async () => {
      const voip = randomToken();
      const owner = await registerDevice({ voip_token: voip });
      // The stranger: a proven device of its own, and several credentials naming the owner's VoIP token.
      const strangerApns = randomToken();
      const creds: string[] = [];
      for (let i = 0; i < 4; i++) creds.push((await registerDevice({ apns_token: strangerApns, voip_token: voip })).credential);
      /** Ring attempts spread over the stranger's credentials; how many got through. */
      const round = async (attempts: number) => {
        let rung = 0;
        for (let i = 0; i < attempts; i++) {
          const res = await credWake(creds[i % creds.length]!, "call");
          if (res.status === 202) rung++;
          else expect(res.status).toBe(429);
        }
        return rung;
      };
      const aMinuteLater = () =>
        runInDurableObject(limiterStub(), (_i, state) => {
          state.storage.sql.exec("UPDATE dest SET ts = ts - 61000");
          state.storage.sql.exec("UPDATE hits SET ts = ts - 61000");
        });

      // The minute: many credentials of one proven device share that device's 6 — none is near its own six.
      expect(await round(16)).toBe(DEFAULT_LIMITS.destCallPerMinute);
      // The owner's calls are unaffected, to the full extent of its own share.
      for (let i = 0; i < DEFAULT_LIMITS.destCallPerMinute; i++) expect((await credWake(owner.credential, "call")).status).toBe(202);
      expect((await credWake(owner.credential, "call")).status).toBe(429);
      // The hour: the stranger gets 6 + 6 + 6 + 2 and then nothing…
      let total = DEFAULT_LIMITS.destCallPerMinute;
      for (let minute = 0; minute < 5; minute++) {
        await aMinuteLater();
        total += await round(16);
      }
      expect(total).toBe(DEFAULT_LIMITS.destCallPerHour);
      await aMinuteLater();
      const refused = await credWake(creds[0]!, "call");
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get("retry-after"))).toBeGreaterThan(3000); // the hour, not the minute
      // …one more credential buys it nothing…
      const late = await registerDevice({ apns_token: strangerApns, voip_token: voip });
      expect((await credWake(late.credential, "call")).status).toBe(429);
      // …and the owner still rings: its hour holds only its own six.
      expect((await credWake(owner.credential, "call")).status).toBe(202);
      // A second stranger has a share of its own — each needs a real proven device for it.
      expect((await credWake((await registerDevice({ voip_token: voip })).credential, "call")).status).toBe(202);
      // The raw path is apart from every pair, in both directions.
      for (let i = 0; i < DEFAULT_LIMITS.callPerMinute; i++) expect((await wake({ token: voip, kind: "call", topic: TOPIC }, withSecret())).status).toBe(202);
      expect((await wake({ token: voip, kind: "call", topic: TOPIC }, withSecret())).status).toBe(429);
      expect((await credWake(owner.credential, "call")).status).toBe(202);

      // No row is keyed on the VoIP token alone except the raw path's.
      const rows = await allRows();
      const perKey = (h: string) => rows.dest.filter((r) => r["h"] === h).length;
      expect(perKey(await limiterKey(deviceKeyInput(strangerApns, voip), SALT))).toBe(DEFAULT_LIMITS.destCallPerHour);
      expect(perKey(await limiterKey(deviceKeyInput(owner.apns, voip), SALT))).toBe(DEFAULT_LIMITS.destCallPerMinute + 2);
      expect(perKey(await limiterKey(destKeyInput(voip), SALT))).toBe(DEFAULT_LIMITS.callPerMinute);
      // Configurable.
      expect((await credWake(creds[0]!, "call", { RL_DEST_CALL_PER_HOUR: "21" })).status).toBe(202);
      expect((await credWake(creds[1]!, "call", { RL_DEST_CALL_PER_HOUR: "21" })).status).toBe(429);
    });

    it("alerts: each proven device's ceiling is its own", async () => {
      const a = randomToken();
      const credsA: string[] = [];
      for (let i = 0; i < 6; i++) credsA.push(((await (await post("/v1/register", await regBody(a))).json()) as Registered).credential);
      let alerts = 0;
      for (const c of credsA) if ((await credWake(c)).status === 202) alerts++;
      expect(alerts).toBe(DEFAULT_LIMITS.messageBurst * DEFAULT_LIMITS.destMessageFactor);
      // Another device, and the raw path for the same token, are not counted under it.
      expect((await credWake((await registerDevice()).credential)).status).toBe(202);
      expect((await wake({ token: a, kind: "message", topic: TOPIC }, withSecret())).status).toBe(202);
    });

    it("every push for a credential carries its registration id as skwod_cred; raw wakes carry none", async () => {
      const voip = randomToken();
      const mine = await registerDevice({ voip_token: voip, tag: TAG });
      const theirs = await registerDevice({ voip_token: voip }); // someone else's credential naming my VoIP token
      // The id: 16 bytes, base64url — the same id the revoke token carries, so nothing new is learnt.
      expect(mine.id).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(theirs.id).not.toBe(mine.id);
      expect(b64urlEncode(b64urlDecode(mine.revoke.slice(3)).subarray(0, 16))).toBe(mine.id);
      // The skwod cannot read it out of what it holds.
      expect(mine.credential).not.toContain(mine.id);

      expect((await credWake(mine.credential, "call")).status).toBe(202);
      expect((await credWake(theirs.credential, "call")).status).toBe(202);
      expect((await credWake(mine.credential, "message")).status).toBe(202);
      expect((await wake({ token: voip, kind: "call", topic: TOPIC }, withSecret())).status).toBe(202);
      expect((await wake({ token: mine.apns, kind: "message", topic: TOPIC, tag: TAG }, withSecret())).status).toBe(202);
      const bodies = seen.map((r) => JSON.parse(r.body) as Record<string, unknown>);
      // Both rings went to the same VoIP token; the app tells them apart by the id alone.
      expect(seen[0]!.url).toBe(seen[1]!.url);
      expect(bodies[0]).toEqual({ aps: {}, kind: "call", tag: TAG, skwod_cred: mine.id });
      expect(bodies[1]).toEqual({ aps: {}, kind: "call", skwod_cred: theirs.id });
      expect(bodies[2]!["skwod_cred"]).toBe(mine.id);
      expect(bodies[2]!["tag"]).toBe(TAG);
      // Raw wakes: no id, and a caller cannot supply one.
      expect(seen[3]!.body).toBe(CALL_PAYLOAD);
      expect("skwod_cred" in bodies[4]!).toBe(false);
      expect((await wake({ token: voip, kind: "call", topic: TOPIC, skwod_cred: mine.id }, withSecret())).status).toBe(400);
      expect((await wake({ credential: mine.credential, kind: "call", skwod_cred: theirs.id }, withSecret())).status).toBe(400);

      // A renewal is a NEW credential: its own id, its own expiry — the old one's is not moved.
      const before = (await allRows()).live.find((l) => l["c"] === mine.liveKey)!;
      const renewal = await post("/v1/register", { apns_token: mine.apns, voip_token: voip, topic: TOPIC, tag: TAG, revoke: mine.revoke }, { CRED_TTL_DAYS: "7" });
      const renewed = (await renewal.json()) as Registered;
      expect(renewed.id).not.toBe(mine.id);
      expect(renewed.expires_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 7 * 86_400);
      expect(renewed.expires_at).toBeLessThan(mine.expires_at);
      const rows = await allRows();
      expect(rows.live.find((l) => l["c"] === mine.liveKey)).toEqual(before);
      expect(before["until"]).toBe(mine.expires_at * 1000);
      expect(rows.live.filter((l) => l["t"] === before["t"])).toHaveLength(2);
    });

    describe("each decision is one step in the limiter (concurrent requests)", () => {
      const statuses = async (requests: Promise<Response>[]) => (await Promise.all(requests)).map((r) => r.status).sort();
      const count = (all: number[], status: number) => all.filter((s) => s === status).length;

      it("one challenge, used many times at once: one use", async () => {
        const apns = randomToken();
        const body = await regBody(apns);
        const all = await statuses(Array.from({ length: 12 }, () => post("/v1/register", body)));
        expect(count(all, 200)).toBe(1);
        expect(count(all, 403)).toBe(11);
        let rows = await allRows();
        expect(rows.live).toHaveLength(1);
        expect(rows.mints).toHaveLength(1);

        // The same for register against revoke-all: whichever lands first uses it.
        const c = await challengeFor(apns);
        const both = await statuses([
          post("/v1/revoke-all", { apns_token: apns, topic: TOPIC, challenge: c }),
          post("/v1/register", { apns_token: apns, voip_token: null, topic: TOPIC, challenge: c }),
          post("/v1/revoke-all", { apns_token: apns, topic: TOPIC, challenge: c }),
        ]);
        expect(both).toEqual([200, 403, 403]);
        rows = await allRows();
        expect(rows.spent).toHaveLength(2);
      });

      it("the mint cap and the live cap hold under concurrent registrations", async () => {
        const apns = randomToken();
        const capped = { RL_REGISTER_PER_DAY: "3" };
        const bodies = await Promise.all(Array.from({ length: 10 }, () => regBody(apns)));
        const all = await statuses(bodies.map((b) => post("/v1/register", b, capped)));
        expect(count(all, 200)).toBe(3);
        expect(count(all, 429)).toBe(7);
        let rows = await allRows();
        expect(rows.mints).toHaveLength(3);
        expect(rows.live).toHaveLength(3);
        // A challenge refused for the cap was not used up: it registers once the cap allows.
        expect(rows.spent).toHaveLength(3);
        expect(count(await statuses(bodies.map((b) => post("/v1/register", b, { RL_REGISTER_PER_DAY: "4" }))), 200)).toBe(1);

        const other = randomToken();
        const few = { LIVE_CREDENTIALS_PER_TOKEN: "2" };
        const many = await Promise.all(Array.from({ length: 8 }, () => regBody(other)));
        const responses = await Promise.all(many.map((b) => post("/v1/register", b, few)));
        expect(responses.every((r) => r.status === 200)).toBe(true);
        const minted = (await Promise.all(responses.map((r) => r.json()))) as Registered[];
        rows = await allRows();
        const otherLive = await limiterKey(liveKeyInput(other), SALT);
        expect(rows.live.filter((l) => l["t"] === otherLive)).toHaveLength(2);
        expect(rows.revoked).toHaveLength(6);
        // Exactly the two outstanding ones wake.
        let alive = 0;
        for (const m of minted) if ((await credWake(m.credential, "call")).status === 202) alive++;
        expect(alive).toBe(2);
      });

      it("concurrent challenge requests for one token push once; concurrent rings stop at the device's ceiling", async () => {
        const apns = randomToken();
        const all = await statuses(Array.from({ length: 25 }, () => post("/v1/challenge", { apns_token: apns, topic: TOPIC })));
        expect(all.every((s) => s === 202)).toBe(true);
        expect(seen).toHaveLength(1);
        const rows = await allRows();
        expect(rows.mints).toHaveLength(1);
        expect(rows.pending).toHaveLength(1);

        // A push APNs refuses is taken back, whoever else was waiting on it.
        const flaky = randomToken();
        respond = apnsError(500, "InternalServerError");
        const failed = await statuses(Array.from({ length: 5 }, () => post("/v1/challenge", { apns_token: flaky, topic: TOPIC })));
        expect(count(failed, 503)).toBeGreaterThanOrEqual(1);
        expect((await allRows()).pending).toHaveLength(1);
        respond = () => new Response(null, { status: 200 });

        seen.length = 0;
        const voip = randomToken();
        const creds: string[] = [];
        const device = randomToken();
        for (let i = 0; i < 4; i++) creds.push((await registerDevice({ apns_token: device, voip_token: voip })).credential);
        const rings = await statuses(Array.from({ length: 24 }, (_x, i) => credWake(creds[i % 4]!, "call")));
        expect(count(rings, 202)).toBe(DEFAULT_LIMITS.destCallPerMinute);
        expect(count(rings, 429)).toBe(24 - DEFAULT_LIMITS.destCallPerMinute);
        expect(seen).toHaveLength(DEFAULT_LIMITS.destCallPerMinute);
      });

      it("revoke-all against a concurrent renewal: nothing minted before the cut survives it", async () => {
        const a = await registerDevice();
        await new Promise((r) => setTimeout(r, 3));
        const responses = await Promise.all([
          ...Array.from({ length: 4 }, () => post("/v1/register", { apns_token: a.apns, voip_token: a.voip, topic: TOPIC, revoke: a.revoke })),
          post("/v1/revoke-all", { apns_token: a.apns, topic: TOPIC, revoke: a.revoke }),
          ...Array.from({ length: 4 }, () => post("/v1/register", { apns_token: a.apns, voip_token: a.voip, topic: TOPIC, revoke: a.revoke })),
        ]);
        expect(responses[4]!.status).toBe(200);
        // Each renewal either landed before the cut (and its credential is now dead) or after it
        // (and was refused: the revoke token stopped being proof). None is alive.
        const rows = await allRows();
        expect(rows.live).toEqual([]);
        for (const [i, res] of responses.entries()) {
          if (i === 4) continue;
          expect([200, 403]).toContain(res.status);
          if (res.status === 200) expect((await credWake(((await res.json()) as Registered).credential)).status).toBe(410);
        }
        // Cut, register, cut again with the clock standing still (here: the first cut recorded
        // ahead of the clock): the second cut still ends the credential minted between them.
        await runInDurableObject(limiterStub(), (_i, state) => {
          state.storage.sql.exec("UPDATE cutoff SET before = ?", Date.now() + 5000);
        });
        const between = await registerDevice({ apns_token: a.apns, voip_token: a.voip });
        expect((await credWake(between.credential)).status).toBe(202);
        expect((await post("/v1/revoke-all", { apns_token: a.apns, topic: TOPIC, revoke: between.revoke })).status).toBe(200);
        expect((await credWake(between.credential)).status).toBe(410);
        expect((await credWake((await registerDevice({ apns_token: a.apns, voip_token: a.voip })).credential)).status).toBe(202);
        await runInDurableObject(limiterStub(), (_i, state) => {
          state.storage.sql.exec("UPDATE cutoff SET before = ?", Date.now() - 10);
          state.storage.sql.exec("UPDATE live SET issued = ?", Date.now() - 5);
        });
        // And a credential minted in the same millisecond as the cut, after it, is alive.
        for (let i = 0; i < 5; i++) {
          const [cut, fresh] = [
            await post("/v1/revoke-all", { apns_token: a.apns, topic: TOPIC, challenge: await challengeFor(a.apns) }),
            await post("/v1/register", await regBody(a.apns, a.voip)),
          ];
          expect(cut.status).toBe(200);
          expect((await credWake(((await fresh.json()) as Registered).credential, i % 2 ? "call" : "message", { RL_DEST_CALL_PER_MINUTE: "100", RL_DEST_MESSAGE_FACTOR: "100" })).status).toBe(202);
        }
      });
    });

    it("register is refused without a challenge, or with a forged, expired, reused or someone else's", async () => {
      const apns = randomToken();
      const base = { apns_token: apns, voip_token: null, topic: TOPIC };
      // None at all: not even the right shape.
      expect((await post("/v1/register", base)).status).toBe(400);
      expect((await post("/v1/register", { ...base, challenge: "" })).status).toBe(400);
      // Forged.
      expect((await post("/v1/register", { ...base, challenge: `c1.${"A".repeat(75)}` })).status).toBe(403);
      const good = await challengeFor(apns);
      const body = good.slice(3);
      for (const i of [0, 30, body.length - 2]) {
        const forged = `c1.${body.slice(0, i)}${body[i] === "A" ? "B" : "A"}${body.slice(i + 1)}`;
        expect((await post("/v1/register", { ...base, challenge: forged })).status).toBe(403);
      }
      // Issued under another gateway's secret.
      const foreign = await mintChallenge("another-gateway-secret-0123456789abcdef!!", apns);
      expect((await post("/v1/register", { ...base, challenge: foreign })).status).toBe(403);
      // Pushed to ANOTHER token: knowing a victim's token and owning a device of one's own is not enough.
      const mine = randomToken();
      expect((await post("/v1/register", { ...base, challenge: await challengeFor(mine) })).status).toBe(403);
      // Expired.
      const old = await challengeFor(apns, Date.now() - CHALLENGE_TTL_MS - 1000);
      expect((await post("/v1/register", { ...base, challenge: old })).status).toBe(403);
      // Nothing was minted or counted by any of that.
      let rows = await allRows();
      expect(rows.mints).toEqual([]);
      expect(rows.live).toEqual([]);

      // The real one works once…
      expect((await post("/v1/register", { ...base, challenge: good })).status).toBe(200);
      // …and only once.
      const again = await post("/v1/register", { ...base, challenge: good });
      expect(again.status).toBe(403);
      expect(await again.json()).toEqual({ ok: false, error: "forbidden" });
      rows = await allRows();
      expect(rows.mints).toHaveLength(1);
      expect(rows.spent).toHaveLength(1);
      expect(JSON.stringify(rows.spent)).not.toContain(body.slice(0, 20));
      // Used challenges are forgotten once they would have expired anyway.
      await runInDurableObject(limiterStub(), (_i, state) => {
        state.storage.sql.exec("UPDATE spent SET until = ?", Date.now() - 1);
      });
      await runDurableObjectAlarm(limiterStub());
      expect((await allRows()).spent).toEqual([]);
    });

    it("revoke-all ends every credential minted before it, and none minted after", async () => {
      const a = await registerDevice();
      const b = await registerDevice({ apns_token: a.apns, voip_token: a.voip });
      const bystander = await registerDevice();
      expect((await credWake(a.credential)).status).toBe(202);
      await new Promise((r) => setTimeout(r, 3));

      const res = await post("/v1/revoke-all", { apns_token: a.apns, topic: TOPIC, challenge: await challengeFor(a.apns) });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true });
      const asked = seen.length;
      for (const c of [a.credential, b.credential]) {
        for (const kind of ["message", "call"] as const) {
          const woken = await credWake(c, kind);
          expect(woken.status).toBe(410);
          expect(await woken.json()).toEqual({ ok: false, error: "gone" });
        }
      }
      expect(seen).toHaveLength(asked);
      // Another phone is untouched.
      expect((await credWake(bystander.credential)).status).toBe(202);

      // A registration made afterwards works.
      await new Promise((r) => setTimeout(r, 3));
      const fresh = await registerDevice({ apns_token: a.apns, voip_token: a.voip });
      expect((await credWake(fresh.credential)).status).toBe(202);
      expect((await credWake(a.credential)).status).toBe(410);

      const rows = await allRows();
      expect(rows.cutoff).toHaveLength(1); // keyed on the APNs token alone
      expect(JSON.stringify(rows.cutoff)).not.toContain(a.apns);
      expect(JSON.stringify(rows.cutoff)).not.toContain(a.voip);
      expect(rows.live).toHaveLength(2); // the bystander's and the fresh one
    });

    it("revoke-all needs proof of the token: no challenge, a wrong one or a used one does nothing", async () => {
      const a = await registerDevice();
      const base = { apns_token: a.apns, topic: TOPIC };
      expect((await post("/v1/revoke-all", base)).status).toBe(400);
      expect((await post("/v1/revoke-all", { ...base, challenge: `c1.${"A".repeat(75)}` })).status).toBe(403);
      expect((await post("/v1/revoke-all", { ...base, challenge: await challengeFor(randomToken()) })).status).toBe(403);
      expect((await post("/v1/revoke-all", { ...base, challenge: await challengeFor(a.apns, Date.now() - CHALLENGE_TTL_MS - 1) })).status).toBe(403);
      // The credential and the revoke token are not proof either.
      expect((await post("/v1/revoke-all", { ...base, challenge: a.credential })).status).toBe(400);
      expect((await post("/v1/revoke-all", { ...base, challenge: a.revoke })).status).toBe(400);
      expect((await post("/v1/revoke-all", { ...base, topic: "com.attacker.app", challenge: await challengeFor(a.apns) })).status).toBe(403);
      expect((await allRows()).cutoff).toEqual([]);
      expect((await credWake(a.credential)).status).toBe(202);
      // A challenge already spent on a registration cannot be replayed here.
      const used = await challengeFor(a.apns);
      expect((await post("/v1/register", { apns_token: a.apns, voip_token: null, topic: TOPIC, challenge: used })).status).toBe(200);
      expect((await post("/v1/revoke-all", { ...base, challenge: used })).status).toBe(403);
      expect((await allRows()).cutoff).toEqual([]);
    });
  });

  it("logs nothing on the credential paths", async () => {
    const methods = ["log", "info", "warn", "error", "debug", "trace"] as const;
    const spies = methods.map((m) => vi.spyOn(console, m));
    const reg = await registerDevice({ tag: TAG });
    await credWake(reg.credential);
    await credWake(reg.credential);
    await credWake(`w1.${"A".repeat(120)}`);
    respond = () => {
      throw new Error(`connect failed for ${reg.apns}`);
    };
    await credWake(reg.credential, "call");
    await post("/v1/revoke", { revoke: reg.revoke });
    await post("/v1/revoke", { revoke: `r1.${"A".repeat(75)}` });
    await post("/v1/register", "{nope");
    await post("/v1/challenge", { apns_token: reg.apns, topic: TOPIC });
    await post("/v1/register", { ...(await regBody(reg.apns)), challenge: `c1.${"A".repeat(75)}` });
    await post("/v1/revoke-all", { apns_token: reg.apns, topic: TOPIC, challenge: await challengeFor(reg.apns) });
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });
});

describe("logging", () => {
  it("logs nothing at all on success and failure paths", async () => {
    const methods = ["log", "info", "warn", "error", "debug", "trace"] as const;
    const spies = methods.map((m) => vi.spyOn(console, m));
    const token = randomToken();
    const msg = { token, kind: "message", topic: TOPIC };
    const noBurst = { RL_MESSAGE_BURST: "100" };

    expect((await wake(msg, noBurst)).status).toBe(202);
    expect((await wake({ ...msg, kind: "call" })).status).toBe(202);
    // Dead-token paths go through their own tokens: a dead token is negative-cached.
    respond = apnsError(410, "Unregistered");
    expect((await wake({ ...msg, token: token.replace(/^./, (c) => (c === "0" ? "1" : "0")) })).status).toBe(410);
    respond = apnsError(400, "BadDeviceToken");
    expect((await wake({ ...msg, token: token.replace(/.$/, (c) => (c === "0" ? "1" : "0")) })).status).toBe(410);
    respond = apnsError(403, "InvalidProviderToken");
    expect((await wake(msg, noBurst)).status).toBe(503);
    respond = apnsError(500, "InternalServerError");
    expect((await wake(msg, noBurst)).status).toBe(503);
    respond = () => {
      throw new Error(`connect failed for ${token}`);
    };
    expect((await wake(msg, noBurst)).status).toBe(503);
    expect((await wake(msg)).status).toBe(429);
    expect((await wake({ ...msg, topic: "com.attacker.app" })).status).toBe(403);
    expect((await wake({ ...msg, extra: token })).status).toBe(400);
    expect((await wake(`{"token":"${token}"`)).status).toBe(400);
    expect((await wake(msg, { ...noBurst, APNS_KEY_P8: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" })).status).toBe(503);
    expect((await wake(msg, { APNS_TEAM_ID: "" })).status).toBe(503);
    expect((await wake(msg, { ...noBurst, RATE_LIMITER: undefined as never })).status).toBe(503);

    for (const spy of spies) {
      for (const call of spy.mock.calls) {
        expect(call.map((arg) => (arg instanceof Error ? `${arg.message} ${arg.stack}` : JSON.stringify(arg))).join(" ")).not.toContain(token);
      }
      expect(spy).not.toHaveBeenCalled();
    }
  });
});
