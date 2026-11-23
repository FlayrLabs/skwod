import type { RateLimiter } from "./ratelimit";

export interface Env {
  RATE_LIMITER: DurableObjectNamespace<RateLimiter>;

  // [vars]
  ALLOWED_TOPICS?: string;
  APNS_HOST?: string;
  APNS_SANDBOX_HOST?: string;
  RL_MESSAGE_BURST?: string;
  RL_MESSAGE_BURST_WINDOW_S?: string;
  RL_MESSAGE_PER_10MIN?: string;
  RL_MESSAGE_PER_HOUR?: string;
  RL_CALL_PER_MINUTE?: string;
  RL_GLOBAL_PER_MINUTE?: string;
  /** Registrations (credentials minted) per proven APNs token per day. */
  RL_REGISTER_PER_DAY?: string;
  /** Per-device ceilings, shared by every credential and raw wake for one token. */
  RL_DEST_MESSAGE_FACTOR?: string;
  RL_DEST_CALL_PER_MINUTE?: string;
  /** Rings per VoIP token per hour, across every credential naming it and the raw path. */
  RL_DEST_CALL_PER_HOUR?: string;
  /** Registration challenges pushed per APNs token. */
  RL_CHALLENGE_PER_10MIN?: string;
  RL_CHALLENGE_PER_DAY?: string;
  /** Outstanding credentials per APNs token before the oldest is evicted. */
  LIVE_CREDENTIALS_PER_TOKEN?: string;
  /** Lifetime of a wake credential, in days. */
  CRED_TTL_DAYS?: string;
  /** Requests per minute from one source address: `/v1/wake`, and the device routes together. "0" = off. */
  RL_SOURCE_WAKE_PER_MINUTE?: string;
  RL_SOURCE_DEVICE_PER_MINUTE?: string;
  /** "0" refuses the legacy raw-token wake shape. Anything else (or unset) accepts it. */
  LEGACY_RAW_WAKES?: string;

  // secrets
  APNS_KEY_P8?: string;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  /** Keys every stored row (>= 16 characters). REQUIRED: without it every route but /health answers 503. */
  RATE_KEY_SALT?: string;
  /** Seals wake credentials (>= 32 characters). Without it only legacy raw wakes work. */
  WAKE_CRED_SECRET?: string;
}
