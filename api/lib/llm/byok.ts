import { createDecipheriv, randomUUID } from "node:crypto";

import type { LLMProvider } from "./types.js";
import { normalizeEnvString } from "./env.js";

const DEFAULT_REDIS_KEY_PREFIX = "hive:byok";
const REDIS_URL_ENV_CANDIDATES = ["HIVEMOOT_REDIS_REST_URL"] as const;
const REDIS_TOKEN_ENV_CANDIDATES = ["HIVEMOOT_REDIS_REST_TOKEN"] as const;
const MASTER_KEYS_ENV = "BYOK_MASTER_KEYS";
const REDIS_KEY_PREFIX_ENV = "BYOK_REDIS_KEY_PREFIX";
const REDIS_FETCH_TIMEOUT_MS = 5000;

interface RedisRuntimeConfig {
  url: string;
  token: string;
  keyPrefix: string;
}

interface BYOKEnvelope {
  ciphertext: string;
  iv: string;
  tag: string;
  keyVersion: string;
  provider?: string;
  model?: string;
  status?: string;
}

interface BYOKPayload {
  apiKey: string;
  provider?: string;
  model?: string;
}

export interface InstallationBYOKConfig {
  provider: LLMProvider;
  model?: string;
  apiKey: string;
}

interface BYOKErrorContext {
  installationId: number;
  correlationId: string;
}

function readFirstEnv(names: readonly string[]): string | undefined {
  for (const name of names) {
    const value = normalizeEnvString(process.env[name]);
    if (value !== undefined) {
      return value;
    }
  }
  return undefined;
}

function getRedisRuntimeConfig(): RedisRuntimeConfig | null {
  const url = readFirstEnv(REDIS_URL_ENV_CANDIDATES);
  const token = readFirstEnv(REDIS_TOKEN_ENV_CANDIDATES);

  if (!url && !token) {
    return null;
  }

  if (!url || !token) {
    throw new Error(
      "BYOK Redis runtime is misconfigured: set both HIVEMOOT_REDIS_REST_URL and HIVEMOOT_REDIS_REST_TOKEN"
    );
  }

  const keyPrefix = normalizeEnvString(process.env[REDIS_KEY_PREFIX_ENV]) ?? DEFAULT_REDIS_KEY_PREFIX;

  return {
    url: url.replace(/\/+$/, ""),
    token,
    keyPrefix,
  };
}

function parseProvider(raw: unknown): LLMProvider {
  if (typeof raw !== "string") {
    throw new Error("BYOK provider is missing");
  }

  const normalized = raw.trim().toLowerCase();
  switch (normalized) {
    case "anthropic":
    case "openai":
    case "google":
    case "openrouter":
      return normalized;
    case "gemini":
      return "google";
    default:
      throw new Error(`Unsupported BYOK provider: ${raw}`);
  }
}

function parseMasterKeysFromEnv(): ReadonlyMap<string, Buffer> {
  const raw = normalizeEnvString(process.env[MASTER_KEYS_ENV]);
  if (!raw) {
    throw new Error(`BYOK master keys are not configured: set ${MASTER_KEYS_ENV}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${MASTER_KEYS_ENV} must be valid JSON`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${MASTER_KEYS_ENV} must be a JSON object keyed by keyVersion`);
  }

  const result = new Map<string, Buffer>();
  for (const [version, encodedKey] of Object.entries(parsed)) {
    if (typeof encodedKey !== "string" || encodedKey.trim().length === 0) {
      throw new Error(`${MASTER_KEYS_ENV}.${version} must be a non-empty 64-char hex string`);
    }

    if (!/^[0-9a-f]{64}$/i.test(encodedKey.trim())) {
      throw new Error(`${MASTER_KEYS_ENV}.${version} must be a 64-char hex string (got ${encodedKey.trim().length} chars)`);
    }

    const key = Buffer.from(encodedKey, "hex");
    if (key.length !== 32) {
      throw new Error(`${MASTER_KEYS_ENV}.${version} must decode to 32 bytes for AES-256-GCM`);
    }
    result.set(version, key);
  }

  if (result.size === 0) {
    throw new Error(`${MASTER_KEYS_ENV} must include at least one key version`);
  }

  return result;
}

let _masterKeysCache: ReadonlyMap<string, Buffer> | undefined;

function parseMasterKeys(): ReadonlyMap<string, Buffer> {
  return (_masterKeysCache ??= parseMasterKeysFromEnv());
}

/** Reset the master keys cache. Intended for use in tests only. */
export function _resetMasterKeysCache(): void {
  _masterKeysCache = undefined;
}

function withBYOKContext(
  error: unknown,
  context: BYOKErrorContext,
): Error & BYOKErrorContext {
  return Object.assign(
    error instanceof Error ? error : new Error(String(error)),
    context,
  );
}

function decodeBase64Field(
  fieldName: string,
  value: string,
  context: BYOKErrorContext,
): Buffer {
  try {
    const decoded = Buffer.from(value, "base64");
    if (decoded.length === 0) {
      throw new Error();
    }
    return decoded;
  } catch {
    throw withBYOKContext(
      new Error(`BYOK envelope field '${fieldName}' is not valid base64`),
      context,
    );
  }
}

function parseEnvelope(
  rawEnvelope: string,
  context: BYOKErrorContext,
): BYOKEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawEnvelope);
  } catch {
    throw withBYOKContext(new Error("BYOK envelope is not valid JSON"), context);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw withBYOKContext(
      new Error("BYOK envelope must be a JSON object"),
      context,
    );
  }

  const envelope = parsed as Partial<BYOKEnvelope>;

  if (
    typeof envelope.ciphertext !== "string" ||
    typeof envelope.iv !== "string" ||
    typeof envelope.tag !== "string" ||
    typeof envelope.keyVersion !== "string"
  ) {
    throw withBYOKContext(
      new Error("BYOK envelope is missing required fields"),
      context,
    );
  }

  return {
    ciphertext: envelope.ciphertext,
    iv: envelope.iv,
    tag: envelope.tag,
    keyVersion: envelope.keyVersion,
    provider: envelope.provider,
    model: envelope.model,
    status: envelope.status,
  };
}

function decryptEnvelope(
  envelope: BYOKEnvelope,
  masterKeys: ReadonlyMap<string, Buffer>,
  context: BYOKErrorContext,
): BYOKPayload {
  const key = masterKeys.get(envelope.keyVersion);
  if (!key) {
    throw withBYOKContext(
      new Error(`BYOK key version '${envelope.keyVersion}' is unavailable`),
      context,
    );
  }

  const iv = decodeBase64Field("iv", envelope.iv, context);
  if (iv.length !== 12) {
    throw withBYOKContext(
      new Error(
        `BYOK envelope IV must be 12 bytes (96 bits) for AES-256-GCM; got ${iv.length}`,
      ),
      context,
    );
  }

  const authTag = decodeBase64Field("tag", envelope.tag, context);
  const ciphertext = decodeBase64Field("ciphertext", envelope.ciphertext, context);

  let plaintext: string;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");
  } catch (error) {
    throw withBYOKContext(
      new Error("BYOK key material could not be decrypted", { cause: error }),
      context,
    );
  }

  let payload: unknown;
  try {
    payload = JSON.parse(plaintext);
  } catch {
    throw withBYOKContext(
      new Error("BYOK decrypted payload is not valid JSON"),
      context,
    );
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw withBYOKContext(
      new Error("BYOK decrypted payload must be a JSON object"),
      context,
    );
  }

  const byokPayload = payload as Partial<BYOKPayload>;
  if (typeof byokPayload.apiKey !== "string" || byokPayload.apiKey.trim().length === 0) {
    throw withBYOKContext(
      new Error("BYOK decrypted payload is missing apiKey"),
      context,
    );
  }

  return {
    apiKey: byokPayload.apiKey.trim(),
    provider: byokPayload.provider,
    model: byokPayload.model,
  };
}

async function fetchEnvelope(
  runtimeConfig: RedisRuntimeConfig,
  installationId: number,
  correlationId: string,
): Promise<BYOKEnvelope | null> {
  const context = { installationId, correlationId };
  const key = `${runtimeConfig.keyPrefix}:${installationId}`;
  const endpoint = `${runtimeConfig.url}/get/${encodeURIComponent(key)}`;

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${runtimeConfig.token}`,
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(REDIS_FETCH_TIMEOUT_MS),
    });
  } catch (error) {
    if (
      error instanceof Error &&
      (error.name === "AbortError" || error.name === "TimeoutError")
    ) {
      throw withBYOKContext(
        new Error(`BYOK Redis lookup timed out after ${REDIS_FETCH_TIMEOUT_MS}ms`),
        context,
      );
    }
    throw withBYOKContext(
      new Error("BYOK Redis network error", { cause: error }),
      context,
    );
  }

  if (!response.ok) {
    throw withBYOKContext(
      new Error(`BYOK Redis lookup failed with HTTP ${response.status}`),
      context,
    );
  }

  let body: { result?: unknown; error?: unknown };
  try {
    body = (await response.json()) as typeof body;
  } catch {
    throw withBYOKContext(
      new Error(`BYOK Redis REST response is not valid JSON (HTTP ${response.status})`),
      context,
    );
  }
  if (typeof body.error === "string" && body.error.length > 0) {
    throw withBYOKContext(
      new Error(`BYOK Redis returned an error for installation ${installationId}`),
      context,
    );
  }

  if (!Object.prototype.hasOwnProperty.call(body, "result")) {
    throw withBYOKContext(
      new Error("BYOK Redis response is missing the 'result' field"),
      context,
    );
  }

  if (body.result === null) {
    return null;
  }

  if (typeof body.result !== "string") {
    throw withBYOKContext(
      new Error("BYOK Redis returned an unexpected result payload"),
      context,
    );
  }

  return parseEnvelope(body.result, context);
}

export function formatBYOKErrorContext(error: unknown): string {
  if (error === null || typeof error !== "object") {
    return "";
  }

  const record = error as Record<string, unknown>;
  const parts: string[] = [];
  if (typeof record.installationId === "number") {
    parts.push(`installationId=${record.installationId}`);
  }
  if (typeof record.correlationId === "string") {
    parts.push(`correlationId=${record.correlationId}`);
  }

  return parts.length > 0 ? ` [${parts.join(" ")}]` : "";
}

/**
 * Resolve BYOK config for an installation from encrypted Redis records.
 *
 * Returns null when BYOK is not configured for the installation, and throws
 * when BYOK material exists but cannot be validated/decrypted (fail-closed).
 */
export async function resolveInstallationBYOKConfig(
  installationId: number
): Promise<InstallationBYOKConfig | null> {
  const correlationId = randomUUID();
  const context = { installationId, correlationId };
  const runtimeConfig = getRedisRuntimeConfig();
  if (!runtimeConfig) {
    return null;
  }

  const envelope = await fetchEnvelope(runtimeConfig, installationId, correlationId);
  if (!envelope) {
    return null;
  }

  if (envelope.status === "revoked") {
    return null;
  }

  if (envelope.status !== "active") {
    const status = envelope.status ?? "missing";
    throw withBYOKContext(
      new Error(
        `BYOK record for installation ${installationId} is not active (status=${status})`,
      ),
      context,
    );
  }

  const masterKeys = parseMasterKeys();
  const decrypted = decryptEnvelope(envelope, masterKeys, context);

  try {
    return {
      apiKey: decrypted.apiKey,
      provider: parseProvider(decrypted.provider),
      model: normalizeEnvString(decrypted.model),
    };
  } catch (error) {
    throw withBYOKContext(error, context);
  }
}
