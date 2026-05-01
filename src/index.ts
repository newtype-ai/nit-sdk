/**
 * @newtype-ai/nit-sdk — Verify agent identity with one function call.
 *
 * Apps receive a login payload from an agent (via nit) and call
 * verifyAgent() to confirm the agent's identity. No crypto needed.
 */

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Typed error for HTTP and shape failures in the SDK. */
export class NitSdkError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = 'NitSdkError';
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const AGENT_ID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REF_NAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_AGENT_CARD_BYTES = 128 * 1024;

/** Throw if a user-supplied URL is not HTTPS (localhost exempt for dev). */
function assertHttps(url: string, label: string): void {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') return;
    if (
      parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')
    )
      return;
    throw new TypeError(
      `${label} must use HTTPS (got ${parsed.protocol}//${parsed.hostname})`,
    );
  } catch (e) {
    if (e instanceof TypeError) throw e;
    throw new TypeError(`${label} is not a valid URL: ${url}`);
  }
}

/** Validate the LoginPayload fields before sending to the server. */
function validatePayload(payload: LoginPayload): void {
  if (payload === null || typeof payload !== 'object') {
    throw new TypeError('payload must be an object');
  }
  validateAgentId(payload.agent_id, 'payload.agent_id');
  validateBranchName(payload.domain, 'payload.domain');
  if (
    typeof payload.timestamp !== 'number' ||
    !Number.isFinite(payload.timestamp) ||
    payload.timestamp <= 0
  ) {
    throw new TypeError('payload.timestamp must be a finite positive number');
  }
  if (typeof payload.signature !== 'string' || payload.signature.length === 0) {
    throw new TypeError('payload.signature must be a non-empty string');
  }
  if (strictBase64ByteLength(payload.signature) !== 64) {
    throw new TypeError('payload.signature must be a 64-byte standard base64 Ed25519 signature');
  }
  if (payload.public_key !== undefined) {
    validatePublicKeyField(payload.public_key, 'payload.public_key');
  }
}

function validateTimeoutMs(timeoutMs: number): void {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('timeoutMs must be a finite positive number');
  }
}

function validatePolicy(policy: VerifyPolicy | undefined): void {
  if (policy === undefined) return;
  if (policy === null || typeof policy !== 'object') {
    throw new TypeError('options.policy must be an object');
  }
  for (const [key, value] of Object.entries(policy)) {
    if (value !== undefined && (!Number.isFinite(value) || value < 0)) {
      throw new TypeError(`options.policy.${key} must be a non-negative finite number`);
    }
  }
}

/** Fetch with an AbortController timeout. */
function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  label = 'HTTP request',
): Promise<Response> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  return fetch(url, { ...init, signal: controller.signal })
    .catch((err) => {
      if (timedOut) {
        throw new NitSdkError(`${label} timed out after ${timeoutMs}ms`, 0);
      }
      throw err;
    })
    .finally(() => clearTimeout(timer));
}

async function readResponseText(
  res: Response,
  label: string,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
): Promise<string> {
  const length = res.headers.get('content-length');
  const parsedLength = length ? Number.parseInt(length, 10) : NaN;
  if (Number.isFinite(parsedLength) && parsedLength > maxBytes) {
    throw new NitSdkError(`${label} exceeds ${maxBytes} bytes`, 0);
  }

  if (!res.body) {
    const text = await res.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new NitSdkError(`${label} exceeds ${maxBytes} bytes`, 0);
    }
    return text;
  }

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new NitSdkError(`${label} exceeds ${maxBytes} bytes`, 0);
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

async function readResponseJson<T>(
  res: Response,
  label: string,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
): Promise<T> {
  const text = await readResponseText(res, label, maxBytes);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new NitSdkError(`${label} is not valid JSON`, 0);
  }
}

function validateAgentId(agentId: unknown, label: string): asserts agentId is string {
  if (typeof agentId !== 'string' || !AGENT_ID_RE.test(agentId)) {
    throw new TypeError(`${label} must be a UUIDv5 agent id`);
  }
}

function validateBranchName(name: unknown, label: string): asserts name is string {
  if (typeof name !== 'string' || name.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  if (name.length > 253) {
    throw new TypeError(`${label} cannot exceed 253 characters`);
  }
  if (/[\x00-\x1f\x7f]/.test(name)) {
    throw new TypeError(`${label} must not contain control characters`);
  }
  if (/[:/\\]/.test(name) || name.includes('..')) {
    throw new TypeError(`${label} contains unsafe characters`);
  }
  if (!REF_NAME_RE.test(name)) {
    throw new TypeError(`${label} must start and end with an alphanumeric character and contain only letters, digits, dots, underscores, or hyphens`);
  }
}

function strictBase64ByteLength(value: string): number | null {
  if (!BASE64_RE.test(value)) {
    return null;
  }
  try {
    const bin = atob(value);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const canonical = btoa(String.fromCharCode(...bytes));
    return canonical === value ? bytes.length : null;
  } catch {
    return null;
  }
}

function validatePublicKeyField(value: unknown, label: string): void {
  if (typeof value !== 'string' || !value.startsWith('ed25519:')) {
    throw new TypeError(`${label} must use ed25519:<base64> format`);
  }
  if (strictBase64ByteLength(value.slice('ed25519:'.length)) !== 32) {
    throw new TypeError(`${label} must contain a 32-byte standard base64 Ed25519 key`);
  }
}

function validateReadToken(token: unknown, label = 'readToken'): asserts token is string {
  if (typeof token !== 'string' || token.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  if (token.length > 4096) {
    throw new TypeError(`${label} is too long`);
  }
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new TypeError(`${label} must be a two-part signed token`);
  }
  if (!BASE64URL_RE.test(parts[0]) || !BASE64URL_RE.test(parts[1])) {
    throw new TypeError(`${label} must use base64url token encoding`);
  }
}

function assertString(value: unknown, label: string, required = true): string | undefined {
  if (value === undefined) {
    if (required) throw new NitSdkError(`Malformed response: ${label} is required`, 0);
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new NitSdkError(`Malformed response: ${label} must be a string`, 0);
  }
  return value;
}

function assertStringArray(value: unknown, label: string): void {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new NitSdkError(`Malformed response: ${label} must be a string array`, 0);
  }
}

function validateWallet(value: unknown, label: string): void {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new NitSdkError(`Malformed response: ${label} must be an object`, 0);
  }
  const wallet = value as Record<string, unknown>;
  assertString(wallet.solana, `${label}.solana`);
  assertString(wallet.evm, `${label}.evm`);
}

function validateAgentCard(card: unknown, label = 'agent card'): asserts card is AgentCard {
  if (card === null || typeof card !== 'object' || Array.isArray(card)) {
    throw new NitSdkError(`Malformed ${label} response`, 0);
  }
  const obj = card as Record<string, unknown>;
  assertString(obj.protocolVersion, `${label}.protocolVersion`);
  assertString(obj.name, `${label}.name`);
  assertString(obj.description, `${label}.description`);
  assertString(obj.version, `${label}.version`);
  assertString(obj.url, `${label}.url`);
  assertStringArray(obj.defaultInputModes, `${label}.defaultInputModes`);
  assertStringArray(obj.defaultOutputModes, `${label}.defaultOutputModes`);
  if (!Array.isArray(obj.skills)) {
    throw new NitSdkError(`Malformed response: ${label}.skills must be an array`, 0);
  }
  for (const [index, skill] of obj.skills.entries()) {
    if (skill === null || typeof skill !== 'object' || Array.isArray(skill)) {
      throw new NitSdkError(`Malformed response: ${label}.skills[${index}] must be an object`, 0);
    }
    assertString((skill as Record<string, unknown>).id, `${label}.skills[${index}].id`);
  }
  if (obj.publicKey !== undefined) {
    validatePublicKeyField(obj.publicKey, `${label}.publicKey`);
  }
  if (obj.wallet !== undefined) {
    validateWallet(obj.wallet, `${label}.wallet`);
  }
  if (obj.runtime !== undefined) {
    if (obj.runtime === null || typeof obj.runtime !== 'object' || Array.isArray(obj.runtime)) {
      throw new NitSdkError(`Malformed response: ${label}.runtime must be an object`, 0);
    }
    const runtime = obj.runtime as Record<string, unknown>;
    assertString(runtime.provider, `${label}.runtime.provider`);
    assertString(runtime.model, `${label}.runtime.model`);
    assertString(runtime.harness, `${label}.runtime.harness`);
    if (typeof runtime.declared_at !== 'number' || !Number.isFinite(runtime.declared_at)) {
      throw new NitSdkError(`Malformed response: ${label}.runtime.declared_at must be a finite number`, 0);
    }
  }
}

function validateVerifyResult(data: unknown): VerifyResult {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    return { verified: false, error: 'Malformed server response' };
  }
  const obj = data as Record<string, unknown>;
  if (typeof obj.verified !== 'boolean') {
    return { verified: false, error: 'Malformed server response (missing verified field)' };
  }
  if (!obj.verified) {
    return {
      verified: false,
      error: typeof obj.error === 'string' ? obj.error : 'Verification failed',
    };
  }
  try {
    validateAgentId(obj.agent_id, 'response.agent_id');
    validateBranchName(obj.domain, 'response.domain');
    validateBranchName(obj.branch, 'response.branch');
    validateReadToken(obj.readToken, 'response.readToken');
    if (typeof obj.admitted !== 'boolean') {
      throw new TypeError('response.admitted must be a boolean');
    }
    if (!('card' in obj)) {
      throw new TypeError('response.card is required');
    }
    if (obj.card !== null && obj.card !== undefined) {
      validateAgentCard(obj.card, 'response.card');
    }
    if (obj.wallet !== null && obj.wallet !== undefined) {
      validateWallet(obj.wallet, 'response.wallet');
    }
  } catch (err) {
    return {
      verified: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
  return data as VerifyResult;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The login payload an agent sends to your app. */
export interface LoginPayload {
  agent_id: string;
  domain: string;
  timestamp: number;
  signature: string;
  /** Agent's public key. Present in nit >= 0.6.0. */
  public_key?: string;
}

/** A skill listed in an agent's card. */
export interface AgentCardSkill {
  id: string;
  name?: string;
  description?: string;
  tags?: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
}

/** The agent's public identity card (A2A-compliant). */
export interface AgentCard {
  protocolVersion: string;
  name: string;
  description: string;
  version: string;
  url: string;
  defaultInputModes: string[];
  defaultOutputModes: string[];
  provider?: { organization: string; url?: string };
  skills: AgentCardSkill[];
  publicKey?: string;
  wallet?: { solana: string; evm: string };
  runtime?: {
    provider: string;
    model: string;
    harness: string;
    declared_at: number;
  };
  iconUrl?: string;
  documentationUrl?: string;
}

/** Identity metadata returned by the server. */
export interface IdentityMetadata {
  registration_timestamp: number | null;
  machine_identity_count: number;
  ip_identity_count: number;
  total_logins: number;
  last_login_timestamp: number | null;
  unique_domains: number;
  /** Country of last push (ISO 3166-1 alpha-2, e.g., "US"). Server-observed. */
  last_push_country: string | null;
  /** ASN of last push (e.g., "13335"). Server-observed. */
  last_push_asn: string | null;
  /** Number of unique IPs across all pushes. Server-observed. */
  unique_push_ips: number;
  /** Total number of pushes. Server-observed. */
  total_pushes: number;
  /** OS and architecture (e.g., "darwin-arm64"). Client-declared. */
  platform: string | null;
  /** SHA-256 of hostname. Client-declared. */
  hostname_hash: string | null;
  /** SHA-256 of workspace path. Client-declared. */
  workspace_hash: string | null;
  /** LLM provider self-declared by the agent (e.g., "anthropic"). Untrusted. */
  runtime_provider: string | null;
  /** Model self-declared by the agent (e.g., "claude-opus-4-6"). Untrusted. */
  runtime_model: string | null;
  /** Harness self-declared by the agent (e.g., "claude-code"). Untrusted. */
  runtime_harness: string | null;
  /** When the runtime was declared (unix seconds). */
  runtime_declared_at: number | null;
  /** Number of distinct runtime providers across all pushes. >1 means the agent changed providers — potential inconsistency signal. */
  distinct_runtime_providers: number;
}

/** App-defined trust policy. Server evaluates and returns admitted: true/false. */
export interface VerifyPolicy {
  max_identities_per_ip?: number;
  max_identities_per_machine?: number;
  min_age_seconds?: number;
  max_login_rate_per_hour?: number;
}

/** Server attestation proving the server endorsed this verification. */
export interface ServerAttestation {
  server_signature: string;
  server_url: string;
  server_public_key: string;
}

/** Successful verification result. */
export interface VerifySuccess {
  verified: true;
  /** Whether the identity meets the app's policy. True if no policy were specified. */
  admitted: boolean;
  agent_id: string;
  domain: string;
  card: AgentCard | null;
  /** Which branch the card came from — the domain branch if pushed, otherwise 'main'. */
  branch: string;
  /** Chain wallet addresses derived from the agent's Ed25519 keypair. */
  wallet?: { solana: string; evm: string } | null;
  /** HMAC-signed read token for fetching the agent's domain branch card. 30-day expiry. */
  readToken: string;
  /** Identity metadata — registration time, login count, machine/IP grouping, etc. */
  identity?: IdentityMetadata;
  /** Server attestation (if server signing key is configured). */
  attestation?: ServerAttestation;
}

/** Failed verification result. */
export interface VerifyFailure {
  verified: false;
  error: string;
}

export type VerifyResult = VerifySuccess | VerifyFailure;

export interface VerifyOptions {
  /** Override the API base URL. Defaults to https://api.newtype-ai.org */
  apiUrl?: string;
  /** App-defined trust policy. Server evaluates and returns admitted: true/false. */
  policy?: VerifyPolicy;
  /** Fetch timeout in milliseconds. Defaults to 10 000. */
  timeoutMs?: number;
}

export interface FetchCardOptions {
  /** Override the base URL for agent card hosting. Defaults to https://agent-{agent_id}.newtype-ai.org */
  baseUrl?: string;
  /** Fetch timeout in milliseconds. Defaults to 10 000. */
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

const DEFAULT_API_URL = 'https://api.newtype-ai.org';

/**
 * Verify an agent's login payload against the newtype-ai.org server.
 *
 * @example
 * ```ts
 * import { verifyAgent } from '@newtype-ai/nit-sdk';
 *
 * const result = await verifyAgent(payload);
 * if (result.verified) {
 *   console.log(`Agent ${result.agent_id} verified`);
 *   console.log(`Card:`, result.card);
 * }
 * ```
 */
export async function verifyAgent(
  payload: LoginPayload,
  options?: VerifyOptions,
): Promise<VerifyResult> {
  validatePayload(payload);

  const apiUrl = (options?.apiUrl ?? DEFAULT_API_URL).replace(/\/$/, '');
  if (options?.apiUrl) assertHttps(apiUrl, 'options.apiUrl');
  validatePolicy(options?.policy);

  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  validateTimeoutMs(timeoutMs);

  try {
    const res = await fetchWithTimeout(
      `${apiUrl}/agent-card/verify`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: payload.agent_id,
          domain: payload.domain,
          timestamp: payload.timestamp,
          signature: payload.signature,
          ...(options?.policy ? { policy: options.policy } : {}),
        }),
      },
      timeoutMs,
      'Agent verification request',
    );

    if (!res.ok) {
      return { verified: false, error: `Server error (HTTP ${res.status})` };
    }

    return validateVerifyResult(await readResponseJson<unknown>(res, 'Verify response'));
  } catch (err) {
    return {
      verified: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Fetch an agent's domain branch card using a read token.
 *
 * The read token is returned by verifyAgent() on successful verification.
 * It is scoped to a specific agent_id + domain and expires after 30 days.
 *
 * @example
 * ```ts
 * import { verifyAgent, fetchAgentCard } from '@newtype-ai/nit-sdk';
 *
 * const result = await verifyAgent(payload);
 * if (result.verified) {
 *   // Later, fetch the latest card:
 *   const card = await fetchAgentCard(result.agent_id, result.domain, result.readToken);
 * }
 * ```
 */
export async function fetchAgentCard(
  agentId: string,
  domain: string,
  readToken: string,
  options?: FetchCardOptions,
): Promise<AgentCard | null> {
  validateAgentId(agentId, 'agentId');
  validateBranchName(domain, 'domain');
  validateReadToken(readToken);

  const baseUrl =
    (options?.baseUrl ?? `https://agent-${agentId}.newtype-ai.org`).replace(/\/$/, '');
  if (options?.baseUrl) assertHttps(baseUrl, 'options.baseUrl');

  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  validateTimeoutMs(timeoutMs);
  const url = `${baseUrl}/.well-known/agent-card.json?branch=${encodeURIComponent(domain)}`;

  const res = await fetchWithTimeout(
    url,
    { headers: { Authorization: `Bearer ${readToken}` } },
    timeoutMs,
    'Agent card request',
  );

  // 404 → card not found (expected)
  if (res.status === 404) return null;

  // Other failures → throw so callers can distinguish auth/server errors
  if (!res.ok) {
    throw new NitSdkError(
      `Failed to fetch agent card (HTTP ${res.status})`,
      res.status,
    );
  }

  const data = await readResponseJson<unknown>(res, 'Agent card response', MAX_AGENT_CARD_BYTES);
  validateAgentCard(data);
  return data;
}
