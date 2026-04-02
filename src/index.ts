/**
 * @newtype-ai/nit-sdk — Verify agent identity with one function call.
 *
 * Apps receive a login payload from an agent (via nit) and call
 * verifyAgent() to confirm the agent's identity. No crypto needed.
 */

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
}

export interface FetchCardOptions {
  /** Override the base URL for agent card hosting. Defaults to https://agent-{agent_id}.newtype-ai.org */
  baseUrl?: string;
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
  const apiUrl = options?.apiUrl ?? DEFAULT_API_URL;

  const res = await fetch(`${apiUrl}/agent-card/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agent_id: payload.agent_id,
      domain: payload.domain,
      timestamp: payload.timestamp,
      signature: payload.signature,
      ...(options?.policy ? { policy: options.policy } : {}),
    }),
  });

  return res.json() as Promise<VerifyResult>;
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
  const baseUrl =
    options?.baseUrl ?? `https://agent-${agentId}.newtype-ai.org`;
  const url = `${baseUrl}/.well-known/agent-card.json?branch=${encodeURIComponent(domain)}`;

  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${readToken}` },
  });

  if (!res.ok) return null;
  return res.json() as Promise<AgentCard>;
}
