/**
 * crypto.ts — Signing, tx construction, and canonical JSON for Nova Network.
 *
 * All transactions use Ed25519 signatures over canonical JSON (keys sorted
 * alphabetically, no extra spaces).
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { bytesToHex, bytesToBase64, hexToBytes, base64ToBytes } from "./wallet.js";
import type { Wallet } from "./wallet.js";

// ── Canonical JSON ───────────────────────────────────────────────────────────

/**
 * Produce canonical JSON: keys sorted alphabetically at every level, no
 * extra whitespace. Arrays preserve insertion order (per spec).
 */
export function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJson).join(",") + "]";
  }
  const sorted = Object.keys(obj as Record<string, unknown>).sort();
  const parts = sorted.map(
    (k) => JSON.stringify(k) + ":" + canonicalJson((obj as Record<string, unknown>)[k])
  );
  return "{" + parts.join(",") + "}";
}

// ── Address derivation ───────────────────────────────────────────────────────

/**
 * Derive a Nova Network address from a base64-encoded public key.
 * Address = 'W' + first 40 hex chars of sha256(canonical_json(pubkey_object))
 */
export function deriveAddress(base64PublicKey: string): string {
  const pubkeyObj = { key: base64PublicKey, kty: "ed25519" };
  const canonical = canonicalJson(pubkeyObj);
  const hash = sha256(new TextEncoder().encode(canonical));
  const hex = bytesToHex(hash);
  return ("W" + hex).slice(0, 41);
}

// ── Signing ──────────────────────────────────────────────────────────────────

/**
 * Sign a canonical JSON payload with the given hex private key.
 * Returns the base64-encoded signature.
 */
export async function signPayload(
  payload: Record<string, unknown>,
  privateKeyHex: string
): Promise<string> {
  const canonical = canonicalJson(payload);
  const msgBytes = new TextEncoder().encode(canonical);
  const privBytes = hexToBytes(privateKeyHex);
  const sigBytes = await ed.signAsync(msgBytes, privBytes);
  return bytesToBase64(sigBytes);
}

// ── Nonce & ID helpers ───────────────────────────────────────────────────────

/** Generate a cryptographically random 8-byte hex nonce. */
export function makeNonce(): string {
  return bytesToHex(randomBytes(8));
}

/**
 * Compute the transaction ID: sha256 of the full transaction (including
 * pubkey and signature) as canonical JSON.
 */
export function makeTxId(tx: Record<string, unknown>): string {
  const canonical = canonicalJson(tx);
  const hash = sha256(new TextEncoder().encode(canonical));
  return bytesToHex(hash);
}

// ── Transaction types ────────────────────────────────────────────────────────

export interface ActivityLogOpts {
  agentId?: string;
  actionType: string;
  inputHash?: string;
  outputHash?: string;
  evidenceHash?: string;
  evidenceUrl?: string;
  success?: boolean;
  durationMs?: number;
  tags?: string[];
  platform?: string;
  externalRef?: string;
  note?: string;
  stakeLocked?: number;
}

export interface AttestOpts {
  logId: string;
  sentiment: string;
  note?: string;
}

export interface ChallengeOpts {
  logId: string;
  stakeLocked?: number;
  reason?: string;
}

/**
 * Build and sign an agent_activity_log transaction.
 *
 * The signable subset excludes: signer, id, pubkey, signature.
 */
export async function makeActivityLogTx(
  wallet: Wallet,
  opts: ActivityLogOpts
): Promise<Record<string, unknown>> {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = makeNonce();

  const signable: Record<string, unknown> = {
    action_type: opts.actionType,
    agent: wallet.address,
    agent_id: opts.agentId ?? "",
    duration_ms: opts.durationMs ?? 0,
    evidence_hash: opts.evidenceHash ?? "",
    evidence_url: opts.evidenceUrl ?? "",
    external_ref: opts.externalRef ?? "",
    input_hash: opts.inputHash ?? "",
    nonce,
    note: opts.note ?? "",
    output_hash: opts.outputHash ?? "",
    platform: opts.platform ?? "",
    schema_version: 1,
    stake_locked: opts.stakeLocked ?? 0.0,
    success: opts.success ?? true,
    tags: opts.tags ?? [],
    timestamp,
    type: "agent_activity_log",
  };

  const signature = await signPayload(signable, wallet.privateKey);

  const tx: Record<string, unknown> = {
    ...signable,
    id: "", // placeholder — will be replaced after id computation
    pubkey: { key: wallet.publicKey, kty: "ed25519" },
    signature,
    signer: wallet.address,
  };

  // Compute the final tx id (sha256 of the full canonical tx)
  tx.id = makeTxId(tx);

  return tx;
}

/**
 * Build and sign an agent_attest transaction.
 *
 * Signable subset: type, schema_version, attester, log_id, sentiment, note,
 * timestamp, nonce
 */
export async function makeAttestTx(
  wallet: Wallet,
  opts: AttestOpts
): Promise<Record<string, unknown>> {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = makeNonce();

  const signable: Record<string, unknown> = {
    attester: wallet.address,
    log_id: opts.logId,
    nonce,
    note: opts.note ?? "",
    schema_version: 1,
    sentiment: opts.sentiment,
    timestamp,
    type: "agent_attest",
  };

  const signature = await signPayload(signable, wallet.privateKey);

  const tx: Record<string, unknown> = {
    ...signable,
    id: "",
    pubkey: { key: wallet.publicKey, kty: "ed25519" },
    signature,
    signer: wallet.address,
  };

  tx.id = makeTxId(tx);
  return tx;
}

/**
 * Build and sign an agent_challenge transaction.
 *
 * Signable subset: type, schema_version, challenger, log_id, stake_locked,
 * reason, timestamp, nonce
 */
export async function makeChallengeTx(
  wallet: Wallet,
  opts: ChallengeOpts
): Promise<Record<string, unknown>> {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = makeNonce();

  const signable: Record<string, unknown> = {
    challenger: wallet.address,
    log_id: opts.logId,
    nonce,
    reason: opts.reason ?? "",
    schema_version: 1,
    stake_locked: opts.stakeLocked ?? 0.0,
    timestamp,
    type: "agent_challenge",
  };

  const signature = await signPayload(signable, wallet.privateKey);

  const tx: Record<string, unknown> = {
    ...signable,
    id: "",
    pubkey: { key: wallet.publicKey, kty: "ed25519" },
    signature,
    signer: wallet.address,
  };

  tx.id = makeTxId(tx);
  return tx;
}
