/**
 * tracker.ts — NovaTracker: the main entry point for logging agent activity.
 *
 * Usage:
 *   const tracker = await NovaTracker.create("my-agent-id");
 *   const txId = await tracker.log("task_complete", { note: "done" });
 *   const result = await tracker.track("fetch_data", () => fetchSomething());
 */

import { loadOrCreateWallet, loadWallet } from "./wallet.js";
import {
  makeActivityLogTx,
  makeAttestTx,
  makeChallengeTx,
  type ActivityLogOpts,
  type AttestOpts,
  type ChallengeOpts,
} from "./crypto.js";
import type { Wallet } from "./wallet.js";

const DEFAULT_NODE_URL = "https://explorer.flowpe.io";
const DEFAULT_WALLET_PATH = "./nova_wallet.json";

// ── Types ────────────────────────────────────────────────────────────────────

export interface LogOpts {
  agentId?: string;
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

export interface TrackOpts extends Omit<LogOpts, "success" | "durationMs"> {
  /** If true, re-throw the error after logging the failure. Default: true */
  rethrow?: boolean;
}

export interface PassportResponse {
  address: string;
  agent_id: string;
  reputation_score?: number;
  activity_count?: number;
  [key: string]: unknown;
}

export interface SubmitResult {
  tx_id: string;
  status: string;
  [key: string]: unknown;
}

// ── NovaTracker ──────────────────────────────────────────────────────────────

export class NovaTracker {
  readonly wallet: Wallet;
  readonly agentId: string;
  readonly nodeUrl: string;

  constructor(wallet: Wallet, agentId: string, nodeUrl: string) {
    this.wallet = wallet;
    this.agentId = agentId;
    this.nodeUrl = nodeUrl.replace(/\/$/, ""); // strip trailing slash
  }

  // ── Factory methods ────────────────────────────────────────────────────────

  /**
   * Read configuration from environment variables:
   *   NOVA_AGENT_ID     — required agent identifier
   *   NOVA_WALLET_PATH  — path to wallet JSON file (default: ./nova_wallet.json)
   *   NOVA_NODE_URL     — node URL (default: https://explorer.flowpe.io)
   *
   * Loads the wallet from disk (does NOT create one automatically — use
   * `create()` for that).
   */
  static fromEnv(): NovaTracker {
    const agentId = process.env.NOVA_AGENT_ID;
    if (!agentId) throw new Error("NOVA_AGENT_ID environment variable is not set");

    const walletPath = process.env.NOVA_WALLET_PATH ?? DEFAULT_WALLET_PATH;
    const nodeUrl = process.env.NOVA_NODE_URL ?? DEFAULT_NODE_URL;

    const wallet = loadWallet(walletPath);
    return new NovaTracker(wallet, agentId, nodeUrl);
  }

  /**
   * Create a NovaTracker, generating a new wallet file if one doesn't exist.
   *
   * @param agentId   Your agent's identifier string.
   * @param walletPath  Path to save/load the wallet JSON (default: ./nova_wallet.json).
   * @param nodeUrl   Nova Network node URL (default: https://explorer.flowpe.io).
   */
  static async create(
    agentId: string,
    walletPath: string = DEFAULT_WALLET_PATH,
    nodeUrl: string = DEFAULT_NODE_URL
  ): Promise<NovaTracker> {
    const wallet = await loadOrCreateWallet(walletPath);
    return new NovaTracker(wallet, agentId, nodeUrl);
  }

  // ── Logging ────────────────────────────────────────────────────────────────

  /**
   * Log a single activity to Nova Network.
   * Returns the transaction ID (sha256 hex string).
   */
  async log(actionType: string, opts: LogOpts = {}): Promise<string> {
    const tx = await makeActivityLogTx(this.wallet, {
      agentId: opts.agentId ?? this.agentId,
      actionType,
      inputHash: opts.inputHash,
      outputHash: opts.outputHash,
      evidenceHash: opts.evidenceHash,
      evidenceUrl: opts.evidenceUrl,
      success: opts.success,
      durationMs: opts.durationMs,
      tags: opts.tags,
      platform: opts.platform,
      externalRef: opts.externalRef,
      note: opts.note,
      stakeLocked: opts.stakeLocked,
    });

    await this._submit(tx);
    return tx.id as string;
  }

  /**
   * Wrap an async function: automatically times it and logs success/failure.
   *
   * Example:
   *   const result = await tracker.track("summarize_doc", () => summarize(doc));
   */
  async track<T>(
    actionType: string,
    fn: () => Promise<T>,
    opts: TrackOpts = {}
  ): Promise<T> {
    const start = Date.now();
    const { rethrow = true, ...logOpts } = opts;

    let result: T;
    let success = true;
    let note = logOpts.note;

    try {
      result = await fn();
    } catch (err: unknown) {
      success = false;
      note = (note ? note + " | " : "") + String(err instanceof Error ? err.message : err);

      // Fire-and-forget the failure log — don't let logging errors mask the real one
      this.log(actionType, {
        ...logOpts,
        success: false,
        durationMs: Date.now() - start,
        note,
      }).catch(() => {/* swallow logging errors */});

      if (rethrow) throw err;
      return undefined as unknown as T;
    }

    const durationMs = Date.now() - start;
    // Fire-and-forget success log
    this.log(actionType, {
      ...logOpts,
      success: true,
      durationMs,
      note,
    }).catch(() => {/* swallow logging errors */});

    return result!;
  }

  // ── Attest / Challenge ─────────────────────────────────────────────────────

  /**
   * Submit an attestation for a specific activity log.
   * Returns the attestation transaction ID.
   */
  async attest(logId: string, sentiment: string, note?: string): Promise<string> {
    const tx = await makeAttestTx(this.wallet, { logId, sentiment, note });
    await this._submit(tx);
    return tx.id as string;
  }

  /**
   * Submit a challenge against a specific activity log.
   * Returns the challenge transaction ID.
   */
  async challenge(logId: string, opts: Omit<ChallengeOpts, "logId"> = {}): Promise<string> {
    const tx = await makeChallengeTx(this.wallet, { logId, ...opts });
    await this._submit(tx);
    return tx.id as string;
  }

  // ── Reputation / Passport ──────────────────────────────────────────────────

  /**
   * Fetch the agent's reputation passport from the Nova Network node.
   */
  async getReputation(): Promise<PassportResponse> {
    const url = `${this.nodeUrl}/public/agent/passport?address=${encodeURIComponent(this.wallet.address)}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to fetch passport: ${res.status} ${res.statusText}`);
    }
    return res.json() as Promise<PassportResponse>;
  }

  /** Alias for getReputation(). */
  async passport(): Promise<PassportResponse> {
    return this.getReputation();
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  private async _submit(tx: Record<string, unknown>): Promise<SubmitResult> {
    const url = `${this.nodeUrl}/public/tx`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(tx),
    });

    if (!res.ok) {
      let body = "";
      try { body = await res.text(); } catch { /* ignore */ }
      throw new Error(`Nova Network rejected tx: ${res.status} ${res.statusText} — ${body}`);
    }

    return res.json() as Promise<SubmitResult>;
  }
}
