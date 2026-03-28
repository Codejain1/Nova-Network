/**
 * wallet.ts — Nova Network wallet creation, loading, and saving.
 *
 * A "wallet" is just an Ed25519 keypair + derived address.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { readFileSync, writeFileSync, existsSync } from "fs";

export interface Wallet {
  /** hex-encoded 32-byte private key */
  privateKey: string;
  /** base64-encoded 32-byte public key */
  publicKey: string;
  /** Nova Network address — 'W' + first 40 hex chars of sha256(canonical pubkey JSON) */
  address: string;
}

/**
 * Produce canonical JSON: keys sorted alphabetically, no extra whitespace.
 * Defined here (duplicated from crypto.ts) to avoid a circular import.
 */
function _canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(_canonicalJson).join(",") + "]";
  const sorted = Object.keys(obj as Record<string, unknown>).sort();
  const parts = sorted.map(
    (k) => JSON.stringify(k) + ":" + _canonicalJson((obj as Record<string, unknown>)[k])
  );
  return "{" + parts.join(",") + "}";
}

/** Derive the address from a raw 32-byte public key Uint8Array. */
export function addressFromPublicKeyBytes(pubBytes: Uint8Array): string {
  const pubkeyJson = _canonicalJson({ key: bytesToBase64(pubBytes), kty: "ed25519" });
  const hash = sha256(new TextEncoder().encode(pubkeyJson));
  const hex = bytesToHex(hash);
  return ("W" + hex).slice(0, 41);
}

/** Create a brand-new random wallet. */
export async function createWallet(): Promise<Wallet> {
  const privBytes = randomBytes(32);
  const pubBytes = await ed.getPublicKeyAsync(privBytes);
  const address = addressFromPublicKeyBytes(pubBytes);
  return {
    privateKey: bytesToHex(privBytes),
    publicKey: bytesToBase64(pubBytes),
    address,
  };
}

/** Load a wallet from a JSON file at the given path. */
export function loadWallet(path: string): Wallet {
  if (!existsSync(path)) {
    throw new Error(`Wallet file not found: ${path}`);
  }
  const raw = readFileSync(path, "utf-8");
  const parsed = JSON.parse(raw) as Partial<Wallet>;
  if (!parsed.privateKey || !parsed.publicKey || !parsed.address) {
    throw new Error(`Invalid wallet file at ${path}: missing required fields`);
  }
  return parsed as Wallet;
}

/** Save a wallet to a JSON file at the given path. */
export function saveWallet(wallet: Wallet, path: string): void {
  writeFileSync(path, JSON.stringify(wallet, null, 2), { mode: 0o600 });
}

/**
 * Load a wallet from path, or create a new one and save it there if the file
 * does not yet exist. Returns the wallet.
 */
export async function loadOrCreateWallet(path: string): Promise<Wallet> {
  if (existsSync(path)) {
    return loadWallet(path);
  }
  const wallet = await createWallet();
  saveWallet(wallet, path);
  return wallet;
}

// ── tiny helpers ────────────────────────────────────────────────────────────

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  // Works in Node 18+, Deno, and Bun
  return Buffer.from(bytes).toString("base64");
}

export function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
