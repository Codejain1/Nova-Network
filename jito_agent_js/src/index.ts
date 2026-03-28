/**
 * nova-agent — TypeScript SDK for the Nova Network agent identity system.
 *
 * Quick start:
 *   import { NovaTracker } from "nova-agent";
 *   const tracker = await NovaTracker.create("my-agent");
 *   await tracker.log("task_complete", { note: "all done" });
 */

// Wallet
export {
  createWallet,
  loadWallet,
  saveWallet,
  loadOrCreateWallet,
  addressFromPublicKeyBytes,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
} from "./wallet.js";
export type { Wallet } from "./wallet.js";

// Crypto / tx building
export {
  canonicalJson,
  deriveAddress,
  signPayload,
  makeNonce,
  makeTxId,
  makeActivityLogTx,
  makeAttestTx,
  makeChallengeTx,
} from "./crypto.js";
export type {
  ActivityLogOpts,
  AttestOpts,
  ChallengeOpts,
} from "./crypto.js";

// Tracker (main high-level API)
export { NovaTracker } from "./tracker.js";
export type {
  LogOpts,
  TrackOpts,
  PassportResponse,
  SubmitResult,
} from "./tracker.js";
