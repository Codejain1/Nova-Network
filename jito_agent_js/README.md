# nova-agent

TypeScript SDK for the [Nova Network](https://explorer.flowpe.io) agent identity system.
Log AI agent activity on-chain with Ed25519-signed transactions. Works with any framework —
OpenAI SDK, Anthropic SDK, LangChain, raw `fetch`, whatever.

Supports Node.js 18+, Deno, and Bun.

---

## Install

```bash
npm install nova-agent
# or
bun add nova-agent
```

---

## Quick start

### Option A — environment variables (recommended for prod)

```bash
export NOVA_AGENT_ID="my-summarizer-agent"
export NOVA_WALLET_PATH="./nova_wallet.json"   # created automatically if missing
export NOVA_NODE_URL="https://explorer.flowpe.io"  # optional, this is the default
```

```ts
import { NovaTracker } from "nova-agent";

// Reads env vars. Wallet file must already exist (use NovaTracker.create() to
// generate one first, then export NOVA_WALLET_PATH pointing to it).
const tracker = NovaTracker.fromEnv();

// Log a single action
const txId = await tracker.log("task_complete", {
  note: "Summarized 3 documents",
  tags: ["summarizer", "prod"],
  durationMs: 1240,
});
console.log("logged tx:", txId);

// Wrap a function — auto-times it, logs success or failure
const summary = await tracker.track("summarize_doc", async () => {
  return await callOpenAI(doc);
});
```

### Option B — manual setup (scripts, CLIs, tests)

```ts
import { NovaTracker } from "nova-agent";

// Creates wallet at the path if it doesn't exist yet
const tracker = await NovaTracker.create(
  "my-agent-id",
  "./my_wallet.json",           // optional, default: ./nova_wallet.json
  "https://explorer.flowpe.io"  // optional
);

const txId = await tracker.log("fetch_prices", {
  success: true,
  durationMs: 320,
  note: "fetched BTC/USD",
});
```

---

## Works with any agent framework

### OpenAI SDK

```ts
import OpenAI from "openai";
import { NovaTracker } from "nova-agent";

const tracker = NovaTracker.fromEnv();
const openai = new OpenAI();

// track() wraps any async call
const response = await tracker.track("openai_chat", () =>
  openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: "Hello!" }],
  })
);
```

### Anthropic SDK

```ts
import Anthropic from "@anthropic-ai/sdk";
import { NovaTracker } from "nova-agent";

const tracker = NovaTracker.fromEnv();
const client = new Anthropic();

const message = await tracker.track("anthropic_message", () =>
  client.messages.create({
    model: "claude-opus-4-5",
    max_tokens: 1024,
    messages: [{ role: "user", content: "Explain quantum computing." }],
  })
);
```

### Raw fetch

```ts
import { NovaTracker } from "nova-agent";

const tracker = NovaTracker.fromEnv();

const result = await tracker.track(
  "fetch_prices",
  () => fetch("https://api.example.com/prices").then((r) => r.json()),
  { tags: ["prices", "external-api"] }
);
```

---

## API reference

### `NovaTracker.create(agentId, walletPath?, nodeUrl?)` → `Promise<NovaTracker>`

Creates a tracker. Generates a new wallet at `walletPath` if the file doesn't exist.

### `NovaTracker.fromEnv()` → `NovaTracker`

Reads `NOVA_AGENT_ID`, `NOVA_WALLET_PATH`, `NOVA_NODE_URL` from `process.env`.
Wallet file must already exist.

### `tracker.log(actionType, opts?)` → `Promise<string>`

Logs a single activity. Returns the transaction ID (sha256 hex).

**opts:**
| field | type | default |
|---|---|---|
| `note` | `string` | `""` |
| `success` | `boolean` | `true` |
| `durationMs` | `number` | `0` |
| `tags` | `string[]` | `[]` |
| `platform` | `string` | `""` |
| `inputHash` | `string` | `""` |
| `outputHash` | `string` | `""` |
| `evidenceHash` | `string` | `""` |
| `evidenceUrl` | `string` | `""` |
| `externalRef` | `string` | `""` |
| `stakeLocked` | `number` | `0.0` |

### `tracker.track(actionType, fn, opts?)` → `Promise<T>`

Wraps an async function. Auto-times execution, logs success or failure.
Pass `rethrow: false` to suppress re-throwing errors.

### `tracker.attest(logId, sentiment, note?)` → `Promise<string>`

Submit an attestation for a log entry. Returns attestation tx ID.

### `tracker.challenge(logId, opts?)` → `Promise<string>`

Submit a challenge against a log entry. Returns challenge tx ID.

### `tracker.getReputation()` / `tracker.passport()` → `Promise<PassportResponse>`

Fetch the agent's on-chain reputation passport.

---

## Low-level API

```ts
import {
  createWallet,
  loadWallet,
  saveWallet,
  signPayload,
  makeActivityLogTx,
  makeAttestTx,
  makeChallengeTx,
  canonicalJson,
  deriveAddress,
} from "nova-agent";

// Create a wallet manually
const wallet = await createWallet();
saveWallet(wallet, "./wallet.json");

// Build & sign a tx without submitting
const tx = await makeActivityLogTx(wallet, {
  actionType: "inference",
  agentId: "my-agent",
  success: true,
  durationMs: 500,
});

// Submit yourself
await fetch("https://explorer.flowpe.io/public/tx", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(tx),
});
```

---

## Transaction format

All transactions are submitted as `POST /public/tx` with `Content-Type: application/json`.

Signing uses Ed25519 over the canonical JSON (keys sorted alphabetically, no extra spaces)
of the signable subset of the transaction fields. The `id` field is the sha256 of the
full transaction (including `pubkey` and `signature`) as canonical JSON.

Address derivation: `'W' + sha256(canonical_json({key: base64_pubkey, kty: "ed25519"}))[hex].slice(0, 40)`

---

## License

MIT
