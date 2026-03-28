# JITO AI-Native Blockchain Gameplan

This document defines the implementation path to make JITO AI-native while preserving current public/private chain architecture.

## Objective

- Public chain: payments, gas, validator economics, AI provider stake/slash.
- Private chain: model/job metadata, privacy-scoped AI request/result lifecycle, governance.
- Settlement: private AI lifecycle state + public economic enforcement.

## Protocol primitives

1. Public chain primitives
- `ai_provider_stake`: provider locks native tokens.
- `ai_provider_slash`: validator slashes provider stake for faults.
- Fee-priority mempool for deterministic producer incentives.
- PoA proposer rotation + finality/checkpoint metadata.

2. Private chain primitives
- `ai_model_register`: register model identity and pricing metadata.
- `ai_job_create`: requester submits model call intent (hashed input).
- `ai_job_result`: provider submits hashed result and quality metadata.
- `ai_job_settle`: validator/notary settles payout/slash decision metadata.

## Current implementation status

Implemented in codebase:
- Public:
  - proposer rotation support
  - fee-priority tx ordering
  - finality/checkpoint metadata
  - AI provider staking/slashing txs + state
  - endpoints: `/public/finality`, `/public/ai/stakes`
- Private:
  - AI model/job tx lifecycle
  - model/job query endpoints: `/private/ai/models`, `/private/ai/jobs`

## Next milestones

1. Economic coupling
- Enforce private `ai_job_settle` onto public payment/slash settlement txs.
- Add bonded dispute window and challenge transactions.

2. Verifiability
- Add attestation fields for trusted execution (TEE quote hash).
- Add optional proof references for verifiable inference.

3. Scheduler and QoS
- Provider selection policy (stake-weight + reputation + latency).
- SLA policy and timeout slashing.

4. DevX and ecosystem
- SDK wrappers for AI tx composition.
- Explorer pages dedicated to model and job entities.
- Monitoring: job latency, settle ratio, slash rate.

## Suggested operating policy

- Keep AI model/job raw inputs off-chain; store only hashes and policy references.
- Keep pricing and settlement explicit and auditable in tx metadata.
- Require minimum provider stake before allowing job result submission.
- Use validator governance for threshold/rule updates.
