# JITO Private Chain Operating Model

## Recommended structure

Default architecture is one private chain with many domains:

- `domain_id` represents an organization, consortium, asset class, or jurisdiction.
- Each domain has:
  - members
  - optional contracts/policy rules
  - private visibility boundaries on tx

This is better than one cluster per asset in most cases.

## When to use separate clusters

Use separate private clusters only when required:

- strict data residency or regulatory isolation
- contractual need for hard compute/storage isolation
- materially different trust/governance models

Otherwise, keep one private chain and isolate via domains.

## Typical enterprise use cases

1. RWA lifecycle:
- issue, transfer, settle compliant real-world assets

2. Multi-organization workflows:
- banks, NBFCs, insurers, logistics sharing attestable state

3. Internal enterprise chain:
- approvals, controls, auditability with privacy

4. AI-native enterprise flows:
- model registry, private job lifecycle, hashed input/result records

## Public-private split

- Public chain:
  - gas token economics
  - payment settlement
  - provider stake/slash
  - broad verifiability
- Private chain:
  - sensitive metadata
  - permissioned participants
  - domain-level privacy and governance

## Practical rollout order

1. Start with one private cluster and domain-per-organization.
2. Define clear governance + validator/notary roles per domain.
3. Add cross-domain policy contracts where needed.
4. Add separate clusters only for strict legal/compliance boundaries.
