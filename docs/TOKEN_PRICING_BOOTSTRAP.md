# JITO Token Pricing Bootstrap

## Core principle

Price is not created by launching a blockchain. Price appears only when buyers and sellers can trade against liquid markets.

## How early token valuation is usually formed

1. A reference valuation is set off-chain:
- seed/private round price,
- strategic sale price,
- treasury accounting valuation.

2. A tradable market is created:
- DEX pool seeded (for example JITO/USDC),
- or CEX market listed (JITO/USDT).

3. First live trades set the public market price:
- first swaps define initial market cap and fully diluted valuation,
- then order flow, liquidity depth, and news reprice continuously.

## Why “no one has tokens yet” still gets a price

At launch, not everyone needs tokens. A small circulating tranche plus liquidity is enough:
- market makers + treasury seed liquidity,
- limited circulating supply unlock,
- vesting for team/investors to prevent immediate sell shock.

## Recommended JITO launch path

1. Testnet phase:
- faucet distribution only,
- no “real” price claims.

2. Mainnet pre-price phase:
- publish tokenomics,
- publish unlock/vesting schedule,
- publish market-making and treasury policy.

3. Price discovery phase:
- list one deep primary market first (DEX or CEX),
- use transparent liquidity and volume targets,
- avoid thin multi-venue listings on day 1.

4. Oracle policy:
- on-chain `price_update` should track external market feeds,
- do not manually pin arbitrary values once markets are live.

## Simple valuation math

- Circulating market cap = `price * circulating_supply`
- FDV = `price * total_supply`

Both numbers matter; circulating cap alone can look healthy while FDV is unsustainably high.

## Practical anti-manipulation controls

- deep initial liquidity,
- gradual unlocks,
- transparent treasury wallet disclosures,
- multiple oracle sources and medianization,
- monitoring for wash trading / spoofing.
