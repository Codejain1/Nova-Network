## ethereum-lists/chains PR Text (JITO)

Title suggestion:

`Add JITO Public Network (eip155-149)`

Description suggestion:

```
Adds JITO Public Network (chainId 149).

Network details:
- Name: JITO Public Network
- Chain ID: 149
- RPC: https://rpc.flowpe.io
- Explorer: https://explorer.flowpe.io/explorer
- Native currency: JITO (18)
- Info URL: https://jito.flowpe.io
```

Checklist before opening PR:

1. Confirm chain ID is still unused in latest upstream.
2. Keep only one file in PR: `_data/chains/eip155-149.json`.
3. Ensure JSON formatting matches repository style.
4. Re-run endpoint checks:
   - `curl -s https://rpc.flowpe.io/health`
   - `curl -s https://explorer.flowpe.io/health`
   - `curl -s -X POST https://rpc.flowpe.io -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'`
