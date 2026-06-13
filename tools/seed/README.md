# Seed Issuer Identity

This directory holds a pre-funded `issuer_identity.json` file that the thesis reviewer
can install with a single command, bypassing the testnet faucet (which now requires a
browser CAPTCHA and cannot be called programmatically).

## For the thesis reviewer

Run the install script from the repository root before starting `identity-service` for
the first time:

```bash
bash tools/install_seed_identity.sh
```

Then start the service normally.  The issuer identity is already initialised on
testnet and pre-funded; calling `POST /api/v1/issuer/initialize` is not required
(the service will log "Loaded existing issuer identity from storage" on startup).

## For the developer: how to regenerate the seed

Run this once whenever the seed wallet needs to be refreshed (e.g. it has run out of
tokens):

```bash
python3 tools/create_seed_identity.py
```

Follow the printed instructions:
1. Note the **tx key address** printed by the script.
2. Transfer testnet IOTA from your CLI wallet to that address:
   ```bash
   iota client transfer-iota \
     --to <tx_key_address> \
     --amount 50000000000 \
     --gas-budget 5000000
   ```
   (50 IOTA = 50 000 000 000 nanos; sufficient for ~10 000 DID operations at ~0.005 IOTA each.)
3. Start `identity-service`, then call:
   ```bash
   curl -s -X POST http://localhost:3000/api/v1/issuer/initialize | jq .
   ```
4. Copy the resulting identity file into this directory:
   ```bash
   cp ~/.iota-identity-service/issuer_identity.json tools/seed/issuer_identity.json
   ```
5. Commit the file to the repository.

> The seed identity contains testnet-only private keys with no real-world monetary
> value.  Committing them is intentional and necessary for reproducible demos.
