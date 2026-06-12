# inspect_psbt security gap fixtures (Signet test keys only)

Captured from `rgb-msig-local` / `rgb_msig_wallet_setup` for offline regression tests.

## Layout

| Path | Contents |
|------|----------|
| `send_rgb/` | Op #5 SendRgb PSBTs, fascia, metadata |
| `foreign_mnemonic/` | Op #6 foreign-signature PSBTs |
| `party_datadirs/party-{1,2,3}/a44a82d6/` | Full multisig wallet dirs (stash required for `inspect_rgb_transfer`) |
| `keys/wallet_{1,2,3}.keys.json` | Signet cosigner key material (test network) |

## Tests

Security-gap tests **fail on purpose** until rgb-lib rejects invalid cosigner signatures at every step.

```bash
cargo test --lib foreign_one_valid -- --nocapture   # 1 valid + 2 foreign mnemonics
cargo test --lib op5_wrong_cosigner -- --nocapture  # op #5 wrong cosigner identity
```

Each run prints `OK <step>: rejected` or lists `SECURITY GAP` per layer:
`inspect_psbt` → `inspect_rgb_transfer` → `respond_to_operation (pre-ACK)` → `finalize_psbt`.

## Do not use on mainnet

All mnemonics and keys are public Signet test material.
