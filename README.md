# lex-x402

[![CI](https://github.com/alpibrusl/lex-x402/actions/workflows/lex.yml/badge.svg)](https://github.com/alpibrusl/lex-x402/actions/workflows/lex.yml)

**Part of the [Lex](https://lexlang.org) project** — [Manifesto](https://www.alpibru.com/manifesto) · [All packages](https://lexlang.org)

The **[x402](https://www.x402.org/)** internet-native payments protocol in pure Lex — HTTP `402 Payment Required` revived as a challenge/response handshake for instant stablecoin payments, designed for both browsers and AI agents (Coinbase, now the [x402 Foundation](https://blog.cloudflare.com/x402/) with Cloudflare).

x402 is *how* an approved spend is executed against a 402 endpoint. It's the natural complement to **[lex-guard](https://github.com/alpibrusl/lex-guard)**, which decides *whether* an agent may spend (signed budget token → policy → caps → attest). This package owns the protocol so guard stays a spending gate that *composes* it — see lex-guard's `x402_exec` executor adapter (lex-guard #3).

## Handshake (transports-v2 / HTTP)

```
1. client requests a resource
2. server  → 402 + PAYMENT-REQUIRED   (base64 PaymentRequirements)
3. client selects a requirement, builds + signs a PaymentPayload, retries
            → PAYMENT-SIGNATURE
4. server verifies (locally or via a facilitator /verify) and settles (/settle)
5. server  → 200 + PAYMENT-RESPONSE   (base64 settlement)
```

`client.pay` drives the whole loop and returns the on-chain settlement reference.

## Modules

- **`types`** — `Requirements`, `PaymentRequired`, `Settlement`; base64 header (de)serialization via `std.crypto.base64*` + `std.json`, with dynamic-JSON parsing (`lex-schema/json_value`) tolerant of optional fields. The snake_case ⇄ camelCase wire mapping lives only here.
- **`network`** — CAIP-2 identifiers and chain-family classification (`eip155:*` → EVM, `solana:*` → Solana).
- **`scheme/exact_solana`** — the `exact` scheme on Solana: build + sign the transfer authorization with `std.crypto.ed25519_*`. **Buildable today.**
- **`scheme/exact_evm`** — the `exact` scheme on EVM (EIP-3009). **Blocked on [lex-lang #655](https://github.com/alpibrusl/lex-lang/issues/655)** (`keccak256` + `secp256k1` in `std.crypto`); `build` returns a structured error rather than hand-rolling crypto.
- **`facilitator`** — `/verify` + `/settle` client over `std.http`.
- **`client`** — drive the full 402 → sign → retry handshake; return the settlement reference.

## Status

The **Solana (ed25519) path is implemented end-to-end** and is the validation of the protocol/handshake shape. The **EVM (`exact` / EIP-3009) path is blocked on lex-lang #655**; it lands once `keccak256` + `secp256k1` ship in `std.crypto`. A resource-side `server` helper (emit `402`, verify incoming payments) is a follow-up — the encoders/decoders it needs already live in `types` and `scheme/*`.

## Develop

```bash
lex pkg install
lex ci          # check --strict + fmt --check + test
```

## License

[EUPL-1.2](https://eupl.eu/).
