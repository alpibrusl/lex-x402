# x402 `exact` scheme — EVM path (EIP-3009 `transferWithAuthorization`).
#
# BLOCKED on lex-lang #655. The EVM path needs `keccak256` and
# `secp256k1_sign_digest` in `std.crypto` to build the EIP-712 typed-data
# digest (domain separator + `hashStruct`) and sign it. Neither primitive
# ships yet, so `build` returns a structured, actionable error rather than
# hand-rolling them — rolling your own crypto is a house-rule violation
# (AGENT_GUIDELINES §3.3). The Solana ed25519 path (`exact_solana`) is the
# buildable validation of the handshake shape until #655 lands.
#
# When #655 ships, this module fills in:
#   - eip712 domain separator for the asset's (name, version, chainId,
#     verifyingContract)
#   - hashStruct over the TransferWithAuthorization typed data
#   - keccak256 final digest, signed via secp256k1_sign_digest
#   - the { signature, authorization } payload, identical in shape to
#     `exact_solana` but signed over the keccak digest.

import "std.str" as str

import "../types" as types

# Returns the blocking error until #655 ships keccak256 + secp256k1.
fn build(req :: types.Requirements) -> Result[Str, Str] {
  Err(str.concat("exact_evm: blocked on lex-lang #655 (keccak256 + secp256k1) — cannot pay on network ", req.network))
}

