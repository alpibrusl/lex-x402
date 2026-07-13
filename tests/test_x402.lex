# x402 protocol tests (pure — no network).
#
# Exercises the full 402 -> sign -> 200 handshake at the pure boundary,
# i.e. with a mock facilitator's header bytes fed through the same
# (de)serialization + signing the live `client` uses:
#   - encode/decode the PAYMENT-REQUIRED challenge and select a requirement
#   - build + sign a Solana `exact` PaymentPayload, then decode it and
#     verify the ed25519 signature against the payer's public key
#   - encode/decode the PAYMENT-RESPONSE settlement
#   - confirm the EVM path is cleanly blocked (lex-lang #655)

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "std.crypto" as crypto

import "../src/types" as types

import "../src/network" as network

import "../src/client" as client

import "../src/scheme/exact_solana" as solana

import "../src/scheme/exact_evm" as evm

# A fixed 32-byte ed25519 seed (deterministic across runs).
fn seed_b64url() -> Str {
  crypto.base64url_encode(bytes.from_str("0123456789abcdef0123456789abcdef"))
}

fn signer() -> solana.Signer {
  { secret_b64url: seed_b64url(), address: "PayerSoLAddr1111111111111111111111111111111" }
}

fn public_b64url() -> Result[Str, Str] {
  match crypto.base64url_decode(seed_b64url()) {
    Err(e) => Err(e),
    Ok(secret) => match crypto.ed25519_public_key(secret) {
      Err(e) => Err(e),
      Ok(pk) => Ok(crypto.base64url_encode(pk)),
    },
  }
}

fn solana_requirement() -> types.Requirements {
  { scheme: "exact", network: network.solana_mainnet(), max_amount_required: "1000000", resource: "https://api.example.com/data", description: "API call", mime_type: "application/json", pay_to: "MerchantSoLAddr2222222222222222222222222222", max_timeout_seconds: 60, asset: "EPjFWdd5USDCmintxxxxxxxxxxxxxxxxxxxxxxxxxxxx", fee_payer: "" }
}

fn evm_requirement() -> types.Requirements {
  { scheme: "exact", network: "eip155:8453", max_amount_required: "1000000", resource: "https://api.example.com/data", description: "API call", mime_type: "application/json", pay_to: "0x000000000000000000000000000000000000dEaD", max_timeout_seconds: 60, asset: "0xUSDC", fee_payer: "" }
}

fn sample_required() -> types.PaymentRequired {
  { x402_version: 2, accepts: [solana_requirement()], error: "" }
}

# ---- tests --------------------------------------------------------
# 402 challenge round-trips through base64/JSON and selects the Solana
# `exact` requirement.
fn t_select_solana() -> Result[Unit, Str] {
  let hdr := types.encode_required(sample_required())
  match types.decode_required(hdr) {
    Err(e) => Err(str.concat("decode_required: ", e)),
    Ok(pr) => match client.select(pr) {
      Err(e) => Err(str.concat("select: ", e)),
      Ok(req) => if req.pay_to == "MerchantSoLAddr2222222222222222222222222222" and req.network == network.solana_mainnet() {
        Ok(())
      } else {
        Err("select returned the wrong requirement")
      },
    },
  }
}

# Build + sign the payload, decode it, and verify the ed25519 signature
# with the payer's public key — the "sign" leg of the handshake.
fn t_sign_and_verify() -> Result[Unit, Str] {
  match solana.build(solana_requirement(), signer(), 0, 4102444800, "nonce-123") {
    Err(e) => Err(str.concat("build: ", e)),
    Ok(header) => match solana.decode(header) {
      Err(e) => Err(str.concat("decode: ", e)),
      Ok(payload) => check_sig(payload),
    },
  }
}

fn check_sig(payload :: solana.Payload) -> Result[Unit, Str] {
  match public_b64url() {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pub) => if solana.verify(pub, payload.payload.authorization, payload.payload.signature) {
      if payload.scheme == "exact" and payload.payload.authorization.nonce == "nonce-123" {
        Ok(())
      } else {
        Err("decoded payload carried wrong scheme/nonce")
      }
    } else {
      Err("signature did not verify against the payer public key")
    },
  }
}

# A tampered authorization must fail verification (signature is bound to
# the exact authorization bytes).
fn t_tamper_fails() -> Result[Unit, Str] {
  match solana.build(solana_requirement(), signer(), 0, 4102444800, "nonce-123") {
    Err(e) => Err(str.concat("build: ", e)),
    Ok(header) => match solana.decode(header) {
      Err(e) => Err(str.concat("decode: ", e)),
      Ok(payload) => check_tamper(payload),
    },
  }
}

fn check_tamper(payload :: solana.Payload) -> Result[Unit, Str] {
  match public_b64url() {
    Err(e) => Err(str.concat("pubkey: ", e)),
    Ok(pub) => if solana.verify(pub, tampered(payload.payload.authorization), payload.payload.signature) {
      Err("tampered authorization unexpectedly verified")
    } else {
      Ok(())
    },
  }
}

fn tampered(auth :: solana.Authorization) -> solana.Authorization {
  { from: auth.from, to: auth.to, value: "9999999", validAfter: auth.validAfter, validBefore: auth.validBefore, nonce: auth.nonce }
}

# Settlement (PAYMENT-RESPONSE) round-trips through base64/JSON.
fn t_settlement_roundtrip() -> Result[Unit, Str] {
  let s := { success: true, transaction: "0xtxhash", network: network.solana_mainnet(), payer: "PayerSoLAddr1111111111111111111111111111111", error: "" }
  let hdr := types.encode_settlement(s)
  match types.decode_settlement(hdr) {
    Err(e) => Err(str.concat("decode_settlement: ", e)),
    Ok(got) => if got.success and got.transaction == "0xtxhash" {
      Ok(())
    } else {
      Err("settlement round-trip mismatch")
    },
  }
}

# The EVM path is cleanly blocked on lex-lang #655.
fn t_evm_blocked() -> Result[Unit, Str] {
  match evm.build(evm_requirement()) {
    Ok(_) => Err("expected the EVM path to be blocked on #655"),
    Err(_) => Ok(()),
  }
}

# A real V2 facilitator's challenge uses `amount` (not `maxAmountRequired`)
# and nests the fee-payer sponsor address under `extra.feePayer` -- svm_client
# needs both to build a real transaction. Confirmed live against
# x402.org/facilitator this session.
fn t_decode_required_reads_v2_amount_and_fee_payer() -> Result[Unit, Str] {
  let raw := "{\"x402Version\":2,\"accepts\":[{\"scheme\":\"exact\",\"network\":\"solana-devnet\",\"amount\":\"10000\",\"asset\":\"AssetMint111111111111111111111111111111111\",\"payTo\":\"MerchantSoLAddr2222222222222222222222222222\",\"maxTimeoutSeconds\":60,\"extra\":{\"feePayer\":\"FeePayerSoLAddr33333333333333333333333333333\"}}]}"
  let hdr := types.encode_header(raw)
  match types.decode_required(hdr) {
    Err(e) => Err(str.concat("decode_required: ", e)),
    Ok(pr) => match list.head(pr.accepts) {
      None => Err("expected one requirement"),
      Some(req) => if req.max_amount_required == "10000" {
        if req.fee_payer == "FeePayerSoLAddr33333333333333333333333333333" {
          Ok(())
        } else {
          Err(str.concat("expected fee_payer parsed from extra.feePayer, got: ", req.fee_payer))
        }
      } else {
        Err(str.concat("expected amount \"10000\" (V2 field name), got: ", req.max_amount_required))
      },
    },
  }
}

# A requirement with neither `amount` nor `extra` (a V1-style facilitator,
# or this package's own outbound wire shape) must still parse cleanly --
# max_amount_required falls back to maxAmountRequired, fee_payer is empty.
fn t_decode_required_falls_back_to_v1_shape() -> Result[Unit, Str] {
  let raw := "{\"x402Version\":2,\"accepts\":[{\"scheme\":\"exact\",\"network\":\"solana-devnet\",\"maxAmountRequired\":\"5000\",\"payTo\":\"MerchantSoLAddr2222222222222222222222222222\",\"maxTimeoutSeconds\":60,\"asset\":\"AssetMint111111111111111111111111111111111\"}]}"
  let hdr := types.encode_header(raw)
  match types.decode_required(hdr) {
    Err(e) => Err(str.concat("decode_required: ", e)),
    Ok(pr) => match list.head(pr.accepts) {
      None => Err("expected one requirement"),
      Some(req) => if req.max_amount_required == "5000" {
        if str.len(req.fee_payer) == 0 {
          Ok(())
        } else {
          Err(str.concat("expected empty fee_payer when extra is absent, got: ", req.fee_payer))
        }
      } else {
        Err(str.concat("expected fallback to maxAmountRequired \"5000\", got: ", req.max_amount_required))
      },
    },
  }
}

fn run_all() -> Unit {
  let results := [t_select_solana(), t_sign_and_verify(), t_tamper_fails(), t_settlement_roundtrip(), t_evm_blocked(), t_decode_required_reads_v2_amount_and_fee_payer(), t_decode_required_falls_back_to_v1_shape()]
  let failures := list.fold(results, 0, fn (n :: Int, r :: Result[Unit, Str]) -> Int {
    match r {
      Ok(_) => n,
      Err(_) => n + 1,
    }
  })
  if failures == 0 {
    ()
  } else {
    let __discard := 1 / 0
    ()
  }
}

