# Resource-server helper tests (pure — no network; `charge` composes
# `facilitator.verify`/`settle`, already exercised at the `body`/parse
# boundary by test_x402.lex, so it isn't re-tested here without a live
# facilitator).

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "std.crypto" as crypto

import "../src/types" as types

import "../src/network" as network

import "../src/server" as server

import "../src/scheme/exact_solana" as solana

fn seed_b64url() -> Str {
  crypto.base64url_encode(bytes.from_str("0123456789abcdef0123456789abcdef"))
}

fn signer() -> solana.Signer {
  { secret_b64url: seed_b64url(), address: "PayerSoLAddr1111111111111111111111111111111" }
}

fn merchant_requirement() -> types.Requirements {
  server.build_requirement("1000000", "https://api.example.com/convert", "Timezone conversion", "MerchantSoLAddr2222222222222222222222222222", network.solana_mainnet(), "EPjFWdd5USDCmintxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 60)
}

# build_requirement fills every field the wire needs (nothing silently
# defaulted to empty).
fn t_build_requirement_fields() -> Result[Unit, Str] {
  let r := merchant_requirement()
  if r.scheme == "exact" and r.max_amount_required == "1000000" and r.pay_to == "MerchantSoLAddr2222222222222222222222222222" and r.max_timeout_seconds == 60 {
    Ok(())
  } else {
    Err("build_requirement dropped or mis-set a field")
  }
}

# challenge -> challenge_header -> decode_required round-trips and
# carries the offered requirement through unchanged.
fn t_challenge_roundtrip() -> Result[Unit, Str] {
  let pr := server.challenge([merchant_requirement()])
  let hdr := server.challenge_header(pr)
  match types.decode_required(hdr) {
    Err(e) => Err(str.concat("decode_required: ", e)),
    Ok(got) => check_challenge(got),
  }
}

fn check_challenge(got :: types.PaymentRequired) -> Result[Unit, Str] {
  if got.x402_version == types.version() and list.len(got.accepts) == 1 {
    Ok(())
  } else {
    Err("challenge round-trip lost the version or the offered requirement")
  }
}

# decode_payment reads back the payer's signed retry (built the same
# way the real client would build it).
fn t_decode_payment() -> Result[Unit, Str] {
  match solana.build(merchant_requirement(), signer(), 0, 4102444800, "nonce-abc") {
    Err(e) => Err(str.concat("build: ", e)),
    Ok(header) => match server.decode_payment(header) {
      Err(e) => Err(str.concat("decode_payment: ", e)),
      Ok(payload) => if payload.payload.authorization.from == signer().address and payload.payload.authorization.nonce == "nonce-abc" {
        Ok(())
      } else {
        Err("decode_payment returned the wrong payer/nonce")
      },
    },
  }
}

# A settlement round-trips through encode_response_header the same way
# encode_settlement does (it's a thin alias, but confirm the boundary).
fn t_response_header_roundtrip() -> Result[Unit, Str] {
  let s := { success: true, transaction: "solTx123", network: network.solana_mainnet(), payer: "PayerSoLAddr1111111111111111111111111111111", error: "" }
  let hdr := server.encode_response_header(s)
  match types.decode_settlement(hdr) {
    Err(e) => Err(str.concat("decode_settlement: ", e)),
    Ok(got) => if got.success and got.transaction == "solTx123" {
      Ok(())
    } else {
      Err("response header round-trip mismatch")
    },
  }
}

fn run_all() -> Unit {
  let results := [t_build_requirement_fields(), t_challenge_roundtrip(), t_decode_payment(), t_response_header_roundtrip()]
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

