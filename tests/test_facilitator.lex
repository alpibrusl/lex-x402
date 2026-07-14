# test_facilitator.lex — regression coverage for the /verify /settle
# request body shape.
#
# Found live paying a real facilitator (x402.org) end-to-end: `body`
# embedded the base64 PAYMENT-SIGNATURE header STRING as the JSON value of
# `paymentPayload`, instead of the decoded payload object. A real
# facilitator's version/network dispatch reads x402Version off the DECODED
# object, so it always failed with "No facilitator registered for x402
# version: undefined" -- every payment through facilitator.verify/settle
# was broken, not just Solana devnet.

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "std.crypto" as crypto

import "../src/types" as types

import "../src/facilitator" as facilitator

fn requirement() -> types.Requirements {
  { scheme: "exact", network: "solana-devnet", max_amount_required: "10000", resource: "https://api.example.com/convert", description: "API call", mime_type: "application/json", pay_to: "MerchantSoLAddr2222222222222222222222222222", max_timeout_seconds: 60, asset: "AssetMint111111111111111111111111111111111", fee_payer: "" }
}

fn requirement_with_fee_payer() -> types.Requirements {
  { scheme: "exact", network: "solana-devnet", max_amount_required: "10000", resource: "https://api.example.com/convert", description: "API call", mime_type: "application/json", pay_to: "MerchantSoLAddr2222222222222222222222222222", max_timeout_seconds: 60, asset: "AssetMint111111111111111111111111111111111", fee_payer: "FeePayerSoLAddr33333333333333333333333333333" }
}

fn payment_header() -> Str {
  crypto.base64_encode(bytes.from_str("{\"x402Version\":2,\"scheme\":\"exact\",\"network\":\"solana-devnet\",\"payload\":{\"signature\":\"sig\",\"authorization\":{\"from\":\"a\",\"to\":\"b\",\"value\":\"10000\",\"validAfter\":0,\"validBefore\":1,\"nonce\":\"n\"}}}"))
}

# The request body must embed the DECODED payload as a raw JSON object
# (its own top-level x402Version/scheme/network/payload fields visible at
# the outer level's nested key), never re-escaped as a JSON string.
fn t_body_embeds_decoded_payload_as_json_object() -> Result[Unit, Str] {
  match facilitator.body(payment_header(), requirement()) {
    Err(e) => Err(str.concat("body failed: ", e)),
    Ok(b) => {
      let has_object := str.contains(b, "\"paymentPayload\":{")
      let has_string := str.contains(b, "\"paymentPayload\":\"")
      if has_object and not has_string {
        Ok(())
      } else {
        Err(str.concat("expected paymentPayload embedded as a JSON object, got: ", b))
      }
    },
  }
}

# The decoded payload's own fields (e.g. its nested x402Version) must be
# reachable by a facilitator parsing the outer body -- i.e. genuinely
# present as JSON, not inside an escaped string.
fn t_body_preserves_inner_fields() -> Result[Unit, Str] {
  match facilitator.body(payment_header(), requirement()) {
    Err(e) => Err(str.concat("body failed: ", e)),
    Ok(b) => if str.contains(b, "\"network\":\"solana-devnet\"") and str.contains(b, "\"signature\":\"sig\"") {
      Ok(())
    } else {
      Err(str.concat("expected the decoded payload's inner fields reachable in the body, got: ", b))
    },
  }
}

fn t_body_rejects_invalid_base64() -> Result[Unit, Str] {
  match facilitator.body("not valid base64!!!", requirement()) {
    Ok(_) => Err("expected invalid base64 to be rejected"),
    Err(_) => Ok(()),
  }
}

# Found live paying a real facilitator end-to-end (#93/OP5 e2e
# verification): /settle rejected a V1-shaped `paymentRequirements`
# (maxAmountRequired, no extra.feePayer) with
# invalid_exact_svm_payload_missing_fee_payer, even though the payload's
# own transaction was already valid -- the requirements echo must be the
# same V2 shape (`amount`, `extra.feePayer`) the payload's `accepted`
# object uses.
fn t_body_sends_v2_shaped_requirements() -> Result[Unit, Str] {
  match facilitator.body(payment_header(), requirement_with_fee_payer()) {
    Err(e) => Err(str.concat("body failed: ", e)),
    Ok(b) => {
      let has_amount := str.contains(b, "\"amount\":\"10000\"")
      let has_fee_payer := str.contains(b, "\"feePayer\":\"FeePayerSoLAddr33333333333333333333333333333\"")
      let has_v1_field := str.contains(b, "maxAmountRequired")
      if has_amount and has_fee_payer and not has_v1_field {
        Ok(())
      } else {
        Err(str.concat("expected V2-shaped paymentRequirements (amount + extra.feePayer, no maxAmountRequired), got: ", b))
      }
    },
  }
}

fn suite() -> List[Result[Unit, Str]] {
  [t_body_embeds_decoded_payload_as_json_object(), t_body_preserves_inner_fields(), t_body_rejects_invalid_base64(), t_body_sends_v2_shaped_requirements()]
}

fn run_all() -> Unit {
  let results := suite()
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

