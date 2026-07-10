# x402 resource-server helper — the merchant side of the handshake.
#
# `client` drives the payer's 402 -> sign -> retry loop; this module is
# the counterpart for a resource server that wants to charge for an
# endpoint: build the 402 challenge, decode the payer's signed
# PAYMENT-SIGNATURE retry, and delegate verify/settle to a facilitator
# (this package doesn't run its own chain node — see `facilitator`).
#
#   1. build_requirement(...) + challenge(...) -> encode_challenge_header
#      -> emit as PAYMENT-REQUIRED on the first (unpaid) request.
#   2. on retry, decode_payment(header) to inspect the payer/amount for
#      bookkeeping, then charge(...) to verify + settle against a
#      facilitator in one call.
#   3. encode_response_header(settlement) -> emit as PAYMENT-RESPONSE on
#      the paid (2xx) response.

import "std.str" as str

import "./types" as types

import "./facilitator" as facilitator

import "./scheme/exact_solana" as solana

# Build the single Requirements a resource offers (this package only
# implements the Solana `exact` scheme end-to-end — see `network`).
fn build_requirement(price_atomic :: Str, resource_url :: Str, description :: Str, pay_to :: Str, network :: Str, asset :: Str, timeout_seconds :: Int) -> types.Requirements {
  { scheme: "exact", network: network, max_amount_required: price_atomic, resource: resource_url, description: description, mime_type: "application/json", pay_to: pay_to, max_timeout_seconds: timeout_seconds, asset: asset }
}

# Wrap one or more offered requirements into the full 402 challenge.
fn challenge(reqs :: List[types.Requirements]) -> types.PaymentRequired {
  { x402_version: types.version(), accepts: reqs, error: "" }
}

# The base64 PAYMENT-REQUIRED header value for a challenge.
fn challenge_header(pr :: types.PaymentRequired) -> Str {
  types.encode_required(pr)
}

# Decode an incoming PAYMENT-SIGNATURE retry (Solana `exact` scheme) so
# the caller can inspect payer/amount before deciding to charge.
fn decode_payment(payment_header_b64 :: Str) -> Result[solana.Payload, Str] {
  solana.decode(payment_header_b64)
}

# Verify then settle a payment against a facilitator, in one call. A
# failed verify short-circuits before any settle attempt (no broadcast
# for a payload that doesn't check out).
fn charge(fac :: facilitator.Facilitator, payment_header_b64 :: Str, req :: types.Requirements) -> [net] Result[types.Settlement, Str] {
  match facilitator.verify(fac, payment_header_b64, req) {
    Err(e) => Err(e),
    Ok(v) => if v.success {
      facilitator.settle(fac, payment_header_b64, req)
    } else {
      Err(verify_denied(v))
    },
  }
}

fn verify_denied(v :: types.Settlement) -> Str {
  if str.len(v.error) > 0 {
    str.concat("x402: facilitator rejected payment: ", v.error)
  } else {
    "x402: facilitator rejected payment"
  }
}

# The base64 PAYMENT-RESPONSE header value for a settlement result —
# emit this on the paid (2xx) response.
fn encode_response_header(s :: types.Settlement) -> Str {
  types.encode_settlement(s)
}

