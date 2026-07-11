# x402 facilitator client — `/verify` and `/settle` over std.http.
#
# A facilitator is the optional party that verifies a payment payload and
# broadcasts/settles it on-chain, so a resource server doesn't need its
# own chain node. Both endpoints take the payment payload + the chosen
# requirement and return a settlement-shaped result. The resource-side
# `client` handshake settles against the resource directly; this module
# is for servers (or pre-flighting clients) that want to delegate
# verify/settle to a facilitator such as the x402 Foundation's.

import "std.str" as str

import "std.int" as int

import "std.map" as map

import "std.bytes" as bytes

import "std.json" as json

import "std.http" as http

import "std.crypto" as crypto

import "./types" as types

type Facilitator = { verify_url :: Str, settle_url :: Str }

# `paymentPayload` in the REST body must be the DECODED payload object, not
# the base64 string carried in the PAYMENT-SIGNATURE header -- the base64
# form is a wire-transport detail of the HTTP header, not the JSON API
# contract. Sending the base64 string as a JSON string value (the original
# bug here) makes a real facilitator's version/network dispatch fail with
# "No facilitator registered for x402 version: undefined", because it never
# finds an x402Version field where it expects one (nested inside the
# decoded object, not the outer string). Found live paying a real facilitator
# (x402.org) end-to-end from loom's lex-x402-api golden path.
fn decode_payload_json(payment_header :: Str) -> Result[Str, Str] {
  match crypto.base64_decode(payment_header) {
    Err(_) => Err("x402: paymentPayload is not valid base64"),
    Ok(raw) => match bytes.to_str(raw) {
      Err(_) => Err("x402: paymentPayload is not UTF-8"),
      Ok(text) => Ok(text),
    },
  }
}

# Build a facilitator bound to a base URL (e.g. "https://x402.org/facilitator").
fn make(base_url :: Str) -> Facilitator {
  { verify_url: str.concat(base_url, "/verify"), settle_url: str.concat(base_url, "/settle") }
}

# POST the payment to /settle and return the settlement result.
fn settle(fac :: Facilitator, payment_header :: Str, req :: types.Requirements) -> [net] Result[types.Settlement, Str] {
  match body(payment_header, req) {
    Err(e) => Err(e),
    Ok(b) => post(fac.settle_url, b),
  }
}

# POST the payment to /verify (no broadcast) and return the verdict as a
# settlement-shaped result (`success` = valid).
fn verify(fac :: Facilitator, payment_header :: Str, req :: types.Requirements) -> [net] Result[types.Settlement, Str] {
  match body(payment_header, req) {
    Err(e) => Err(e),
    Ok(b) => post(fac.verify_url, b),
  }
}

# The protocol version, the DECODED payment payload (spliced in verbatim --
# it's already well-formed JSON, re-stringifying it as a nested string would
# reintroduce the bug), and the requirement it satisfies (re-serialized to
# the wire shape so the facilitator sees spec field names).
fn body(payment_header :: Str, req :: types.Requirements) -> Result[Str, Str] {
  match decode_payload_json(payment_header) {
    Err(e) => Err(e),
    Ok(payload_json) => Ok(str.join(["{\"x402Version\":", int.to_str(types.version()), ",\"paymentPayload\":", payload_json, ",\"paymentRequirements\":", json.stringify(types.to_wire(req)), "}"], "")),
  }
}

fn post(url :: Str, json_body :: Str) -> [net] Result[types.Settlement, Str] {
  let req0 := { method: "POST", url: url, headers: map.new(), body: Some(bytes.from_str(json_body)), timeout_ms: Some(30000) }
  let req1 := http.with_header(req0, "Content-Type", "application/json")
  match http.send(req1) {
    Err(_) => Err("x402: facilitator request failed"),
    Ok(resp) => if resp.status >= 200 and resp.status < 300 {
      match http.text_body(resp) {
        Err(_) => Err("x402: could not read facilitator response"),
        Ok(text) => types.parse_settlement(text),
      }
    } else {
      Err(str.concat("x402: facilitator returned status ", int.to_str(resp.status)))
    },
  }
}

