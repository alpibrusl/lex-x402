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

import "./types" as types

type Facilitator = { verify_url :: Str, settle_url :: Str }

# Body sent to /verify and /settle: the protocol version, the base64
# payment header, and the requirement it satisfies (re-serialized to the
# wire shape so the facilitator sees spec field names).
type Body = { x402Version :: Int, paymentPayload :: Str, paymentRequirements :: types.ReqWire }

# Build a facilitator bound to a base URL (e.g. "https://x402.org/facilitator").
fn make(base_url :: Str) -> Facilitator {
  { verify_url: str.concat(base_url, "/verify"), settle_url: str.concat(base_url, "/settle") }
}

# POST the payment to /settle and return the settlement result.
fn settle(fac :: Facilitator, payment_header :: Str, req :: types.Requirements) -> [net] Result[types.Settlement, Str] {
  post(fac.settle_url, body(payment_header, req))
}

# POST the payment to /verify (no broadcast) and return the verdict as a
# settlement-shaped result (`success` = valid).
fn verify(fac :: Facilitator, payment_header :: Str, req :: types.Requirements) -> [net] Result[types.Settlement, Str] {
  post(fac.verify_url, body(payment_header, req))
}

fn body(payment_header :: Str, req :: types.Requirements) -> Str {
  json.stringify(({ x402Version: types.version(), paymentPayload: payment_header, paymentRequirements: types.to_wire(req) } :: Body))
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

