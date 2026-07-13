# x402 wire types and header (de)serialization.
#
# Every x402 message rides in an HTTP header as base64(JSON). This
# module owns the shared data model plus the base64/JSON boundary:
#   - inbound: `decode_required` / `decode_settlement` parse the
#     PAYMENT-REQUIRED / PAYMENT-RESPONSE headers (dynamic JSON via
#     `lex-schema/json_value`, tolerant of optional/extra fields).
#   - outbound: `encode_*` render a value back to a header (used by the
#     scheme builders, the facilitator client, and the resource-server
#     side). `encode_header` is the raw base64-of-JSON primitive.
#
# Internal record fields use the house snake_case; the *wire* records
# (`ReqWire`, `RequiredWire`, `SettleWire`) carry the x402 camelCase
# field names so `json.stringify` emits spec-compatible JSON. The
# snake_case <-> camelCase mapping lives only at this boundary.

import "std.str" as str

import "std.json" as json

import "std.list" as list

import "std.bytes" as bytes

import "std.crypto" as crypto

import "lex-schema/json_value" as jv

# ---- protocol constants -------------------------------------------
# Implemented protocol version (transports-v2).
fn version() -> Int
  examples {
    version() => 2
  }
{
  2
}

# ---- internal model -----------------------------------------------
# One payment option offered by a resource server (an element of the
# 402 `accepts` set). Amounts are atomic-unit decimal strings, per spec.
# `fee_payer` (from the wire's nested `extra.feePayer`, V2 shape) is the
# facilitator's sponsor address for SVM `exact` payments -- the client signs
# only its own transfer-authority slot; the facilitator's fee payer signs
# and covers gas during settlement. Empty when absent (EVM requirements,
# or a facilitator/network that doesn't sponsor gas).
type Requirements = { scheme :: Str, network :: Str, max_amount_required :: Str, resource :: Str, description :: Str, mime_type :: Str, pay_to :: Str, max_timeout_seconds :: Int, asset :: Str, fee_payer :: Str }

# The full 402 challenge: the version, the offered options, and an
# optional human-readable error from the server.
type PaymentRequired = { x402_version :: Int, accepts :: List[Requirements], error :: Str }

# Settlement / verify result echoed back by the server (or facilitator).
type Settlement = { success :: Bool, transaction :: Str, network :: Str, payer :: Str, error :: Str }

# ---- wire records (camelCase keys) --------------------------------
type ReqWire = { scheme :: Str, network :: Str, maxAmountRequired :: Str, resource :: Str, description :: Str, mimeType :: Str, payTo :: Str, maxTimeoutSeconds :: Int, asset :: Str }

type RequiredWire = { x402Version :: Int, accepts :: List[ReqWire], error :: Str }

type SettleWire = { success :: Bool, transaction :: Str, network :: Str, payer :: Str, errorReason :: Str }

# ---- dynamic-JSON field accessors (defaulting) --------------------
# Defaulting readers over a json_value: missing / wrong-typed fields
# fall back to a zero value rather than erroring, so an absent optional
# field (e.g. `description`) never fails a parse.
fn get_str(j :: jv.Json, key :: Str) -> Str {
  match jv.get_field(j, key) {
    None => "",
    Some(v) => match jv.as_str(v) {
      None => "",
      Some(s) => s,
    },
  }
}

fn get_int(j :: jv.Json, key :: Str) -> Int {
  match jv.get_field(j, key) {
    None => 0,
    Some(v) => match jv.as_int(v) {
      None => 0,
      Some(n) => n,
    },
  }
}

fn get_bool(j :: jv.Json, key :: Str) -> Bool {
  match jv.get_field(j, key) {
    None => false,
    Some(v) => match jv.as_bool(v) {
      None => false,
      Some(b) => b,
    },
  }
}

# ---- snake_case -> wire mapping -----------------------------------
fn to_wire(r :: Requirements) -> ReqWire {
  { scheme: r.scheme, network: r.network, maxAmountRequired: r.max_amount_required, resource: r.resource, description: r.description, mimeType: r.mime_type, payTo: r.pay_to, maxTimeoutSeconds: r.max_timeout_seconds, asset: r.asset }
}

# ---- header primitive ---------------------------------------------
# Encode a JSON document as an x402 header value: base64 of the JSON.
fn encode_header(json_text :: Str) -> Str {
  crypto.base64_encode(bytes.from_str(json_text))
}

# ---- inbound: PAYMENT-REQUIRED ------------------------------------
fn decode_required(header_b64 :: Str) -> Result[PaymentRequired, Str] {
  match crypto.base64_decode(header_b64) {
    Err(_) => Err("x402: PAYMENT-REQUIRED is not valid base64"),
    Ok(raw) => match bytes.to_str(raw) {
      Err(_) => Err("x402: PAYMENT-REQUIRED is not UTF-8"),
      Ok(text) => parse_required(text),
    },
  }
}

fn parse_required(text :: Str) -> Result[PaymentRequired, Str] {
  match jv.parse(text) {
    Err(e) => Err(str.concat("x402: PAYMENT-REQUIRED bad json: ", e.message)),
    Ok(j) => Ok({ x402_version: get_int(j, "x402Version"), accepts: parse_accepts(j), error: get_str(j, "error") }),
  }
}

fn parse_accepts(j :: jv.Json) -> List[Requirements] {
  match jv.get_field(j, "accepts") {
    None => [],
    Some(v) => match jv.as_list(v) {
      None => [],
      Some(items) => list.map(items, fn (it :: jv.Json) -> Requirements {
        requirement_from_json(it)
      }),
    },
  }
}

fn requirement_from_json(j :: jv.Json) -> Requirements {
  { scheme: get_str(j, "scheme"), network: get_str(j, "network"), max_amount_required: amount_field(j), resource: get_str(j, "resource"), description: get_str(j, "description"), mime_type: get_str(j, "mimeType"), pay_to: get_str(j, "payTo"), max_timeout_seconds: get_int(j, "maxTimeoutSeconds"), asset: get_str(j, "asset"), fee_payer: get_nested_str(j, "extra", "feePayer") }
}

# V2 requirements use `amount`; V1 (and this package's own outbound wire
# shape) use `maxAmountRequired`. Accept either so decode_required works
# against a real V2 facilitator/server without breaking the V1 fixtures
# already covered by test_x402.lex/test_server.lex.
fn amount_field(j :: jv.Json) -> Str {
  let v2 := get_str(j, "amount")
  if str.len(v2) > 0 {
    v2
  } else {
    get_str(j, "maxAmountRequired")
  }
}

fn get_nested_str(j :: jv.Json, outer_key :: Str, inner_key :: Str) -> Str {
  match jv.get_field(j, outer_key) {
    None => "",
    Some(outer) => get_str(outer, inner_key),
  }
}

# ---- inbound: PAYMENT-RESPONSE ------------------------------------
fn decode_settlement(header_b64 :: Str) -> Result[Settlement, Str] {
  match crypto.base64_decode(header_b64) {
    Err(_) => Err("x402: PAYMENT-RESPONSE is not valid base64"),
    Ok(raw) => match bytes.to_str(raw) {
      Err(_) => Err("x402: PAYMENT-RESPONSE is not UTF-8"),
      Ok(text) => parse_settlement(text),
    },
  }
}

fn parse_settlement(text :: Str) -> Result[Settlement, Str] {
  match jv.parse(text) {
    Err(e) => Err(str.concat("x402: PAYMENT-RESPONSE bad json: ", e.message)),
    Ok(j) => Ok({ success: get_bool(j, "success"), transaction: settlement_tx(j), network: get_str(j, "network"), payer: get_str(j, "payer"), error: get_str(j, "errorReason") }),
  }
}

# transports-v2 names the on-chain reference `transaction`; some
# facilitators still emit `txHash`. Accept either.
fn settlement_tx(j :: jv.Json) -> Str {
  let primary := get_str(j, "transaction")
  if str.len(primary) > 0 {
    primary
  } else {
    get_str(j, "txHash")
  }
}

# ---- outbound encoders (resource-server / test side) --------------
fn encode_required(pr :: PaymentRequired) -> Str {
  encode_header(json.stringify(({ x402Version: pr.x402_version, accepts: list.map(pr.accepts, fn (r :: Requirements) -> ReqWire {
    to_wire(r)
  }), error: pr.error } :: RequiredWire)))
}

fn encode_settlement(s :: Settlement) -> Str {
  encode_header(json.stringify(({ success: s.success, transaction: s.transaction, network: s.network, payer: s.payer, errorReason: s.error } :: SettleWire)))
}

