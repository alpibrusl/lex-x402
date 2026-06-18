# x402 `exact` scheme — Solana / ed25519 path.
#
# This is the buildable validation of the x402 handshake shape (the EVM
# path is blocked on lex-lang #655; see `exact_evm`). The client selects
# an `exact` requirement on a `solana:*` network, this module builds the
# canonical transfer authorization, signs it with the payer's ed25519
# key (`std.crypto.ed25519_sign`, a pure primitive), and packs the
# signature + authorization into the PaymentPayload carried in the
# PAYMENT-SIGNATURE header.
#
# Note on scope: this signs the EIP-3009-style authorization envelope —
# enough to prove the end-to-end handshake and let a facilitator verify
# the payer's signature. Assembling a full SVM on-chain transaction for
# real settlement is a follow-up; the envelope and signing primitive are
# real today.
#
# Wire field names (camelCase, `from`/`to`/`validAfter`/…) match the
# x402 spec so `json.stringify` emits a spec-compatible object; this is
# the deliberate boundary exception to the snake_case house style.

import "std.str" as str

import "std.json" as json

import "std.bytes" as bytes

import "std.crypto" as crypto

import "lex-schema/json_value" as jv

import "../types" as types

# Ed25519 signer for the Solana `exact` scheme. `secret_b64url` is the
# 32-byte ed25519 seed (base64url); `address` is the payer's account
# (base58), recorded as the authorization `from`.
type Signer = { secret_b64url :: Str, address :: Str }

# EIP-3009-style transfer authorization — the canonical object that is
# signed and then echoed inside the payment payload.
type Authorization = { from :: Str, to :: Str, value :: Str, validAfter :: Int, validBefore :: Int, nonce :: Str }

# Inner `payload` of a PaymentPayload for the exact scheme: the
# base64url ed25519 signature plus the authorization it covers.
type ExactPayload = { signature :: Str, authorization :: Authorization }

# The full PaymentPayload envelope (the PAYMENT-SIGNATURE header value).
type Payload = { x402Version :: Int, scheme :: Str, network :: Str, payload :: ExactPayload }

# Build the authorization for a selected requirement.
fn authorization(req :: types.Requirements, signer :: Signer, valid_after :: Int, valid_before :: Int, nonce :: Str) -> Authorization {
  { from: signer.address, to: req.pay_to, value: req.max_amount_required, validAfter: valid_after, validBefore: valid_before, nonce: nonce }
}

# The canonical bytes that get signed: the authorization as JSON. Both
# signer and verifier serialize the same record in declaration order, so
# the digest is deterministic.
fn signing_message(auth :: Authorization) -> Str {
  json.stringify(auth)
}

# Sign the authorization, returning the base64url signature.
fn sign(signer :: Signer, auth :: Authorization) -> Result[Str, Str] {
  match crypto.base64url_decode(signer.secret_b64url) {
    Err(_) => Err("exact_solana: signer secret is not valid base64url"),
    Ok(secret) => match crypto.ed25519_sign(secret, bytes.from_str(signing_message(auth))) {
      Err(e) => Err(str.concat("exact_solana: signing failed: ", e)),
      Ok(sig) => Ok(crypto.base64url_encode(sig)),
    },
  }
}

# Build + sign the PaymentPayload and return it as a PAYMENT-SIGNATURE
# header value (base64 of the payload JSON).
fn build(req :: types.Requirements, signer :: Signer, valid_after :: Int, valid_before :: Int, nonce :: Str) -> Result[Str, Str] {
  let auth := authorization(req, signer, valid_after, valid_before, nonce)
  match sign(signer, auth) {
    Err(e) => Err(e),
    Ok(sig) => Ok(types.encode_header(json.stringify(({ x402Version: types.version(), scheme: "exact", network: req.network, payload: { signature: sig, authorization: auth } } :: Payload)))),
  }
}

# Verify a payload's signature against a base64url ed25519 public key —
# the check a facilitator (or a resource server verifying locally) runs.
fn verify(public_b64url :: Str, auth :: Authorization, sig_b64url :: Str) -> Bool {
  match crypto.base64url_decode(public_b64url) {
    Err(_) => false,
    Ok(pk) => match crypto.base64url_decode(sig_b64url) {
      Err(_) => false,
      Ok(sig) => crypto.ed25519_verify(pk, bytes.from_str(signing_message(auth)), sig),
    },
  }
}

# Decode a PAYMENT-SIGNATURE header back into a Payload (server side and
# tests). Dynamic JSON via the shared json_value accessors in `types`.
fn decode(header_b64 :: Str) -> Result[Payload, Str] {
  match crypto.base64_decode(header_b64) {
    Err(_) => Err("exact_solana: payload is not valid base64"),
    Ok(raw) => match bytes.to_str(raw) {
      Err(_) => Err("exact_solana: payload is not UTF-8"),
      Ok(text) => parse(text),
    },
  }
}

fn parse(text :: Str) -> Result[Payload, Str] {
  match jv.parse(text) {
    Err(e) => Err(str.concat("exact_solana: payload bad json: ", e.message)),
    Ok(j) => match jv.get_field(j, "payload") {
      None => Err("exact_solana: payload missing inner `payload` object"),
      Some(p) => Ok({ x402Version: types.get_int(j, "x402Version"), scheme: types.get_str(j, "scheme"), network: types.get_str(j, "network"), payload: { signature: types.get_str(p, "signature"), authorization: authorization_from_json(p) } }),
    },
  }
}

fn authorization_from_json(p :: jv.Json) -> Authorization {
  match jv.get_field(p, "authorization") {
    None => empty_authorization(),
    Some(a) => { from: types.get_str(a, "from"), to: types.get_str(a, "to"), value: types.get_str(a, "value"), validAfter: types.get_int(a, "validAfter"), validBefore: types.get_int(a, "validBefore"), nonce: types.get_str(a, "nonce") },
  }
}

# A zero authorization, returned when the payload carries no `authorization`
# object (a malformed payload — `verify` will then reject it).
fn empty_authorization() -> Authorization {
  { from: "", to: "", value: "", validAfter: 0, validBefore: 0, nonce: "" }
}

