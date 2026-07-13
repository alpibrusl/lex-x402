# x402 client — drive the full 402 -> sign -> retry handshake.
#
# Flow (transports-v2 / HTTP):
#   1. request the resource
#   2. on 402, decode PAYMENT-REQUIRED and select a requirement
#   3. build + sign the PaymentPayload for that scheme/network
#   4. retry with PAYMENT-SIGNATURE
#   5. on 2xx, decode PAYMENT-RESPONSE -> settlement transaction
#
# `pay` returns the on-chain settlement reference as `Ok(tx)`, mirroring
# an executor's `Result[Str, Str]`. This is the surface lex-guard's
# x402 executor adapter composes (lex-guard #3).

import "std.str" as str

import "std.int" as int

import "std.map" as map

import "std.list" as list

import "std.http" as http

import "./types" as types

import "./network" as network

import "./scheme/exact_solana" as solana

import "./scheme/exact_evm" as evm

import "./scheme/svm_client" as svm_client

# Per-payment config: the resource to pay for, the ed25519 signer, and
# the authorization nonce / validity window. The caller supplies nonce
# and window because the handshake runs under `[net]` only (the gate's
# executor row) and so cannot read the clock or the CSPRNG itself — see
# lex-guard's x402_exec for how the executor derives them per intent.
# nonce/valid_after/valid_before are unused by the real Solana `exact`
# path (svm_client) -- kept for the EVM path and any facilitator that
# still expects the older envelope shape. `svm_rpc_url` overrides
# svm_rpc's public default endpoint; pass "" to use it.
type Config = { resource_url :: Str, signer :: solana.Signer, nonce :: Str, valid_after :: Int, valid_before :: Int, svm_rpc_url :: Str }

# ---- header names (transports-v2) ---------------------------------
fn h_required() -> Str
  examples {
    h_required() => "PAYMENT-REQUIRED"
  }
{
  "PAYMENT-REQUIRED"
}

fn h_signature() -> Str
  examples {
    h_signature() => "PAYMENT-SIGNATURE"
  }
{
  "PAYMENT-SIGNATURE"
}

fn h_response() -> Str
  examples {
    h_response() => "PAYMENT-RESPONSE"
  }
{
  "PAYMENT-RESPONSE"
}

# ---- handshake ----------------------------------------------------
fn pay(cfg :: Config) -> [net] Result[Str, Str] {
  match http.send(get_req(cfg.resource_url, None)) {
    Err(_) => Err("x402: resource request failed"),
    Ok(resp) => if resp.status == 402 {
      on_challenge(cfg, resp)
    } else {
      Err(str.concat("x402: expected 402 Payment Required, got status ", int.to_str(resp.status)))
    },
  }
}

fn on_challenge(cfg :: Config, resp :: HttpResponse) -> [net] Result[Str, Str] {
  match get_header(resp.headers, h_required()) {
    None => Err("x402: 402 response carried no PAYMENT-REQUIRED header"),
    Some(hdr) => match types.decode_required(hdr) {
      Err(e) => Err(e),
      Ok(pr) => match select(pr) {
        Err(e) => Err(e),
        Ok(req) => settle_with(cfg, req),
      },
    },
  }
}

fn settle_with(cfg :: Config, req :: types.Requirements) -> [net] Result[Str, Str] {
  match build_payload(cfg, req) {
    Err(e) => Err(e),
    Ok(header) => match http.send(get_req(cfg.resource_url, Some(header))) {
      Err(_) => Err("x402: signed retry request failed"),
      Ok(resp) => read_settlement(resp),
    },
  }
}

fn read_settlement(resp :: HttpResponse) -> Result[Str, Str] {
  if resp.status >= 200 and resp.status < 300 {
    match get_header(resp.headers, h_response()) {
      None => Err("x402: paid response carried no PAYMENT-RESPONSE header"),
      Some(hdr) => match types.decode_settlement(hdr) {
        Err(e) => Err(e),
        Ok(s) => settlement_ref(s),
      },
    }
  } else {
    Err(str.concat("x402: settlement rejected with status ", int.to_str(resp.status)))
  }
}

# Map a settlement to the spend reference: the tx on success, an error
# otherwise.
fn settlement_ref(s :: types.Settlement) -> Result[Str, Str] {
  if s.success {
    if str.len(s.transaction) > 0 {
      Ok(s.transaction)
    } else {
      Err("x402: settlement reported success but no transaction reference")
    }
  } else {
    if str.len(s.error) > 0 {
      Err(str.concat("x402: settlement failed: ", s.error))
    } else {
      Err("x402: settlement failed")
    }
  }
}

# ---- requirement selection ----------------------------------------
# Prefer a Solana `exact` requirement (buildable today); fall back to an
# EVM `exact` one so the caller gets the #655 blocked message rather than
# an opaque "no requirement" error.
fn select(pr :: types.PaymentRequired) -> Result[types.Requirements, Str] {
  match pick(pr.accepts, fn (r :: types.Requirements) -> Bool {
    is_exact_solana(r)
  }) {
    Some(r) => Ok(r),
    None => select_evm(pr),
  }
}

fn select_evm(pr :: types.PaymentRequired) -> Result[types.Requirements, Str] {
  match pick(pr.accepts, fn (r :: types.Requirements) -> Bool {
    is_exact_evm(r)
  }) {
    Some(r) => Ok(r),
    None => Err(no_match(pr)),
  }
}

fn no_match(pr :: types.PaymentRequired) -> Str {
  if str.len(pr.error) > 0 {
    str.concat("x402: ", pr.error)
  } else {
    "x402: no supported (exact) payment requirement offered"
  }
}

fn pick(rs :: List[types.Requirements], ok :: (types.Requirements) -> Bool) -> Option[types.Requirements] {
  list.fold(rs, None, fn (acc :: Option[types.Requirements], r :: types.Requirements) -> Option[types.Requirements] {
    match acc {
      Some(_) => acc,
      None => if ok(r) {
        Some(r)
      } else {
        None
      },
    }
  })
}

# Trivial scheme/family guards — no examples (need a Requirements value).
fn is_exact_solana(r :: types.Requirements) -> Bool {
  if r.scheme == "exact" {
    match network.family(r.network) {
      Solana => true,
      Evm => false,
      Unknown => false,
    }
  } else {
    false
  }
}

fn is_exact_evm(r :: types.Requirements) -> Bool {
  if r.scheme == "exact" {
    match network.family(r.network) {
      Evm => true,
      Solana => false,
      Unknown => false,
    }
  } else {
    false
  }
}

fn build_payload(cfg :: Config, req :: types.Requirements) -> [net] Result[Str, Str] {
  match network.family(req.network) {
    Solana => svm_client.build_payment(req, cfg.signer, cfg.svm_rpc_url),
    Evm => evm.build(req),
    Unknown => Err(str.concat("x402: unsupported network ", req.network)),
  }
}

# ---- http helpers -------------------------------------------------
# Build a GET to the resource, optionally carrying a PAYMENT-SIGNATURE.
fn get_req(url :: Str, signature :: Option[Str]) -> HttpRequest {
  let base := { method: "GET", url: url, headers: map.new(), body: None, timeout_ms: Some(30000) }
  match signature {
    None => base,
    Some(h) => http.with_header(base, h_signature(), h),
  }
}

# Read a response header case-insensitively (servers/runtimes differ on
# header casing).
fn get_header(headers :: Map[Str, Str], name :: Str) -> Option[Str] {
  match map.get(headers, name) {
    Some(v) => Some(v),
    None => match map.get(headers, str.to_lower(name)) {
      Some(v) => Some(v),
      None => map.get(headers, str.to_upper(name)),
    },
  }
}

