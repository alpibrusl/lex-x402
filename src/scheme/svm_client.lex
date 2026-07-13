# Real Solana `exact` payment builder -- combines svm_rpc (chain reads)
# and solana_tx (pure wire serialization) into the actual client-side
# PAYMENT-SIGNATURE header a real x402 V2 facilitator accepts.
#
# Confirmed live against x402.org/facilitator this session: the facilitator
# expects x402Version:2, a top-level `accepted` object mirroring the chosen
# requirement (field name `amount`, not `maxAmountRequired`), an optional
# `resource` object, and `payload.transaction` = base64 of a partially
# signed wire transaction. The facilitator itself is the fee payer (its
# address arrives as `extra.feePayer` on the requirement, see types.lex) --
# it signs and broadcasts during settlement; the client here only signs its
# own transfer-authority slot.
#
# What this module does NOT do (documented gaps, not silent shortcuts):
#   - Associated Token Account creation: both the payer's and the payTo's
#     token accounts must already exist on-chain. svm_rpc.find_token_account
#     reads the real existing account rather than deriving a PDA (this
#     codebase has no off-curve validity search), so a payTo with no token
#     account for this asset yet produces a clear error, not a guess.
#   - Compute-unit estimation via simulation: uses a fixed conservative
#     unit limit (see `compute_unit_limit`) instead of calling
#     simulateTransaction. Good enough to not run out of compute for a
#     single transferChecked; a real production path could tighten this.

import "std.str" as str

import "std.int" as int

import "std.bytes" as bytes

import "std.crypto" as crypto

import "../types" as types

import "./exact_solana" as solana

import "./solana_tx" as tx

import "./svm_rpc" as rpc

# Fixed compute-unit budget for a single ComputeBudget + TransferChecked
# transaction -- generous relative to typical usage (a plain
# TransferChecked runs in the low tens of thousands of units) without
# needing a simulateTransaction round-trip.
fn compute_unit_limit() -> Int {
  200000
}

fn compute_unit_price_micro_lamports() -> Int {
  1
}

# Build and sign the real Solana transaction for `req`, returning the
# base64(JSON) PAYMENT-SIGNATURE header value. `rpc_url_override` picks a
# specific endpoint (e.g. a paid RPC); pass "" to use svm_rpc's public
# default for `req.network`.
fn build_payment(req :: types.Requirements, signer :: solana.Signer, rpc_url_override :: Str) -> [net] Result[Str, Str] {
  if str.len(req.fee_payer) == 0 {
    Err("svm_client: requirement carries no extra.feePayer -- this facilitator/network doesn't sponsor gas, or the challenge is malformed")
  } else {
    let rpc_url := if str.len(rpc_url_override) > 0 {
      rpc_url_override
    } else {
      rpc.default_rpc_url(req.network)
    }
    build_with_rpc(req, signer, rpc_url)
  }
}

fn build_with_rpc(req :: types.Requirements, signer :: solana.Signer, rpc_url :: Str) -> [net] Result[Str, Str] {
  match parse_amount(req.max_amount_required) {
    Err(e) => Err(e),
    Ok(amount) => match tx.decode_pubkey(req.fee_payer) {
      Err(e) => Err(e),
      Ok(fee_payer_pk) => match tx.decode_pubkey(signer.address) {
        Err(e) => Err(e),
        Ok(payer_pk) => match tx.decode_pubkey(req.asset) {
          Err(e) => Err(e),
          Ok(mint_pk) => match rpc.find_token_account(rpc_url, signer.address, req.asset) {
            Err(e) => Err(e),
            Ok(source_ata_b58) => match rpc.find_token_account(rpc_url, req.pay_to, req.asset) {
              Err(e) => Err(e),
              Ok(dest_ata_b58) => match tx.decode_pubkey(source_ata_b58) {
                Err(e) => Err(e),
                Ok(source_ata_pk) => match tx.decode_pubkey(dest_ata_b58) {
                  Err(e) => Err(e),
                  Ok(dest_ata_pk) => match rpc.get_mint_decimals(rpc_url, req.asset) {
                    Err(e) => Err(e),
                    Ok(decimals) => match rpc.get_latest_blockhash(rpc_url) {
                      Err(e) => Err(e),
                      Ok(blockhash) => assemble_and_sign(req, signer, fee_payer_pk, payer_pk, mint_pk, source_ata_pk, dest_ata_pk, amount, decimals, blockhash),
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  }
}

fn assemble_and_sign(req :: types.Requirements, signer :: solana.Signer, fee_payer_pk :: Bytes, payer_pk :: Bytes, mint_pk :: Bytes, source_ata_pk :: Bytes, dest_ata_pk :: Bytes, amount :: Int, decimals :: Int, blockhash :: Bytes) -> Result[Str, Str] {
  match tx.compute_budget_program_id() {
    Err(e) => Err(e),
    Ok(cb_pid) => match tx.token_program_id() {
      Err(e) => Err(e),
      Ok(token_pid) => {
        let instructions := [tx.set_compute_unit_limit(cb_pid, compute_unit_limit()), tx.set_compute_unit_price(cb_pid, compute_unit_price_micro_lamports()), tx.transfer_checked(token_pid, source_ata_pk, mint_pk, dest_ata_pk, payer_pk, amount, decimals)]
        match tx.build_message(fee_payer_pk, blockhash, instructions) {
          Err(e) => Err(e),
          Ok(message) => match tx.unsigned_wire_transaction(fee_payer_pk, blockhash, instructions) {
            Err(e) => Err(e),
            Ok(wire) => match crypto.base64url_decode(signer.secret_b64url) {
              Err(_) => Err("svm_client: signer secret is not valid base64url"),
              Ok(secret) => match tx.sign_into(wire, fee_payer_pk, instructions, secret, payer_pk, message) {
                Err(e) => Err(e),
                Ok(signed_wire) => Ok(types.encode_header(payload_json(req, crypto.base64_encode(signed_wire)))),
              },
            },
          },
        }
      },
    },
  }
}

fn parse_amount(s :: Str) -> Result[Int, Str] {
  match str.to_int(s) {
    Some(n) => Ok(n),
    None => Err(str.concat("svm_client: max_amount_required is not a valid integer: ", s)),
  }
}

fn json_escape(s :: Str) -> Str {
  let a := str.join(str.split(s, "\\"), "\\\\")
  str.join(str.split(a, "\""), "\\\"")
}

# The V2 PaymentPayload envelope: x402Version, an optional `resource`
# description, the `accepted` requirement mirrored back (field name
# `amount`, matching what the facilitator itself sent), and the
# scheme-specific `payload`.
fn payload_json(req :: types.Requirements, tx_b64 :: Str) -> Str {
  str.join(["{\"x402Version\":", int.to_str(types.version()), ",\"resource\":{\"url\":\"", json_escape(req.resource), "\",\"description\":\"", json_escape(req.description), "\",\"mimeType\":\"", json_escape(req.mime_type), "\"},\"accepted\":", accepted_json(req), ",\"payload\":{\"transaction\":\"", tx_b64, "\"}}"], "")
}

fn accepted_json(req :: types.Requirements) -> Str {
  str.join(["{\"scheme\":\"", req.scheme, "\",\"network\":\"", req.network, "\",\"amount\":\"", req.max_amount_required, "\",\"asset\":\"", req.asset, "\",\"payTo\":\"", req.pay_to, "\",\"maxTimeoutSeconds\":", int.to_str(req.max_timeout_seconds), ",\"extra\":{\"feePayer\":\"", req.fee_payer, "\"}}"], "")
}

