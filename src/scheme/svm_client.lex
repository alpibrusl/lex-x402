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
#   - Compute-unit estimation via simulation: uses a fixed conservative
#     unit limit (see `compute_unit_limit`) instead of calling
#     simulateTransaction. Good enough to not run out of compute for a
#     single transferChecked; a real production path could tighten this.
#
# Associated Token Accounts (source and destination) are derived via
# solana_tx.associated_token_address (a real PDA search, verified against
# a live on-chain account this session) and always created idempotently
# in the same transaction -- CreateIdempotent is a no-op if the account
# already exists, so this never needs a "does it exist yet" RPC round
# trip before committing to instructions. The fee payer (the
# facilitator's sponsor) funds the rent for any account that doesn't
# exist yet, consistent with it sponsoring the transaction's gas too.

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
        Ok(payer_pk) => match tx.decode_pubkey(req.pay_to) {
          Err(e) => Err(e),
          Ok(merchant_pk) => match tx.decode_pubkey(req.asset) {
            Err(e) => Err(e),
            Ok(mint_pk) => match tx.token_program_id() {
              Err(e) => Err(e),
              Ok(token_pid) => match tx.associated_token_address(payer_pk, mint_pk, token_pid) {
                Err(e) => Err(e),
                Ok(source_ata_pk) => match tx.associated_token_address(merchant_pk, mint_pk, token_pid) {
                  Err(e) => Err(e),
                  Ok(dest_ata_pk) => match rpc.get_mint_decimals(rpc_url, req.asset) {
                    Err(e) => Err(e),
                    Ok(decimals) => match rpc.get_latest_blockhash(rpc_url) {
                      Err(e) => Err(e),
                      Ok(blockhash) => assemble_and_sign(req, signer, fee_payer_pk, payer_pk, merchant_pk, mint_pk, token_pid, source_ata_pk, dest_ata_pk, amount, decimals, blockhash),
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

fn assemble_and_sign(req :: types.Requirements, signer :: solana.Signer, fee_payer_pk :: Bytes, payer_pk :: Bytes, merchant_pk :: Bytes, mint_pk :: Bytes, token_pid :: Bytes, source_ata_pk :: Bytes, dest_ata_pk :: Bytes, amount :: Int, decimals :: Int, blockhash :: Bytes) -> Result[Str, Str] {
  match tx.compute_budget_program_id() {
    Err(e) => Err(e),
    Ok(cb_pid) => match tx.system_program_id() {
      Err(e) => Err(e),
      Ok(sys_pid) => match tx.associated_token_program_id() {
        Err(e) => Err(e),
        Ok(ata_pid) => {
          let create_source := tx.create_associated_token_account_idempotent(ata_pid, fee_payer_pk, source_ata_pk, payer_pk, mint_pk, sys_pid, token_pid)
          let create_dest := tx.create_associated_token_account_idempotent(ata_pid, fee_payer_pk, dest_ata_pk, merchant_pk, mint_pk, sys_pid, token_pid)
          let transfer := tx.transfer_checked(token_pid, source_ata_pk, mint_pk, dest_ata_pk, payer_pk, amount, decimals)
          let instructions := [tx.set_compute_unit_limit(cb_pid, compute_unit_limit()), tx.set_compute_unit_price(cb_pid, compute_unit_price_micro_lamports()), create_source, create_dest, transfer]
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
    },
  }
}

fn parse_amount(s :: Str) -> Result[Int, Str] {
  match str.to_int(s) {
    Some(n) => Ok(n),
    None => Err(str.concat("svm_client: max_amount_required is not a valid integer: ", s)),
  }
}

# The V2 PaymentPayload envelope: x402Version, an optional `resource`
# description, the `accepted` requirement mirrored back (shared with
# facilitator.lex's own paymentRequirements echo via
# types.requirements_v2_json, so both stay in the same V2 shape a real
# facilitator expects), and the scheme-specific `payload`.
fn payload_json(req :: types.Requirements, tx_b64 :: Str) -> Str {
  str.join(["{\"x402Version\":", int.to_str(types.version()), ",\"resource\":{\"url\":\"", types.json_escape(req.resource), "\",\"description\":\"", types.json_escape(req.description), "\",\"mimeType\":\"", types.json_escape(req.mime_type), "\"},\"accepted\":", types.requirements_v2_json(req), ",\"payload\":{\"transaction\":\"", tx_b64, "\"}}"], "")
}

