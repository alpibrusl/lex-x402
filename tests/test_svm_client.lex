# svm_client.lex / svm_rpc.lex tests -- pure boundary only (JSON
# assembly, error-path guards). The actual RPC calls need a live cluster
# and are exercised manually, same reasoning as `run_server` having no
# unit test either: this file locks down everything checkable without
# a network.

import "std.str" as str

import "std.list" as list

import "std.crypto" as crypto

import "lex-schema/json_value" as jv

import "../src/types" as types

import "../src/scheme/exact_solana" as solana

import "../src/scheme/svm_client" as svm_client

import "../src/scheme/svm_rpc" as rpc

fn requirement_with_fee_payer(fee_payer :: Str) -> types.Requirements {
  { scheme: "exact", network: "solana-devnet", max_amount_required: "10000", resource: "https://api.example.com/convert", description: "API call", mime_type: "application/json", pay_to: "MerchantSoLAddr2222222222222222222222222222", max_timeout_seconds: 60, asset: "AssetMint111111111111111111111111111111111", fee_payer: fee_payer }
}

fn fake_signer() -> solana.Signer {
  { secret_b64url: "not-a-real-secret", address: "PayerSoLAddr1111111111111111111111111111111" }
}

# build_payment must refuse up front (no RPC attempt at all) when the
# requirement carries no extra.feePayer -- a clean, specific error rather
# than a confusing failure several RPC calls deep.
fn t_build_payment_requires_fee_payer() -> [net] Result[Unit, Str] {
  match svm_client.build_payment(requirement_with_fee_payer(""), fake_signer(), "") {
    Ok(_) => Err("expected an error when the requirement has no fee_payer"),
    Err(e) => if str.contains(e, "feePayer") {
      Ok(())
    } else {
      Err(str.concat("expected the error to mention feePayer, got: ", e))
    },
  }
}

fn default_rpc_url_devnet() -> Result[Unit, Str] {
  if rpc.default_rpc_url("solana-devnet") == "https://api.devnet.solana.com" {
    Ok(())
  } else {
    Err(str.concat("expected the devnet RPC url, got: ", rpc.default_rpc_url("solana-devnet")))
  }
}

fn default_rpc_url_mainnet() -> Result[Unit, Str] {
  let mainnet_id := "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
  if rpc.default_rpc_url(mainnet_id) == "https://api.mainnet-beta.solana.com" {
    Ok(())
  } else {
    Err(str.concat("expected the mainnet RPC url, got: ", rpc.default_rpc_url(mainnet_id)))
  }
}

# Found live (e2e verification): a real facilitator's devnet CAIP-2 id
# doesn't contain the substring "devnet" -- silently querying mainnet RPC
# for it caused an incorrect "no token account" error against real
# devnet addresses.
fn default_rpc_url_devnet_caip2() -> Result[Unit, Str] {
  let devnet_caip2 := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
  if rpc.default_rpc_url(devnet_caip2) == "https://api.devnet.solana.com" {
    Ok(())
  } else {
    Err(str.concat("expected the devnet RPC url for the CAIP-2 devnet id, got: ", rpc.default_rpc_url(devnet_caip2)))
  }
}

# The final PAYMENT-SIGNATURE header is a real V2 envelope: x402Version,
# a top-level `accepted` mirroring the requirement (field `amount`, not
# `maxAmountRequired`), and payload.transaction carrying the wire tx.
fn t_payload_json_is_v2_shape() -> Result[Unit, Str] {
  let req := requirement_with_fee_payer("FeePayerSoLAddr33333333333333333333333333333")
  let hdr := svm_client.payload_json(req, "BASE64TXBYTES")
  match jv.parse(hdr) {
    Err(e) => Err(str.concat("payload_json is not valid json: ", e.message)),
    Ok(j) => match jv.get_field(j, "accepted") {
      None => Err("expected a top-level accepted field"),
      Some(accepted) => {
        let amount := get_json_str(accepted, "amount")
        let fee_payer := get_nested_json_str(accepted, "extra", "feePayer")
        let tx := get_nested_json_str(j, "payload", "transaction")
        if amount == "10000" {
          if fee_payer == "FeePayerSoLAddr33333333333333333333333333333" {
            if tx == "BASE64TXBYTES" {
              Ok(())
            } else {
              Err(str.concat("expected payload.transaction to carry the wire tx, got: ", tx))
            }
          } else {
            Err(str.concat("expected accepted.extra.feePayer to mirror the requirement, got: ", fee_payer))
          }
        } else {
          Err(str.concat("expected accepted.amount (V2 field name, not maxAmountRequired), got: ", amount))
        }
      },
    },
  }
}

fn get_json_str(j :: jv.Json, key :: Str) -> Str {
  match jv.get_field(j, key) {
    None => "",
    Some(v) => match jv.as_str(v) {
      None => "",
      Some(s) => s,
    },
  }
}

fn get_nested_json_str(j :: jv.Json, outer :: Str, inner :: Str) -> Str {
  match jv.get_field(j, outer) {
    None => "",
    Some(o) => get_json_str(o, inner),
  }
}

fn suite() -> [net] List[Result[Unit, Str]] {
  [t_build_payment_requires_fee_payer(), default_rpc_url_devnet(), default_rpc_url_mainnet(), default_rpc_url_devnet_caip2(), t_payload_json_is_v2_shape()]
}

fn run_all() -> [net] Unit {
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
    let __force_fail := 1 / 0
    ()
  }
}

