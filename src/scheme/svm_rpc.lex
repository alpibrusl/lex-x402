# Minimal Solana JSON-RPC client -- just the handful of read-only calls the
# `exact` SVM payment builder needs (blockhash, mint decimals, an owner's
# existing token account for a mint). No wallet/keypair logic here; this
# module only ever reads chain state, never submits a transaction (the
# facilitator broadcasts during settlement).

import "std.str" as str

import "std.int" as int

import "std.map" as map

import "std.list" as list

import "std.http" as http

import "std.bytes" as bytes

import "std.crypto" as crypto

import "lex-schema/json_value" as jv

# Default public RPC endpoints per x402 network id. Callers needing a
# private/paid RPC (recommended for anything beyond light testing) pass
# their own `rpc_url` instead of relying on this.
fn default_rpc_url(network :: Str) -> Str {
  if str.contains(network, "devnet") {
    "https://api.devnet.solana.com"
  } else {
    "https://api.mainnet-beta.solana.com"
  }
}

fn rpc_call(rpc_url :: Str, method :: Str, params_json_array :: Str) -> [net] Result[jv.Json, Str] {
  let body_text := str.join(["{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"", method, "\",\"params\":", params_json_array, "}"], "")
  let req0 := { method: "POST", url: rpc_url, headers: map.new(), body: Some(bytes.from_str(body_text)), timeout_ms: Some(15000) }
  let req1 := http.with_header(req0, "Content-Type", "application/json")
  match http.send(req1) {
    Err(_) => Err(str.concat("svm_rpc: request to ", str.concat(rpc_url, " failed"))),
    Ok(resp) => if resp.status >= 200 and resp.status < 300 {
      match http.text_body(resp) {
        Err(_) => Err("svm_rpc: could not read response body"),
        Ok(text) => parse_rpc_response(method, text),
      }
    } else {
      Err(str.join(["svm_rpc: ", method, " returned HTTP ", int.to_str(resp.status)], ""))
    },
  }
}

fn parse_rpc_response(method :: Str, text :: Str) -> Result[jv.Json, Str] {
  match jv.parse(text) {
    Err(e) => Err(str.join(["svm_rpc: ", method, " returned bad json: ", e.message], "")),
    Ok(j) => match jv.get_field(j, "error") {
      Some(err_j) => Err(str.join(["svm_rpc: ", method, " rpc error: ", rpc_error_message(err_j)], "")),
      None => match jv.get_field(j, "result") {
        None => Err(str.concat("svm_rpc: response missing result field for ", method)),
        Some(r) => Ok(r),
      },
    },
  }
}

fn rpc_error_message(err_j :: jv.Json) -> Str {
  match jv.get_field(err_j, "message") {
    Some(v) => match jv.as_str(v) {
      Some(s) => s,
      None => "(no message)",
    },
    None => "(no message)",
  }
}

fn json_str_field(j :: jv.Json, key :: Str) -> Str {
  match jv.get_field(j, key) {
    None => "",
    Some(v) => match jv.as_str(v) {
      None => "",
      Some(s) => s,
    },
  }
}

# getLatestBlockhash -- the transaction's lifetime anchor. Returns raw
# 32 bytes (decoded from the RPC's base58 string) ready for build_message.
fn get_latest_blockhash(rpc_url :: Str) -> [net] Result[Bytes, Str] {
  match rpc_call(rpc_url, "getLatestBlockhash", "[{\"commitment\":\"confirmed\"}]") {
    Err(e) => Err(e),
    Ok(result) => match jv.get_field(result, "value") {
      None => Err("svm_rpc: getLatestBlockhash response missing value"),
      Some(value) => {
        let hash_b58 := json_str_field(value, "blockhash")
        if str.len(hash_b58) == 0 {
          Err("svm_rpc: getLatestBlockhash response missing blockhash string")
        } else {
          match crypto.base58_decode(hash_b58) {
            Err(e) => Err(str.concat("svm_rpc: blockhash is not valid base58: ", e)),
            Ok(raw) => if bytes.len(raw) == 32 {
              Ok(raw)
            } else {
              Err("svm_rpc: blockhash did not decode to 32 bytes")
            },
          }
        }
      },
    },
  }
}

# getAccountInfo with base64 encoding -- the account's raw data bytes.
fn get_account_info_base64(rpc_url :: Str, address_b58 :: Str) -> [net] Result[Bytes, Str] {
  let params := str.join(["[\"", address_b58, "\", {\"encoding\":\"base64\"}]"], "")
  match rpc_call(rpc_url, "getAccountInfo", params) {
    Err(e) => Err(e),
    Ok(result) => match jv.get_field(result, "value") {
      None => Err(str.concat("svm_rpc: account not found: ", address_b58)),
      Some(JNull) => Err(str.concat("svm_rpc: account not found: ", address_b58)),
      Some(value) => match jv.get_field(value, "data") {
        None => Err("svm_rpc: getAccountInfo response missing data"),
        Some(data_j) => match jv.as_list(data_j) {
          None => Err("svm_rpc: getAccountInfo data is not the expected [base64, encoding] pair"),
          Some(items) => match list.head(items) {
            None => Err("svm_rpc: getAccountInfo data array is empty"),
            Some(first) => match jv.as_str(first) {
              None => Err("svm_rpc: getAccountInfo data[0] is not a string"),
              Some(b64) => match crypto.base64_decode(b64) {
                Err(e) => Err(str.concat("svm_rpc: account data is not valid base64: ", e)),
                Ok(raw) => Ok(raw),
              },
            },
          },
        },
      },
    },
  }
}

# SPL Token Mint account layout (Token Program, 82 bytes):
# 0..4 mintAuthorityOption, 4..36 mintAuthority, 36..44 supply (u64 LE),
# 44 decimals (u8), 45 isInitialized, 46..50 freezeAuthorityOption,
# 50..82 freezeAuthority. Decimals is the one field this module needs.
fn get_mint_decimals(rpc_url :: Str, mint_b58 :: Str) -> [net] Result[Int, Str] {
  match get_account_info_base64(rpc_url, mint_b58) {
    Err(e) => Err(e),
    Ok(data) => if bytes.len(data) < 45 {
      Err(str.concat("svm_rpc: mint account data too short to be a valid SPL Mint: ", mint_b58))
    } else {
      bytes.u8_at(data, 44)
    },
  }
}

# getTokenAccountsByOwner -- the real, already-created token account
# address for (owner, mint), read directly from chain rather than derived
# (sidesteps Associated Token Account PDA derivation, which needs an
# off-curve validity search this codebase doesn't implement). Errors
# clearly if the owner has no token account for this mint yet -- creating
# one is a real on-chain action outside this module's (read-only) scope.
fn find_token_account(rpc_url :: Str, owner_b58 :: Str, mint_b58 :: Str) -> [net] Result[Str, Str] {
  let params := str.join(["[\"", owner_b58, "\", {\"mint\":\"", mint_b58, "\"}, {\"encoding\":\"jsonParsed\"}]"], "")
  match rpc_call(rpc_url, "getTokenAccountsByOwner", params) {
    Err(e) => Err(e),
    Ok(result) => match jv.get_field(result, "value") {
      None => Err(no_token_account_err(owner_b58, mint_b58)),
      Some(value_j) => match jv.as_list(value_j) {
        None => Err(no_token_account_err(owner_b58, mint_b58)),
        Some(items) => match list.head(items) {
          None => Err(no_token_account_err(owner_b58, mint_b58)),
          Some(first) => {
            let pubkey := json_str_field(first, "pubkey")
            if str.len(pubkey) == 0 {
              Err("svm_rpc: getTokenAccountsByOwner entry missing pubkey")
            } else {
              Ok(pubkey)
            }
          },
        },
      },
    },
  }
}

fn no_token_account_err(owner_b58 :: Str, mint_b58 :: Str) -> Str {
  str.join(["svm_rpc: ", owner_b58, " has no token account for mint ", mint_b58, " yet -- one must exist on-chain before a transferChecked can reference it (this module only reads chain state, it does not create accounts)"], "")
}

