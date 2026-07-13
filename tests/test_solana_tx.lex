# solana_tx.lex tests — pure byte-layer checks against known Solana wire
# format vectors (no RPC, no live network).

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "std.int" as int

import "../src/scheme/solana_tx" as tx

fn assert_bytes_eq(label :: Str, got :: Bytes, want :: List[Int]) -> Result[Unit, Str] {
  let want_bytes := bytes.concat_all(list.map(want, fn (b :: Int) -> Bytes {
    bytes.u8(b)
  }))
  if bytes.eq(got, want_bytes) {
    Ok(())
  } else {
    Err(str.join([label, ": byte mismatch (len got=", int.to_str(bytes.len(got)), " want=", int.to_str(bytes.len(want_bytes)), ")"], ""))
  }
}

# Canonical shortvec test vectors (from Solana's own docs/reference impls):
# single-byte for < 128, two bytes crossing the boundary, three bytes for
# the next boundary.
fn test_compact_u16_single_byte() -> Result[Unit, Str] {
  match assert_bytes_eq("compact_u16(0)", tx.compact_u16(0), [0]) {
    Err(e) => Err(e),
    Ok(_) => match assert_bytes_eq("compact_u16(1)", tx.compact_u16(1), [1]) {
      Err(e) => Err(e),
      Ok(_) => assert_bytes_eq("compact_u16(127)", tx.compact_u16(127), [127]),
    },
  }
}

fn test_compact_u16_two_bytes() -> Result[Unit, Str] {
  match assert_bytes_eq("compact_u16(128)", tx.compact_u16(128), [128, 1]) {
    Err(e) => Err(e),
    Ok(_) => match assert_bytes_eq("compact_u16(300)", tx.compact_u16(300), [172, 2]) {
      Err(e) => Err(e),
      Ok(_) => assert_bytes_eq("compact_u16(16383)", tx.compact_u16(16383), [255, 127]),
    },
  }
}

fn test_compact_u16_three_bytes() -> Result[Unit, Str] {
  assert_bytes_eq("compact_u16(16384)", tx.compact_u16(16384), [128, 128, 1])
}

fn test_decode_pubkey_known_addresses() -> Result[Unit, Str] {
  match tx.decode_pubkey("6zmfwgnYVMhnKSJKFetkqtgQ3U2h6QdEbjAE7jmGxSc2") {
    Err(e) => Err(str.concat("merchant address failed to decode: ", e)),
    Ok(pk) => if bytes.len(pk) == 32 {
      match tx.decode_pubkey("FGDYmR8zKEucYLwcSJ3Rra6Gi62LqvGHMM9vk7sTjDNV") {
        Err(e) => Err(str.concat("payer address failed to decode: ", e)),
        Ok(pk2) => if bytes.len(pk2) == 32 {
          Ok(())
        } else {
          Err("payer address did not decode to 32 bytes")
        },
      }
    } else {
      Err("merchant address did not decode to 32 bytes")
    },
  }
}

# base58 "1" repeated decodes to that many leading zero bytes (1:1) -- 30 of
# them is a valid base58 string that decodes to 30 bytes, one short of a
# real 32-byte pubkey. decode_pubkey must reject it rather than silently
# padding/truncating.
fn test_decode_pubkey_rejects_bad_length() -> Result[Unit, Str] {
  match tx.decode_pubkey("111111111111111111111111111111") {
    Err(_) => Ok(()),
    Ok(_) => Err("expected a decode error for a base58 string that decodes to 30 bytes, not 32"),
  }
}

fn test_set_compute_unit_limit_discriminator() -> Result[Unit, Str] {
  match tx.compute_budget_program_id() {
    Err(e) => Err(e),
    Ok(pid) => {
      let ix := tx.set_compute_unit_limit(pid, 1)
      assert_bytes_eq("SetComputeUnitLimit(1)", ix.data, [2, 1, 0, 0, 0])
    },
  }
}

fn test_set_compute_unit_price_discriminator() -> Result[Unit, Str] {
  match tx.compute_budget_program_id() {
    Err(e) => Err(e),
    Ok(pid) => {
      let ix := tx.set_compute_unit_price(pid, 1)
      assert_bytes_eq("SetComputeUnitPrice(1)", ix.data, [3, 1, 0, 0, 0, 0, 0, 0, 0])
    },
  }
}

fn test_transfer_checked_discriminator() -> Result[Unit, Str] {
  match tx.token_program_id() {
    Err(e) => Err(e),
    Ok(pid) => match tx.decode_pubkey("6zmfwgnYVMhnKSJKFetkqtgQ3U2h6QdEbjAE7jmGxSc2") {
      Err(e) => Err(e),
      Ok(addr) => {
        let ix := tx.transfer_checked(pid, addr, addr, addr, addr, 10000, 6)
        assert_bytes_eq("TransferChecked(10000, 6)", ix.data, [12, 16, 39, 0, 0, 0, 0, 0, 0, 6])
      },
    },
  }
}

fn payer_pk() -> Bytes {
  match tx.decode_pubkey("FGDYmR8zKEucYLwcSJ3Rra6Gi62LqvGHMM9vk7sTjDNV") {
    Ok(pk) => pk,
    Err(_) => bytes.from_str(""),
  }
}

fn merchant_pk() -> Bytes {
  match tx.decode_pubkey("6zmfwgnYVMhnKSJKFetkqtgQ3U2h6QdEbjAE7jmGxSc2") {
    Ok(pk) => pk,
    Err(_) => bytes.from_str(""),
  }
}

fn fake_blockhash() -> Bytes {
  bytes.concat_all(list.map(list.range(0, 32), fn (_i :: Int) -> Bytes {
    bytes.u8(7)
  }))
}

# The fee payer must always land at account-key index 0 -- the whole point
# of seeding collect_keys with it first. This is the single most
# consequential ordering fact in the message: a wrong fee-payer index means
# a transaction with the wrong signer paying (or a totally invalid tx).
# Byte offset math: version(1) + header(3) + compact_u16 count(1, since
# < 128 keys) = byte 5 is the start of account_keys; first 32 bytes there
# must equal the fee payer.
fn test_fee_payer_is_first_account_key() -> Result[Unit, Str] {
  match tx.token_program_id() {
    Err(e) => Err(e),
    Ok(token_pid) => {
      let payer := payer_pk()
      let merchant := merchant_pk()
      let ix := tx.transfer_checked(token_pid, payer, merchant, merchant, payer, 10000, 6)
      match tx.build_message(payer, fake_blockhash(), [ix]) {
        Err(e) => Err(str.concat("build_message failed: ", e)),
        Ok(msg) => {
          let first_key := bytes.slice(msg, 5, 37)
          if bytes.eq(first_key, payer) {
            Ok(())
          } else {
            Err("fee payer is not at account_keys index 0")
          }
        },
      }
    },
  }
}

# num_required_signatures must count the fee payer once even though it's
# ALSO the transfer authority in this test (same key, two roles) -- a
# naive implementation might double-count or miss the merge.
fn test_message_header_signer_count_dedupes_fee_payer_as_authority() -> Result[Unit, Str] {
  match tx.token_program_id() {
    Err(e) => Err(e),
    Ok(token_pid) => {
      let payer := payer_pk()
      let merchant := merchant_pk()
      let ix := tx.transfer_checked(token_pid, payer, merchant, merchant, payer, 10000, 6)
      match tx.build_message(payer, fake_blockhash(), [ix]) {
        Err(e) => Err(str.concat("build_message failed: ", e)),
        Ok(msg) => match bytes.u8_at(msg, 1) {
          Err(e) => Err(e),
          Ok(num_signers) => if num_signers == 1 {
            Ok(())
          } else {
            Err(str.concat("expected 1 required signer (payer==authority deduped), got ", int.to_str(num_signers)))
          },
        },
      }
    },
  }
}

# When the fee payer is DIFFERENT from the transfer authority (the real
# x402 shape: the facilitator sponsors gas, the client authorizes the
# transfer), both must be counted as required signers.
fn test_message_header_signer_count_two_distinct_signers() -> Result[Unit, Str] {
  match tx.token_program_id() {
    Err(e) => Err(e),
    Ok(token_pid) => {
      let payer := payer_pk()
      let merchant := merchant_pk()
      let ix := tx.transfer_checked(token_pid, payer, merchant, merchant, payer, 10000, 6)
      match tx.build_message(merchant, fake_blockhash(), [ix]) {
        Err(e) => Err(str.concat("build_message failed: ", e)),
        Ok(msg) => match bytes.u8_at(msg, 1) {
          Err(e) => Err(e),
          Ok(num_signers) => if num_signers == 2 {
            Ok(())
          } else {
            Err(str.concat("expected 2 required signers (fee payer + authority), got ", int.to_str(num_signers)))
          },
        },
      }
    },
  }
}

# Byte offset math: compact_u16(2) signatures prefix = 1 byte, then 2*64
# zero bytes.
fn test_unsigned_wire_transaction_has_zeroed_signature_slots() -> Result[Unit, Str] {
  match tx.token_program_id() {
    Err(e) => Err(e),
    Ok(token_pid) => {
      let payer := payer_pk()
      let merchant := merchant_pk()
      let ix := tx.transfer_checked(token_pid, payer, merchant, merchant, payer, 10000, 6)
      match tx.unsigned_wire_transaction(merchant, fake_blockhash(), [ix]) {
        Err(e) => Err(str.concat("unsigned_wire_transaction failed: ", e)),
        Ok(wire) => {
          let sig_area := bytes.slice(wire, 1, 129)
          let zeros := bytes.concat_all(list.map(list.range(0, 128), fn (_i :: Int) -> Bytes {
            bytes.u8(0)
          }))
          if bytes.eq(sig_area, zeros) {
            Ok(())
          } else {
            Err("expected both signature slots to be zeroed before signing")
          }
        },
      }
    },
  }
}

fn suite() -> List[Result[Unit, Str]] {
  [test_compact_u16_single_byte(), test_compact_u16_two_bytes(), test_compact_u16_three_bytes(), test_decode_pubkey_known_addresses(), test_decode_pubkey_rejects_bad_length(), test_set_compute_unit_limit_discriminator(), test_set_compute_unit_price_discriminator(), test_transfer_checked_discriminator(), test_fee_payer_is_first_account_key(), test_message_header_signer_count_dedupes_fee_payer_as_authority(), test_message_header_signer_count_two_distinct_signers(), test_unsigned_wire_transaction_has_zeroed_signature_slots()]
}

fn run_all() -> Unit {
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

