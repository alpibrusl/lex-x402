# Real Solana versioned (v0) transaction serialization for the `exact` scheme
# (#93/OP5 follow-up to the epic; supersedes the EIP-3009-style envelope in
# exact_solana.lex — see its header comment).
#
# This module is PURE byte-layer serialization: given account keys, a
# blockhash, and instructions already decided by the caller, it produces the
# exact bytes the Solana wire format expects. It deliberately does NOT touch
# the network — no RPC calls, no blockhash fetch, no ATA lookup. That's a
# separate, follow-up integration layer; keeping this module pure means every
# byte here is independently checkable against the known wire format without
# a live cluster.
#
# Reference shape (verified against the real x402 TypeScript SVM client,
# `@solana/kit`'s wire encoding):
#   wire_transaction := compact_array(signatures) ++ versioned_message
#   versioned_message := version_byte(0x80 | 0)
#                        ++ header(3 bytes: num_required_signatures,
#                                  num_readonly_signed, num_readonly_unsigned)
#                        ++ compact_array(account_keys, 32 bytes each)
#                        ++ recent_blockhash(32 bytes)
#                        ++ compact_array(instructions)
#                        ++ compact_array(address_table_lookups)  -- empty, no ALT
#   instruction := program_id_index(u8)
#                  ++ compact_array(account_indices, u8 each)
#                  ++ compact_array(data_bytes)
#
# Account key ordering (the part most implementations get wrong): fee payer
# first, then remaining signers, writable before readonly within each of
# {signer, non-signer} — see `order_accounts`.

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.str" as str

import "std.list" as list

import "std.int" as int

# A single account reference within an instruction, before key-list ordering.
type AccountMeta = { pubkey :: Bytes, is_signer :: Bool, is_writable :: Bool }

# An instruction before account-index resolution — accounts are still full
# pubkeys here; `build_message` resolves them against the final ordered key
# list.
type RawInstruction = { program_id :: Bytes, accounts :: List[AccountMeta], data :: Bytes }

fn bool_not(b :: Bool) -> Bool {
  if b {
    false
  } else {
    true
  }
}

fn bool_and(a :: Bool, b :: Bool) -> Bool {
  if a {
    b
  } else {
    false
  }
}

fn bool_or(a :: Bool, b :: Bool) -> Bool {
  if a {
    true
  } else {
    b
  }
}

fn decode_pubkey(b58 :: Str) -> Result[Bytes, Str] {
  match crypto.base58_decode(b58) {
    Err(e) => Err(str.concat("solana_tx: invalid base58 pubkey: ", e)),
    Ok(raw) => if bytes.len(raw) == 32 {
      Ok(raw)
    } else {
      Err(str.join(["solana_tx: pubkey must decode to 32 bytes, got ", int.to_str(bytes.len(raw))], ""))
    },
  }
}

# Solana's "compact-u16" (shortvec) length/value encoding: 7 bits per byte,
# little-endian, MSB of each byte set iff more bytes follow. Values here are
# always small (account/instruction counts, byte lengths within one
# transaction, all comfortably < 2^16) so a straightforward 3-byte-max
# encoding covers every real case.
fn compact_u16(n :: Int) -> Bytes {
  if n < 128 {
    bytes.u8(n)
  } else {
    if n < 16384 {
      bytes.concat(bytes.u8(bit_or(mod128(n), 128)), bytes.u8(n / 128))
    } else {
      bytes.concat_all([bytes.u8(bit_or(mod128(n), 128)), bytes.u8(bit_or(mod128(n / 128), 128)), bytes.u8(n / 16384)])
    }
  }
}

fn mod128(n :: Int) -> Int {
  n - n / 128 * 128
}

# n has bit 0x80 clear by construction (mod128/div results) OR-ing in 0x80 is
# just an addition in that case.
fn bit_or(n :: Int, flag :: Int) -> Int {
  n + flag
}

fn compact_bytes(b :: Bytes) -> Bytes {
  bytes.concat(compact_u16(bytes.len(b)), b)
}

fn compact_array(items :: List[Bytes]) -> Bytes {
  bytes.concat(compact_u16(list.len(items)), bytes.concat_all(items))
}

# ---- Instruction builders (SPL Token + ComputeBudget) --------------------
# Program ids are well-known constants, not derived.
fn token_program_id() -> Result[Bytes, Str] {
  decode_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

fn compute_budget_program_id() -> Result[Bytes, Str] {
  decode_pubkey("ComputeBudget111111111111111111111111111111")
}

# ComputeBudget instruction discriminator 2: SetComputeUnitLimit(u32 units).
fn set_compute_unit_limit(program_id :: Bytes, units :: Int) -> RawInstruction {
  { program_id: program_id, accounts: [], data: bytes.concat(bytes.u8(2), bytes.u32_le(units)) }
}

# ComputeBudget instruction discriminator 3: SetComputeUnitPrice(u64 micro_lamports).
fn set_compute_unit_price(program_id :: Bytes, micro_lamports :: Int) -> RawInstruction {
  { program_id: program_id, accounts: [], data: bytes.concat(bytes.u8(3), bytes.u64_le(micro_lamports)) }
}

# SPL Token instruction discriminator 12: TransferChecked(u64 amount, u8 decimals).
# Accounts, in order: source (writable), mint (readonly), destination
# (writable), authority (signer, readonly unless it's also the fee payer).
fn transfer_checked(program_id :: Bytes, source :: Bytes, mint :: Bytes, destination :: Bytes, authority :: Bytes, amount :: Int, decimals :: Int) -> RawInstruction {
  let accounts := [{ pubkey: source, is_signer: false, is_writable: true }, { pubkey: mint, is_signer: false, is_writable: false }, { pubkey: destination, is_signer: false, is_writable: true }, { pubkey: authority, is_signer: true, is_writable: false }]
  { program_id: program_id, accounts: accounts, data: bytes.concat_all([bytes.u8(12), bytes.u64_le(amount), bytes.u8(decimals)]) }
}

# ---- Account key ordering -------------------------------------------------
type OrderedKey = { pubkey :: Bytes, b58 :: Str, is_signer :: Bool, is_writable :: Bool }

fn key_b58(pk :: Bytes) -> Str {
  crypto.base58_encode(pk)
}

# Merge one account's flags into the accumulated per-key metadata: a pubkey
# referenced as writable by ANY instruction (or as the fee payer) is
# writable overall, even if another instruction only reads it. Same for
# is_signer.
fn merge_into(acc :: List[OrderedKey], pk :: Bytes, is_signer :: Bool, is_writable :: Bool) -> List[OrderedKey] {
  let b58 := key_b58(pk)
  let found := list.fold(acc, false, fn (f :: Bool, k :: OrderedKey) -> Bool {
    if f {
      true
    } else {
      k.b58 == b58
    }
  })
  if found {
    list.map(acc, fn (k :: OrderedKey) -> OrderedKey {
      if k.b58 == b58 {
        { pubkey: k.pubkey, b58: k.b58, is_signer: bool_or(k.is_signer, is_signer), is_writable: bool_or(k.is_writable, is_writable) }
      } else {
        k
      }
    })
  } else {
    list.concat(acc, [{ pubkey: pk, b58: b58, is_signer: is_signer, is_writable: is_writable }])
  }
}

# Fold every instruction's program id (readonly, non-signer -- program ids
# are never signers) and every account meta into one deduplicated key set,
# seeded with the fee payer (always signer + writable, index 0).
fn collect_keys(fee_payer :: Bytes, instructions :: List[RawInstruction]) -> List[OrderedKey] {
  let seeded := [{ pubkey: fee_payer, b58: key_b58(fee_payer), is_signer: true, is_writable: true }]
  list.fold(instructions, seeded, fn (acc :: List[OrderedKey], ix :: RawInstruction) -> List[OrderedKey] {
    let with_accounts := list.fold(ix.accounts, acc, fn (a :: List[OrderedKey], am :: AccountMeta) -> List[OrderedKey] {
      merge_into(a, am.pubkey, am.is_signer, am.is_writable)
    })
    merge_into(with_accounts, ix.program_id, false, false)
  })
}

# Solana's required ordering: signers before non-signers; writable before
# readonly within each group. Stable within each bucket (first-seen order),
# so the fee payer (seeded first, signer+writable) always lands at index 0.
fn order_keys(keys :: List[OrderedKey]) -> List[OrderedKey] {
  let signer_writable := list.filter(keys, fn (k :: OrderedKey) -> Bool {
    bool_and(k.is_signer, k.is_writable)
  })
  let signer_readonly := list.filter(keys, fn (k :: OrderedKey) -> Bool {
    bool_and(k.is_signer, bool_not(k.is_writable))
  })
  let nonsigner_writable := list.filter(keys, fn (k :: OrderedKey) -> Bool {
    bool_and(bool_not(k.is_signer), k.is_writable)
  })
  let nonsigner_readonly := list.filter(keys, fn (k :: OrderedKey) -> Bool {
    bool_and(bool_not(k.is_signer), bool_not(k.is_writable))
  })
  list.concat(signer_writable, list.concat(signer_readonly, list.concat(nonsigner_writable, nonsigner_readonly)))
}

fn count_if(keys :: List[OrderedKey], pred :: (OrderedKey) -> Bool) -> Int {
  list.fold(keys, 0, fn (n :: Int, k :: OrderedKey) -> Int {
    if pred(k) {
      n + 1
    } else {
      n
    }
  })
}

fn index_of(ordered :: List[OrderedKey], pk :: Bytes) -> Int {
  let target := key_b58(pk)
  match list.fold(ordered, (0, -1), fn (acc :: (Int, Int), k :: OrderedKey) -> (Int, Int) {
    match acc {
      (i, found) => if found >= 0 {
        (i + 1, found)
      } else {
        if k.b58 == target {
          (i + 1, i)
        } else {
          (i + 1, -1)
        }
      },
    }
  }) {
    (_, found) => found,
  }
}

fn encode_instruction(ordered :: List[OrderedKey], ix :: RawInstruction) -> Bytes {
  let program_idx := index_of(ordered, ix.program_id)
  let account_idx_bytes := list.map(ix.accounts, fn (am :: AccountMeta) -> Bytes {
    bytes.u8(index_of(ordered, am.pubkey))
  })
  bytes.concat_all([bytes.u8(program_idx), compact_array(account_idx_bytes), compact_bytes(ix.data)])
}

# Assemble the full versioned (v0) message. `recent_blockhash` must be exactly
# 32 raw bytes (the caller fetches it live via RPC -- out of scope here).
fn build_message(fee_payer :: Bytes, recent_blockhash :: Bytes, instructions :: List[RawInstruction]) -> Result[Bytes, Str] {
  if bytes.len(recent_blockhash) != 32 {
    Err("solana_tx: recent_blockhash must be exactly 32 bytes")
  } else {
    let ordered := order_keys(collect_keys(fee_payer, instructions))
    let num_signers := count_if(ordered, fn (k :: OrderedKey) -> Bool {
      k.is_signer
    })
    let num_readonly_signed := count_if(ordered, fn (k :: OrderedKey) -> Bool {
      bool_and(k.is_signer, bool_not(k.is_writable))
    })
    let num_readonly_unsigned := count_if(ordered, fn (k :: OrderedKey) -> Bool {
      bool_and(bool_not(k.is_signer), bool_not(k.is_writable))
    })
    let header := bytes.concat_all([bytes.u8(num_signers), bytes.u8(num_readonly_signed), bytes.u8(num_readonly_unsigned)])
    let account_keys := compact_array(list.map(ordered, fn (k :: OrderedKey) -> Bytes {
      k.pubkey
    }))
    let ix_bytes := compact_array(list.map(instructions, fn (ix :: RawInstruction) -> Bytes {
      encode_instruction(ordered, ix)
    }))
    let version_byte := bytes.u8(128)
    let empty_alt := compact_u16(0)
    Ok(bytes.concat_all([version_byte, header, account_keys, recent_blockhash, ix_bytes, empty_alt]))
  }
}

# Number of distinct required signers this message needs -- callers use this
# to size the signatures placeholder array before any signing happens.
fn required_signature_count(fee_payer :: Bytes, instructions :: List[RawInstruction]) -> Int {
  count_if(order_keys(collect_keys(fee_payer, instructions)), fn (k :: OrderedKey) -> Bool {
    k.is_signer
  })
}

fn zero_signature() -> Bytes {
  bytes.u8(0)
}

fn zero_signatures(n :: Int) -> Bytes {
  compact_array(list.map(list.range(0, n), fn (_i :: Int) -> Bytes {
    zero_sig_64()
  }))
}

fn zero_sig_64() -> Bytes {
  bytes.concat_all(list.map(list.range(0, 64), fn (_i :: Int) -> Bytes {
    zero_signature()
  }))
}

# Wire transaction with every signature slot zeroed -- the pre-signing shape,
# useful for tests and for computing the exact bytes a signer must sign
# (the message portion, which follows the signatures array unchanged by
# which slots are filled).
fn unsigned_wire_transaction(fee_payer :: Bytes, recent_blockhash :: Bytes, instructions :: List[RawInstruction]) -> Result[Bytes, Str] {
  match build_message(fee_payer, recent_blockhash, instructions) {
    Err(e) => Err(e),
    Ok(message) => Ok(bytes.concat(zero_signatures(required_signature_count(fee_payer, instructions)), message)),
  }
}

# Sign `message` with `secret` (32-byte ed25519 seed) and splice the
# resulting 64-byte signature into `signer_pubkey`'s slot of an
# already-built wire transaction, leaving every other slot (e.g. the
# facilitator's fee-payer slot, filled in later during settlement)
# untouched. Fails if `signer_pubkey` isn't one of this message's signers.
fn sign_into(wire_tx :: Bytes, fee_payer :: Bytes, instructions :: List[RawInstruction], secret :: Bytes, signer_pubkey :: Bytes, message :: Bytes) -> Result[Bytes, Str] {
  let ordered := order_keys(collect_keys(fee_payer, instructions))
  let signers := list.filter(ordered, fn (k :: OrderedKey) -> Bool {
    k.is_signer
  })
  let idx := index_of(signers, signer_pubkey)
  if idx < 0 {
    Err("solana_tx: signer_pubkey is not a required signer of this message")
  } else {
    match crypto.ed25519_sign(secret, message) {
      Err(e) => Err(str.concat("solana_tx: signing failed: ", e)),
      Ok(sig) => {
        let sig_count := list.len(signers)
        let sig_array_prefix_len := bytes.len(compact_u16(sig_count))
        let slot_offset := sig_array_prefix_len + idx * 64
        Ok(bytes.concat_all([bytes.slice(wire_tx, 0, slot_offset), sig, bytes.slice(wire_tx, slot_offset + 64, bytes.len(wire_tx))]))
      },
    }
  }
}

