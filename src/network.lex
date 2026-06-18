# CAIP-2 network identifiers and family classification for x402.
#
# x402 carries the target chain in the `network` field of every
# PaymentRequirements / PaymentPayload. We model the chain *family*
# (which signing scheme applies) so the client can route to the right
# scheme module: EVM (`eip155:*`) -> the `exact_evm` scheme (EIP-3009,
# blocked on lex-lang #655); Solana (`solana:*`) -> the `exact_solana`
# scheme (ed25519, buildable today).

import "std.str" as str

type Family = Evm | Solana | Unknown

# Classify a network identifier by CAIP-2 namespace. Accepts both the
# CAIP-2 form ("eip155:8453", "solana:5eykt...") and the x402 short
# names ("base", "solana") still seen in transports-v1 traffic.
fn family(network :: Str) -> Family
  examples {
    family("eip155:8453") => Evm,
    family("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp") => Solana,
    family("base") => Evm,
    family("solana") => Solana,
    family("near:mainnet") => Unknown
  }
{
  if str.starts_with(network, "eip155:") {
    Evm
  } else {
    if str.starts_with(network, "solana:") {
      Solana
    } else {
      short_family(network)
    }
  }
}

# x402 transports-v1 short names, mapped to a family.
fn short_family(network :: Str) -> Family
  examples {
    short_family("base") => Evm,
    short_family("base-sepolia") => Evm,
    short_family("solana") => Solana,
    short_family("solana-devnet") => Solana,
    short_family("near") => Unknown
  }
{
  if network == "solana" or network == "solana-devnet" {
    Solana
  } else {
    if network == "base" or network == "base-sepolia" or network == "avalanche" or network == "avalanche-fuji" {
      Evm
    } else {
      Unknown
    }
  }
}

# CAIP-2 identifier for the canonical Solana mainnet (first 32 chars of
# the genesis hash, per the CAIP-2 `solana` namespace).
fn solana_mainnet() -> Str
  examples {
    solana_mainnet() => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
  }
{
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
}
