# rain-erc

ERC-related utilities for the Rain Protocol ecosystem, in Rust.

[![crates.io](https://img.shields.io/crates/v/rain-erc.svg)](https://crates.io/crates/rain-erc)
[![docs.rs](https://docs.rs/rain-erc/badge.svg)](https://docs.rs/rain-erc)

## What's here

- `erc165` — Probe arbitrary contracts for `IERC165` support. The probe is
  spec-compliant: it distinguishes execution-revert results (treated as
  "interface not supported", per
  [EIP-165](https://eips.ethereum.org/EIPS/eip-165)) from genuine RPC / decoding
  errors (returned as `Err`). Works against any `alloy::providers::Provider`.

## Install

```toml
[dependencies]
rain-erc = "0.1"
```

## Use

```rust
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use rain_erc::erc165::supports_erc165;

let provider = ProviderBuilder::new().connect_http("https://...".parse()?);
let contract: Address = "0x...".parse()?;

if supports_erc165(&provider, contract).await? {
    // contract responds correctly to ERC-165 probes
}
```

## Develop

Requires Nix with flakes:

```sh
nix develop                    # default = rust-shell (slim Rust toolchain)
nix develop -c cargo test
nix develop -c cargo clippy
```

CI runs via [rainlanguage/rainix](https://github.com/rainlanguage/rainix)
reusable workflows.

## License

CAL-1.0.
