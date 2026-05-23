# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

`rain-erc` is a pure-Rust crate of ERC-related utilities for the Rain Protocol
ecosystem. Currently contains one module:

- `erc165` — probe arbitrary contracts for `IERC165` support against any
  `alloy::providers::Provider`. Spec-compliant: execution reverts on the probe
  count as "interface not supported" per
  [EIP-165](https://eips.ethereum.org/EIPS/eip-165); only RPC / decoding errors
  are returned as `Err`.

No Solidity, no submodules, no path-deps. Everything else (alloy, thiserror) is
on crates.io.

## Build Environment

Nix flake with the slim `rust-shell` as the default devShell. Enter with
`nix develop` or prefix commands with `nix develop -c`.

| Task         | Command                                                                                  |
| ------------ | ---------------------------------------------------------------------------------------- |
| Native tests | `nix develop -c cargo test`                                                              |
| WASM build   | `nix develop -c cargo build --target wasm32-unknown-unknown`                             |
| Format check | `nix develop -c cargo fmt --all -- --check`                                              |
| Clippy       | `nix develop -c cargo clippy --all-targets --all-features -- -D warnings -D clippy::all` |

Run a single test:

```sh
nix develop -c cargo test test_name
```

## Architecture

### `src/erc165/mod.rs`

- `supports_erc165<P: Provider>(provider, addr) -> Result<bool, Erc165Error>` —
  orchestrates two probes per EIP-165:
  - `check1`: `supportsInterface(0x01ffc9a7)` must return `true`.
  - `check2`: `supportsInterface(0xffffffff)` must return `false` (or revert,
    which counts as `false`).
- `Erc165Error` distinguishes transport/decoding errors from
  interface-unsupported results. Revert errors are classified by inspecting the
  alloy `ContractError`.

Tests use `alloy::providers::mock::Asserter` driven by
`ProviderBuilder::new().connect_mocked_client(asserter)`. No real network calls;
no submodules.

## CI

`.github/workflows/rainix-rs.yaml` is a thin caller of
`rainlanguage/rainix/.github/workflows/rainix-rs.yaml@main`. The upstream
reusable workflow covers rs-static + rs-test (ubuntu/macos) + rs-wasm +
rs-wasm-test.

`.github/workflows/manual-rs-release.yml` is a manual `workflow_dispatch` that
runs `cargo release LEVEL` and publishes to crates.io. Triggered by maintainers
when a release is ready; there's no auto-publish on push to main.

## Release

1. Bump `version` in `Cargo.toml` on a PR.
2. After merge, sync `Cargo.lock` (cargo update -p rain-erc) on a second PR —
   required because `cargo release` refuses to run with a dirty tree.
3. Once main is at the new version with a clean lockfile, trigger the `Release`
   workflow with the appropriate version-level (`release` to drop a pre-release
   suffix, `patch`/`minor`/`major` to bump).

## License

CAL-1.0. SPDX headers per REUSE 3.2.
