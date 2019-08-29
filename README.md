# This library is a Work in Progress. Don't use in production.

# This is an Iota library written in rust.
[![Build Status](https://travis-ci.org/iotaledger/iota-lib-rs.svg?branch=master)](https://travis-ci.org/njaremko/iota-lib-rs) 
[![Windows Build status](https://ci.appveyor.com/api/projects/status/m1g0ddlgxk8wq9es/branch/master?svg=true)](https://ci.appveyor.com/project/njaremko/iota-lib-rs/branch/master)
[![Version](https://img.shields.io/crates/v/iota-lib-rs.svg)](https://crates.io/crates/iota-lib-rs)
[![Documentation](https://docs.rs/iota-lib-rs/badge.svg)](https://docs.rs/iota-lib-rs/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/iotaledger/iota-lib-rs/master/LICENSE)

# Documentation

https://docs.rs/iota-lib-rs

This library currently requires nightly rust to build.

Things that are done:
- [ ] Stateful Accounts
    - [ ] Plugins
    - [ ] Storage
    - [ ] Events
    - [ ] Conditional Deposit Addresses
- [x] Crypto
    - [x] Curl
    - [x] Kerl
    - [x] PearlDiver
    - [x] ISS
    - [x] HMAC
    - [x] Signing
- [x] Model
    - [x] Bundle
    - [x] Input
    - [x] Inputs
    - [x] Neighbor
    - [x] Signature
    - [x] Transaction
    - [x] Transfer
- [x] Utils
    - [x] Checksum
    - [x] Constants
    - [x] Converter
    - [x] InputValidator
    - [x] IotaAPIUtils
    - [x] IotaUnitConversion
    - [x] IotaUnits
    - [x] Multisig
    - [x] SeedRandomGenerator
    - [x] StopWatch
    - [x] TrytesConverter
- [ ] API
    - [x] IRI API calls and responses
        - [x] add neighbors
        - [x] attach_to_tangle
        - [x] find_transactions
        - [x] get_balances
        - [x] broadcastTransactions
        - [x] storeTransactions
        - [x] get_inclusion_states
        - [x] get_neighbors
        - [x] get_node_info
        - [x] get_tips
        - [x] get_transactions_to_approve
        - [x] get_trytes
        - [x] remove_neighbor
        - [x] were_addresses_spent_from
        - [x] check_consistency
    - [ ] Ease of use wrappers/helpers
        - [x] new_address
        - [x] get_new_address
        - [x] send_trytes
        - [x] store_and_broadcast
        - [x] get_inputs
        - [x] prepare_transfers
        - [x] traverse_bundle
        - [x] send_transfer
        - [x] get_bundle

Here's an example of how to send a transaction: (Note that we're using the address as the seed in `send_transfer()`...don't do this)
```rust
use iota_api::options::SendTransferOptions;
use iota_lib_rs::prelude::*;
use iota_model::Transfer;
use iota_conversion::trytes_converter;

fn main() {
    let trytes =
        "HELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDD";
    let message = trytes_converter::to_trytes("Hello World").unwrap();
    let transfer = Transfer {
        address: trytes.to_string(),
        // Don't need to specify the field 
        // because the field and variable
        // have the same name
        message,
        // Populate the rest of the fields with default values
        ..Transfer::default()
    };
    let mut api = iota_api::API::new("https://node01.iotatoken.nl");
    let tx = api
        .send_transfers(
            transfer,
            &trytes,
            SendTransferOptions {
                local_pow: true,
                threads: 2,
                ..SendTransferOptions::default()
            },
        )
        .unwrap();
    println!("{:?}", tx);
}
```

# Donations:
If you feel so inclined, you can find my address for donations at:

https://ecosystem.iota.org/projects/iota-lib-rs
