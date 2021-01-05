# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.2.9](https://github.com/maidsafe/sn_transfers/compare/v0.2.8...v0.2.9) (2021-01-05)

### [0.2.8](https://github.com/maidsafe/sn_transfers/compare/v0.2.7...v0.2.8) (2020-12-30)


### Features

* use Dt 0.12.0 ([b6137fb](https://github.com/maidsafe/sn_transfers/commit/b6137fba3ac465bd4ef2a06bb4a2272c3c3dd32b))

### [0.2.7](https://github.com/maidsafe/sn_transfers/compare/v0.2.6...v0.2.7) (2020-12-30)

### [0.2.6](https://github.com/maidsafe/sn_transfers/compare/v0.2.5...v0.2.6) (2020-12-29)


### Features

* use thiserror and create transfers error lib ([dfa7f4f](https://github.com/maidsafe/sn_transfers/commit/dfa7f4fd8dcc85ad21a6547aadf9235ae547be0c))

### [0.2.5](https://github.com/maidsafe/sn_transfers/compare/v0.2.4...v0.2.5) (2020-12-17)


### Bug Fixes

* align transfer-split and actor model changes ([3a0ed37](https://github.com/maidsafe/sn_transfers/commit/3a0ed37c080eadb2a1dc8f205ee3a7817f87a68a))
* don't start new wallet w/ sync ([a1c19cc](https://github.com/maidsafe/sn_transfers/commit/a1c19cca6991709ed2026017b4a7d22c36361ea6))
* ignore sig validation for simulated payouts ([554e89d](https://github.com/maidsafe/sn_transfers/commit/554e89d6bf595b6f7ef4054b04354216a226a834))
* use master pubkey as id for multisig wallet ([2efe1f2](https://github.com/maidsafe/sn_transfers/commit/2efe1f2f393673cb755d622673f31af096a8c8b0))
* wrap replica counter in option ([e5a624a](https://github.com/maidsafe/sn_transfers/commit/e5a624a769afa64caca3019919be08f5f9fc156e))
* **validation:** add case zero ([0efd75e](https://github.com/maidsafe/sn_transfers/commit/0efd75e8849d5bb40b54da446a222c564211d11e))
* verify correct signature for credit ([53c6b85](https://github.com/maidsafe/sn_transfers/commit/53c6b85158693f8c997d424998a0ec4ba34396b7))

### [0.2.4](https://github.com/maidsafe/sn_transfers/compare/v0.2.3...v0.2.4) (2020-11-24)


### Bug Fixes

* **all:** remove all unwraps from library and test code ([ee0520a](https://github.com/maidsafe/sn_transfers/commit/ee0520a1f8ad018c0e7d743762bb9a35880406dd))

### [0.2.3](https://github.com/maidsafe/sn_transfers/compare/v0.2.2...v0.2.3) (2020-11-23)

### [0.2.2](https://github.com/maidsafe/sn_transfers/compare/v0.2.1...v0.2.2) (2020-10-27)


### Features

* **no PublicId:** updated for data_type changes for No PublicIds ([e2474c6](https://github.com/maidsafe/sn_transfers/commit/e2474c6d01b8c4c9e05245dfa9c9e0052110aac7))

### [0.2.1](https://github.com/maidsafe/sn_transfers/compare/v0.2.0...v0.2.1) (2020-10-20)


### Bug Fixes

* **0:** don't allow sending of no money ([fffbf8c](https://github.com/maidsafe/sn_transfers/commit/fffbf8ca19debfcbf36a212e184a273ae4ba1830))
* **actor:** move mutation to apply fn ([b51ab31](https://github.com/maidsafe/sn_transfers/commit/b51ab31746af06241107de932f7bab236e004294))

### [0.2.0](https://github.com/maidsafe/sn_transfers/compare/v0.1.0...v0.2.0) (2020-09-03)

* Update crate name to sn_transfers.
* Expose genesis generator.
* Add initial infusion of money.
* Check against previous 'next' count when applying RegisteredTransfers.
* Support checking SectionProofChain in safe_vaults.
* Add scheduled security audit scan.
* Update simulated payout funcs to credit/debit correct pk.
* Add GetReplicaKeys.
* Add simulated debitting APIs to replica.
* Refactor and fix simulated-payouts APIs.
* Add simulated-payouts feature and include testing API to Replica.
* Fix received debits logic.
* Accumulate remote credits.
* Add peer logic and sig validations.

### [0.1.0](https://github.com/maidsafe/sn_transfers/compare/v0.1.0...v0.1.0) (2020-05-19)

* Initial implementation.
