# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

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
