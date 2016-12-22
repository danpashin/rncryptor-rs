[![Build Status](https://travis-ci.org/adinapoli/rncryptor-rs.svg?branch=master)](https://travis-ci.org/adinapoli/rncryptor-rs)
[![Coverage Status](https://coveralls.io/repos/github/RNCryptor/rncryptor-rs/badge.svg?branch=master)](https://coveralls.io/github/RNCryptor/rncryptor-rs?branch=master)

# Rust Implementation of the RNCryptor spec
This library implements the specification for the [RNCryptor](https://github.com/RNCryptor)
encrypted file format by Rob Napier.

# Current Supported Versions
* V3 - [Spec](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)

# What's there

- [x] Password-based Encryption
- [x] Key-based Encryption
- [x] Decryption (with HMAC validation)
- [x] Test vectors
- [x] Quickcheck roundtrip properties

# TODO
- [ ] Move away from `rust-crypto` if possible/needed.
- [ ] Profiling & optimisations

# Contributors (Sorted by name)
- Alfredo Di Napoli (creator and maintainer)

# Contributions
This library scratches my own itches, but please fork away!
Pull requests are encouraged.
