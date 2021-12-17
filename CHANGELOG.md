# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Internal improvements

- Update `blake2` dependency.

## 0.4.0 - 2021-05-03

### Changed

- Update `rand*` dependencies.
- Update `secrecy` dependency and bump MSRV to 1.51.

### Internal improvements

- Remove `byteorder` dependency; the same functionality can be accomplished using
  the standard library.

## 0.3.0 - 2020-11-30

### Added

- Add `SecretTree::create_secret` as a high-level alternative to `fill()`.
- Make `Name::new()` method constant.
- Implement `Display`, `AsRef<str>` and `FromStr` for `Name`.

### Changed

- Use the `secrecy` crate instead of `clear_on_drop` and `blake2b` instead of
  `blake2b-rfc`.
- Change `Seed` type to `Secret<[u8; 32]>` (that is, wrap it in `Secret`).
- Make `from_seed` constructor accept `Seed`. The previous `from_seed` constructor
  is renamed to `from_slice`, and it now returns a `Result<_, TryFromSliceError>`
  instead of an `Option`.

### Removed

- Remove support of `rand` 0.6.

### Fixed

- Fix `no_std` mode by switching off unnecessary dependency features. 

## 0.2.0 - 2019-09-10

### Added

- Mark the crate as not needing the standard library.
- Add a type alias for the seed array.

## 0.2.0-pre.0 - 2019-07-04

### Changed

- Use Rust 2018 edition.
- Support `rand` v0.6 and 0.7.

## 0.1.1 - 2018-12-24

### Security

- Clear stack after deriving keys with Blake2b for better security.

### Fixed

- Improve crate documentation.
- Fix crate metadata in `Cargo.toml`.

## 0.1.0 - 2018-12-23

The initial release of `secret-tree`.
