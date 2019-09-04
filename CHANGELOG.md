# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Mark the crate as not needing the standard library.
- Alias for seed array.

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
