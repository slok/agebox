# Changelog

## [Unreleased]

### Fixed

- On public and private key discovery, now ignores the sockets so application doesn't fail while trying to read them.

## [v0.6.0] - 2021-09-10

### Changed

- `cat` cmd now logs info and warning messages as debug instead.
- Update `age` to v1.0.0.

## [v0.5.2] - 2021-05-22

### Changed

- Fixed bug that wouldn't allow loading `X25519` (Age) public keys with comments or newlines.
- Allow loading `X25519` (Age) public keys in the form of `Public key: {PUBLIC_KEY}` (e.g: Using `age-keygen -o ./priv.key 2> ./pub.key`).

## [v0.5.1] - 2021-05-15

### Changed

- Fixed bug that wouldn't allow loading `X25519` (Age) private keys with comments or newlines.

## [v0.5.0] - 2021-05-03

### Changed

- Remove the 20 public key encryption limit as Age has removed the decrypt limits.

## [v0.4.0] - 2021-03-25

### Added

- Private key discovery in a directory.

### Changed

- When loading public keys, invalid ones will be ignored instead of failing.
- Fail if we have more than 20 recipients on encryption (due to Age decrypt limit).
- --private-key flag has been deprecated in favor of --private-keys.
- By default private keys will try to be loaded from `$HOME/.ssh` dir.
- Use multiple private keys to decrypt, if any of them is able to decrypt it will do it.

## [v0.3.0] - 2021-03-19

### Added

- `validate` cmd that validates tracked files.
- `validate` cmd checks tracked secrets are not decrypted.
- `validate` cmd checks tracked secrets are encrypted.
- `validate` cmd optionally checks tracked secrets can be decrypted.
- Support for SSH passphrase using stdin.
- Support for SSH passphrase using cmd `--passphrase` flag.

## [v0.2.0] - 2021-03-13

### Added

- `cat` cmd that decrypts and prints to stdout.
- `--filter` (`-f`) regex to include the matching secrets in `encrypt` cmd.
- `--filter` (`-f`) regex to include the matching secrets in `decrypt` cmd.
- `--filter` (`-f`) regex to include the matching secrets in `untrack` cmd.

## [v0.1.1] - 2021-03-11

### Added

- Ignore `#` comments in multi recipient public key files.
- Alias `update` command for `reencrypt` command.

## [v0.1.0] - 2021-03-11

### Added

- Encryption of files.
- Decryption of files.
- Reencryption of tracked files.
- Directory expansion.
- Dry run mode.
- Untracking of files.
- Tracking registry initialization.

[unreleased]: https://github.com/slok/agebox/compare/v0.6.0...HEAD
[v0.6.0]: https://github.com/slok/agebox/compare/v0.5.2...v0.6.0
[v0.5.2]: https://github.com/slok/agebox/compare/v0.5.1...v0.5.2
[v0.5.1]: https://github.com/slok/agebox/compare/v0.5.0...v0.5.1
[v0.5.0]: https://github.com/slok/agebox/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/slok/agebox/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/slok/agebox/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/slok/agebox/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/slok/agebox/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/slok/agebox/releases/tag/v0.1.0
