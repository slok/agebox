# Changelog

## [Unreleased]

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

[unreleased]: https://github.com/slok/agebox/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/slok/agebox/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/slok/agebox/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/slok/agebox/releases/tag/v0.1.0
