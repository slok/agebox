<p align="center">
    <img src="img/logo.png" width="50%" align="center" alt="agebox">
</p>

# agebox

[![CI](https://github.com/slok/agebox/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/slok/agebox/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/slok/agebox)](https://goreportcard.com/report/github.com/slok/agebox)
[![Apache 2 licensed](https://img.shields.io/badge/license-Apache2-blue.svg)](https://raw.githubusercontent.com/slok/agebox/master/LICENSE)

Easy and simple file repository encryption tool based on [Age].

Have you ever though _"this should be simple"_ while you were using tools like [Blackbox] , [Git-crypt] or [Sops]? This is what agebox is. A tool on top of [Age]'s security system that encrypts/decrypts your repository files, focused on simplicity and gitops.

## Features

- Secure (Agebox delegates security to [Age]).
- Tracks encrypted files in repository.
- No PGP and no agents, just simple SSH and [Age] key files.
- File flexibility (encrypts/decrypts recursive paths, multiple/single files, all tracked files...).
- Reencrypts all tracked files with a single command.
- Focused on Gitops, CI flows and simplicity.
- Works with any file (doesn't understand formats like JSON, YAML...).
- Single binary/executable.
- No side effects like VCS commands (e.g: doesn't execute Git commands for you).

## Get agebox

- [Releases](https://github.com/slok/agebox/releases)
- [Docker images](https://hub.docker.com/r/slok/agebox)
- `git clone git@github.com:slok/agebox.git && cd ./agebox && make build && ls -la ./bin`

## Getting started

Initialize agebox tracking file.

```bash
agebox init
```

Encrypt (and track) multiple files.

```bash
agebox encrypt ./app1/secret1.yaml ./app2/secret1.yaml
```

Encrypt (and track) a directory in dry-run to see what would be encrypted before doing it.

```bash
agebox encrypt ./secrets --dry-run
```

Encrypt (and track) a directory and only (filter regex used) the `secret` named yaml files.

```bash
agebox encrypt ./manifests --filter ".*secret(\.yaml|\.yml)$"
```

Decrypt a subset of tracked secrets and a file.

```bash
agebox decrypt ./secrets/team-1 ./secrets/secret1.yaml
```

Decrypt only (filter regex used) `team-a` tracked files.

```bash
agebox decrypt ./secrets --filter ".*team-a.*"
```

Force decryption of all tracked files.

```bash
agebox decrypt --all --force
```

Validate tracked secrets are encrypted and not decrypted (without decrypt validation).

```bash
validate --no-decrypt
```

Cat multiple encrypted files and print them to stdout.

```bash
agebox cat ./secrets/secret1.yaml.agebox ./secrets/secret2.json.agebox --no-log
```

Reencrypt all files.

```bash
agebox reencrypt
```

Untrack multiple files.

```bash
agebox untrack ./secrets/secret1.yaml ./secrets/secret2.yaml
```

Untrack and delete file.

```bash
agebox untrack ./secrets/secret1.yaml --delete
```

## How does it work

When you initialize agebox on a repository it will create a file (`.ageboxreg.yml`) that will track all the encrypted
files in the repository.

From now on if you encrypt files with agebox from the root of the repository it will:

- Track the files if not already tracked.
- Encrypt the files with the public keys in `./keys` or `--public-keys` as recipients.
- If is a directory it will expand to all the files in the directory and subdirectories.

As a regular flow of agebox usage examples, you can:

- Decrypt tracked files as a single file, multiple files, a directory and its subdirectories...
- Decrypt all tracked files (`--all`).
- Reencrypt all tracked files with the public key recipients.
- Encrypt all tracked files (`--all`) that are decrypted in the repository.
- Untrack a file (and optionally delete from the file system).
- Encrypt/decrypt in dry-run to validate (handy en CI for checking).
- Cat encrypted files to stdout.
- Validate tracked files are encrypted and not decrypted (useful on CI, git hooks...).

Check the **Getting started** section for specific commands.

## Keys

Agebox supports the same asymmetric keys [Age] does:

- X25519 (Age).
- RSA SSH.
- Ed25519 SSH.

### Public keys

The public keys are the recipients of the encrypted files. With their respective private keys, users will be able to decrypt the files.

Public keys should be on a directory relative to the root of the repository (by default `./keys`) at the moment of invoking encryption commands, this simplifies the usage of keys by not requiring pgp keys or agents.

Agebox will encrypt with the loaded public keys, this means that when we add or remove any public key we should `reencrypt` the tracked files.

In case you don't want to have all the public keys in all the repositories that are managed by agebox, you could centralize these keys in another repository andgetting them before invoking agebox. Some usage examples:

- Git submodule `git pull --recurse-submodules`.
- Git repo and previous agebox command invoke `git clone/pull`.
- Download public keys from S3.

You can configure this with `--public-keys` flag or `AGEBOX_PUBLIC_KEYS` env var.

You can have multiple public keys in a file (one per line), like [Age recipients file](https://github.com/FiloSottile/age/#recipient-files).

### Private keys

Private key (**singular**) should be passed whenever a decrypt operation is made.

You can configure this with `--private-key` flag or `AGEBOX_PRIVATE_KEY` env var.

## Alternatives

- [Blackbox]: Uses PGP (requires an agent), complex and sometimes has undesired side effects (e.g git commands execution).
- [Sops]: Lots of features and very complex for simple use cases.
- [Git-crypt]: Uses PGP (requires an agent), complex, 100% tied to Git.

## Kudos

Thanks to [@FiloSottile](https://twitter.com/FiloSottile), [@Benjojo12](https://twitter.com/Benjojo12) and all the other [contributors](https://github.com/FiloSottile/age/graphs/contributors) of [Age].

Without [Age], [Agebox] would not exist.

[agebox]: https://github.com/slok/agebox
[age]: https://github.com/FiloSottile/age
[blackbox]: https://github.com/StackExchange/blackbox
[sops]: https://github.com/mozilla/sops
[git-crypt]: https://github.com/AGWA/git-crypt
