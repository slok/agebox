<p align="center">
    <img src="img/logo.png" width="50%" align="center" alt="agebox">
</p>

# agebox

[![CI](https://github.com/slok/agebox/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/slok/agebox/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/slok/agebox)](https://goreportcard.com/report/github.com/slok/agebox)
[![Apache 2 licensed](https://img.shields.io/badge/license-Apache2-blue.svg)](https://raw.githubusercontent.com/slok/agebox/master/LICENSE)

Easy and simple file repository encryption tool based on [Age].

Have you ever though _this should be simple_ while you were use tools like [Blackbox] , [git-crypt] or [Sops]? This is what agebox is. A tool on top of [Age]'s security system that encrypts/decrypts your repository files, focused on simplicity and gitops.

## Features

- Secure (Agebox delegates security to [Age]).
- Tracks encrypted files in repository.
- No GPG or agents (simple SSH and Age key file paths).
- File flexibility (encrypts/decrypts recursive paths, multiple/single files, all tracked files...).
- Reencrypts all tracked files with a single command.
- Focused on Gitops, CI flows and simplicity.
- Works with full files (doesn't understand formats like JSON, YAML...).

## Get agebox

- [Releases](https://github.com/slok/agebox/releases)
- [Docker images](https://hub.docker.com/r/slok/agebox)
- `git clone git@github.com:slok/agebox.git && cd ./agebox && make build && ls -la ./bin`

## Getting started

Initialize agebox tracking file.

```bash
agebox init
```

Encrypt (and track) multiple file.

```bash
agebox encrypt ./app1/secret1.yaml ./app2/secret1.yaml
```

Encrypt (and track) a directory in dry-run to see what would be encrypted before doing it.

```bash
agebox encrypt ./secrets --dry-run
```

Decrypt a subset of tracked secrets and a file.

```bash
agebox decrypt ./secrets/team-1 ./secrets/secret1.yaml
```

Decrypt all tracked files in dry-run, so we don't write to disk, but checks we can decrypt all files correctly.

```bash
agebox decrypt --all --dry-run
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

## Keys

Agebox supports the same asymmetric keys [Age] does:

- X25519 (Age).
- RSA SSH.
- Ed25519 SSH.

### Public keys

Public keys should be on a directory relative to the root of the repository (by default `./keys`) at the moment of invoking encryption commands, this simplifies the usage of keys by not requiring pgp keys or agents.

Agebox will encrypt with the loaded public keys, this means that when we add or remove any public key we should `reencrypt` the tracked files.

In case you don't want to have all the public keys in all the repositories that are managed by agebox, you could centralize these keys in another repository andgetting them before invoking agebox. Some usage examples:

- Git submodule `git pull --recurse-submodules`.
- Git repo and previous agebox command invoke `git clone/pull`.
- Download public keys from S3.

You can configure this with `--public-keys` flag or `AGEBOX_PUBLIC_KEYS` env var.

### Private keys

Private key (**singular**) should be passed whenever a decrypt operation is made.

You can configure this with `--private-key` flag or `AGEBOX_PRIVATE_KEY` env var.

### Alternatives

- [Blackbox]: Uses PGP (requires an agent), complex and sometimes has undesired side effects (e.g git commands execution).
- [Sops]: Lots of features and very complex for simple use cases.
- [Git-crypt]: Uses PGP (requires an agent), complex, 100% tied to Git.

[age]: https://github.com/FiloSottile/age
[blackbox]: https://github.com/StackExchange/blackbox
[sops]: https://github.com/mozilla/sops
[git-crypt]: https://github.com/AGWA/git-crypt
