# gemstone_utils

**gemstone_utils** provides cryptographic helpers, transparent AES-GCM encrypted SQLAlchemy fields, and a minimal experimental secrets resolver suitable for Pydantic's `BeforeValidator`. It is designed for applications that need reversible secret storage with minimal plaintext exposure and predictable operational behavior.

The package is licensed under the **MPL-2.0**, allowing use in both open-source and proprietary projects while keeping modifications to this library itself open.

## User guide

```{toctree}
:maxdepth: 2
:caption: User guide

api
sqlalchemy
key-storage
election
secrets-resolver
```

## Release notes

```{toctree}
:maxdepth: 2
:caption: Release notes

release-notes
```

## API reference

Per-module symbol documentation generated from Google-style docstrings. For integration patterns and bootstrap order, see {doc}`api`.

```{toctree}
:maxdepth: 2
:caption: API reference

reference/index
```

## Quick links

| Topic | Guide |
|-------|-------|
| SQLAlchemy `EncryptedString`, init order, rotation | {doc}`sqlalchemy` |
| Persisted keys (`key_storage`), bootstrap | {doc}`key-storage` |
| SQL-backed leader election | {doc}`election` |
| Experimental `resolve_secret` and backends | {doc}`secrets-resolver` |
| Curated public API (stable vs experimental) | {doc}`api` |
| Breaking changes and migration | {doc}`release-notes` |

Install from PyPI:

```bash
pip install gemstone_utils
```

Source: [github.com/gemstone-software-dev/gemstone_utils](https://github.com/gemstone-software-dev/gemstone_utils)
