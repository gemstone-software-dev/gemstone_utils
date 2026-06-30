# Public API guide

How to use **stable, intended** entry points in `gemstone_utils`. This page focuses on integration patterns and where to go next — not an exhaustive symbol list.

Per-function and per-class reference material lives in **Google-style docstrings** on the public modules (suitable for Sphinx or MkDocs autodoc when you add a reference build). Use `help()` in Python or your IDE for inline docs.

## Documentation map

| Area | Module(s) | Usage guide |
|------|-----------|-------------|
| Encrypted SQLAlchemy columns | `sqlalchemy.encrypted_type`, `lazy_secret` | [sqlalchemy.md](sqlalchemy.md) |
| Persisted keys and rotation | `sqlalchemy.key_storage`, `key_mgmt`, `db` | [key-storage.md](key-storage.md) |
| Leader election | `election`, `db` | [election.md](election.md) |
| Config secret references | `experimental.secrets_resolver` | [secrets-resolver.md](secrets-resolver.md) |
| Breaking changes | — | [RELEASE_NOTES.md](../RELEASE_NOTES.md) |

## Typical bootstrap order

Applications that use encrypted columns **and** persisted keys usually wire things in this order:

1. **`init_db(db_url)`** — after importing every module that defines `GemstoneDB` subclasses (`key_storage`, `election`, app plugins).
2. **`key_mgmt.init(...)`** — secret name and KEK-check plaintext for passphrase verification.
3. **Persisted keys** — `set_kdf_params`, `set_kek_canary`, `put_keyrecord` (see [key-storage.md](key-storage.md)).
4. **`EncryptedString.set_current_keyctx`** — active DEK for new writes.
5. **`EncryptedString.set_keyctx_resolver`** — often `make_keyctx_resolver()` from `key_storage`.
6. **Optional:** `secrets_resolver.set_keyctx_resolver` if config values use encrypted wires; `set_allowed_file_path_prefixes` for non-container `file:` paths.

For election-only or resolver-only apps, skip the steps that do not apply.

## Cryptography and encrypted fields

Use **`gemstone_utils.crypto`** for algorithm dispatch (`encrypt_alg` / `decrypt_alg`, `generate_key_by_alg`, `recommended_data_alg`) and **`gemstone_utils.encrypted_fields`** for the `$alg$keyid$params$blob` wire format (`encrypt_string`, `decrypt_string`).

Generate new logical key ids with **`new_key_id()`** (UUIDv7). Pass **`KeyContext`** (`keyid`, `key`, `alg`) into encrypt helpers; use **`KeyRecord`** when wrapping DEKs under a KEK.

## Key management

**`derive_kek(passphrase, params)`** uses persisted JSON (`params["kdf"]`) as the source of truth. New installs should use **`recommended_kdf_params()`** or **`kdf.pbkdf2.recommended_pbkdf2_params`**.

Verify passphrases with **`derive_and_verify_kek`** and KEK-check records (`make_kek_check_record`, `verify_kek`). Rotate with **`rotate_kek`** or persisted **`rewrap_key_records`**.

Load passphrases via **`load_passphrase()`** (secret mount, optional env fallback).

## SQLAlchemy encrypted columns

Declare columns as **`EncryptedString`**. Reads return **`LazySecret`** — call **`str(value)`** or **`value.get()`** to decrypt. Do not assign already-encrypted strings on write.

See [sqlalchemy.md](sqlalchemy.md) for init order, rotation, and failure modes.

## SQL key storage

**`GemstoneKeyKdf`** rows hold KDF JSON and the KEK canary; **`GemstoneKeyRecord`** rows hold wrapped DEKs only. Segment 2 in application ciphertext is the **DEK id**; segment 2 in `wrapped` is the **KEK slot id** — do not confuse them.

See [key-storage.md](key-storage.md) for bootstrap, `make_keyctx_resolver`, and `rewrap_key_records`.

## Database layer

**`GemstoneDB`** is the shared declarative base. **`init_db`** creates missing tables for all registered models; **`get_session`** returns sessions for helpers and app code.

## Leader election

Optional multi-worker leader leases: **`register_candidate`**, periodic **`heartbeat`** and **`elect`**, gate work with **`is_leader`**. Import **`gemstone_utils.election`** before **`init_db`**.

See [election.md](election.md) for protocol rules and limitations.

## Experimental secrets resolver

**`resolve_secret`** is the single entry point for `env:`, `file:`, `secret:`, `literal:`, plugins, and encrypted wires. Register custom prefixes with **`register_backend`**; introspect with **`list_backends`**.

Not a full secrets manager — see [secrets-resolver.md](secrets-resolver.md).

## API reference (autodoc)

Public modules use **Google-style docstrings** (`Args`, `Returns`, `Raises`, `Attributes`). When you add Sphinx or MkDocs with autodoc/mkdocstrings, generate the full symbol reference from those docstrings and link it here (for example on Read the Docs or GitHub Pages). **`api.md` remains the usage guide**; autodoc is the exhaustive index.

Modules covered: `crypto`, `key_id`, `types`, `encrypted_fields`, `key_mgmt` (+ `registry`, `kdf`), `sqlalchemy.encrypted_type`, `sqlalchemy.lazy_secret`, `sqlalchemy.key_storage`, `db`, `election`, `experimental.secrets_resolver`.
