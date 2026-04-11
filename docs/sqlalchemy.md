# SQLAlchemy encrypted columns

This guide covers `EncryptedString` in `gemstone_utils.sqlalchemy.encrypted_type`: transparent encryption on write, lazy decryption on read, and how it interacts with `KeyContext` and key ids.

## What `EncryptedString` does

- **Write path (`process_bind_param`):** Plaintext is encrypted with the **current** `KeyContext` (`EncryptedString.set_current_keyctx`). Already-encrypted strings are rejected to avoid double encryption.
- **Read path (`process_result_value`):** The stored wire is parsed; segment 2 is the **logical DEK id** (UUID string). A `KeyContext` for that id is obtained from the **resolver** (`EncryptedString.set_keyctx_resolver`). The result is a `LazySecret` that decrypts when you access the value.

`EncryptedString` does **not** manage database migrations, key storage, or passphrase handling. For persisted keys, see [key-storage.md](key-storage.md).

## Initialization order

Before any read or write of encrypted columns:

1. **`EncryptedString.set_current_keyctx(ctx)`** — `KeyContext` used for **new** writes (plaintext → ciphertext). `ctx.keyid` should be a new UUID from `gemstone_utils.key_id.new_key_id()` when provisioning a new DEK.
2. **`EncryptedString.set_keyctx_resolver`** — `Callable[[str], KeyContext]`. Given the **UUID string** from segment 2 of stored ciphertext, return the `KeyContext` that can decrypt that row.

Writes only need the current key. Reads need the resolver to map **historical** key ids (rotation, multiple DEKs).

## Key ids are strings (UUIDs)

`KeyContext.keyid` and the resolver argument are **`str`**, canonical UUID text (typically UUIDv7 from `new_key_id()`). Integer key ids in legacy data are not accepted by current parsers; see [RELEASE_NOTES.md](../RELEASE_NOTES.md) and [key-storage.md](key-storage.md#key-ids-and-wire-format).

## Rotation behavior

- **New rows** use `set_current_keyctx` with the active DEK.
- **Old rows** still contain ciphertext whose segment 2 is an older DEK id. The resolver must return the correct `KeyContext` for each id until those rows are re-encrypted or migrated.

## Failure modes

| Symptom | Typical cause |
|--------|----------------|
| `RuntimeError: set_current_keyctx(...) must be called` | Write attempted before configuration. |
| `RuntimeError: set_keyctx_resolver(...) must be called` | Read attempted before resolver. |
| `ValueError: Encrypted values must not be assigned directly` | Assigning an already-wired ciphertext as plaintext. |
| `KeyError` / `ValueError` from resolver | Unknown `keyid`, or DB/key lookup failure. |

## Related modules

- `gemstone_utils.sqlalchemy.lazy_secret` — lazy decryption wrapper.
- `gemstone_utils.encrypted_fields` — `encrypt_string` / `parse_encrypted_field`.
- [key-storage.md](key-storage.md) — `make_keyctx_resolver` for persisted DEKs.
