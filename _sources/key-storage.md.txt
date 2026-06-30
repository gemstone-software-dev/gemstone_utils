# SQL key storage (`sqlalchemy.key_storage`)

This module defines ORM tables and helpers for **persisted KDF parameters**, **KEK canaries**, and **wrapped DEKs**, integrated with the same encrypted-field **wire format** as application columns.

Import the module to register models on the shared `GemstoneDB` base (see `gemstone_utils.db`).

## Two meanings of “key id” in wire strings

The five-part format is `$<alg>$<segment2>$<params_b64>$<blob_b64>` (see [release-notes.md](release-notes.md)). **Segment 2 is always a canonical UUID string**, but its **meaning depends on which blob** you are looking at:

1. **Application ciphertext** (`EncryptedString` column values): segment 2 is the **logical DEK id** — the primary key of `gemstone_key_record` (`GemstoneKeyRecord.key_id`). The resolver passed to `EncryptedString.set_keyctx_resolver` receives this UUID **as a string** and must return a `KeyContext` for that DEK.

2. **Wrapped DEK rows** (`GemstoneKeyRecord.wrapped`) and **KEK canary** (`GemstoneKeyKdf.canary_wrapped`): segment 2 is the **KEK slot id** — the primary key of `gemstone_key_kdf` (`GemstoneKeyKdf.key_id`). It identifies which persisted KDF row (and thus which derived KEK) was used to wrap the blob. It is **not** the DEK row’s primary key.

Confusing these two is the most common integration mistake. **DEK id** ↔ decrypts app data. **KEK slot id** ↔ unwraps the DEK (or verifies the canary) after you derive the KEK from the passphrase + KDF params.

## Tables

### `gemstone_key_kdf` (`GemstoneKeyKdf`)

KEK **slot**: one row per slot.

| Field | Role |
|-------|------|
| `key_id` | UUID string PK — KEK slot id (appears as segment 2 in wrapped DEK and canary wires). |
| `params` | JSON text for `derive_kek` (e.g. PBKDF2 salt and iterations). |
| `canary_wrapped` | KEK check blob (same wire format); `None` until set. |
| `app_reencrypt_pending` | Application flag for re-encrypt workflows. |
| `created_at` / `updated_at` | UTC timestamps. |

### `gemstone_key_record` (`GemstoneKeyRecord`)

**DEKs only** (no KEK canary row here).

| Field | Role |
|-------|------|
| `key_id` | UUID string PK — logical DEK id (segment 2 in **application** ciphertext). |
| `wrapped` | Wire string wrapping the DEK bytes; segment 2 is the **KEK slot** `key_id`. |
| `data_alg` | Symmetric algorithm id for **field** encryption (`KeyContext.alg`), not necessarily the wrap algorithm inside `wrapped`. |
| `is_active` | At most one row should be active when you use `put_keyrecord(..., is_active=True)` (it clears others on insert). |
| `created_at` / `updated_at` | UTC timestamps. |

## Bootstrap (new database)

Typical order inside a transaction:

1. **`new_kdf_params()`** (or `recommended_kdf_params`) — build KDF params; for PBKDF2, **salt must be stored** in the persisted JSON.
2. **`set_kdf_params(session, kek_id, params)`** — creates or updates the `gemstone_key_kdf` row for KEK slot `kek_id` (a new UUID from `new_key_id()`).
3. **`set_kek_canary(session, kek_id, canary_wrapped)`** — set `canary_wrapped` from `keyrecord_to_wire(make_kek_check_record(kek), kek_id)` (KEK-check records use `KeyRecord.keyid is None` until serialized into wire with the slot id).
4. **`put_keyrecord(session, key_id=dek_id, wrapped=wire_wrap(kek_id, kek, dek_material), is_active=True)`** — insert the DEK row; `dek_id` is a new UUID.

Then configure the app:

- `EncryptedString.set_current_keyctx(KeyContext(keyid=dek_id, key=dek_material, alg=...))`
- `EncryptedString.set_keyctx_resolver(make_keyctx_resolver(...))` — loads passphrase, derives KEK, unwraps DEK by row.

## `make_keyctx_resolver`

Builds `Callable[[str], KeyContext]` suitable for `EncryptedString.set_keyctx_resolver`:

- Looks up `GemstoneKeyRecord` by **DEK id** (the argument).
- Parses `wrapped` to find **KEK slot id** (segment 2).
- Loads KDF params for that slot, derives KEK, unwraps DEK.
- Returns `KeyContext(keyid=<dek id>, key=<dek bytes>, alg=row.data_alg)`.

Optional `max_cache_size` enables an in-process LRU-style cache of resolved contexts.

## `rewrap_key_records`

Run inside a transaction (`with session.begin(): ...`). Unwraps **all** KEK-slot canaries and all DEK rows (or a subset via `key_ids`) with `old_kek`, re-wraps with `new_kek`, and updates `old_wrap_key_id` → `new_wrap_key_id` in wire segment 2. Requires every KEK slot with a `canary_wrapped` to match `old_wrap_key_id` on the wires being processed.

Use this when rotating the passphrase or moving to a new KEK slot id while keeping the same logical DEKs.

## Key ids and wire format

- **`gemstone_utils.key_id.new_key_id()`** — returns a new canonical UUIDv7 string for a DEK or KEK slot primary key (RFC 9562; on Python 3.14+ uses `uuid.uuid7()`, otherwise `uuid6`).
- **`normalize_key_id(value)`** — parse and normalize a UUID string; raises `ValueError` if invalid.

Legacy integer segment values in stored ciphertext are **rejected** at parse time. Upgrading existing deployments requires a **data migration** (application-specific). A **documentation-only** outline lives at [`scripts/migrate_key_ids.py`](https://github.com/gemstone-software-dev/gemstone_utils/blob/main/scripts/migrate_key_ids.py). Full breaking-change notes: [release-notes.md](release-notes.md).

## Backup and recovery

Treat **`gemstone_key_kdf`** and **`gemstone_key_record`** with the same care as application secrets: without **KDF params** (including salt) and the **vault passphrase**, you cannot derive KEKs or unwrap DEKs. **Back up** `params` plus `wrapped`/`canary_wrapped` as your security model requires.

## Common mistakes

- Mixing **DEK id** (app ciphertext segment 2, `gemstone_key_record.key_id`) with **KEK slot id** (wrap segment 2, `gemstone_key_kdf.key_id`).
- Calling `set_kek_canary` before `set_kdf_params` for that slot (no row yet — `set_kek_canary` raises `KeyError`).
- Expecting `KeyContext.alg` from the wrap algorithm inside `wrapped` — for field encryption it comes from **`data_alg`**.
