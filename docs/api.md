# Public API overview

Curated index of **stable, intended** entry points for application use. For usage, wire formats, and operational guidance, follow the topic guides linked at the bottom — not a symbol dump.

## Cryptography (`gemstone_utils.crypto`)

- Symmetric registry: `encrypt_alg`, `decrypt_alg`, `is_supported_sym_alg`, `SUPPORTED_SYM_ALGS`, `sym_alg_key_length`, `generate_key_by_alg`
- Backward-compatible wrappers: `encrypt_with_alg`, `decrypt_with_alg` (ciphertext only; same as `encrypt_alg` / `decrypt_alg` with empty params)
- Defaults: `recommended_data_alg`, `RECOMMENDED_DATA_ALG`
- PBKDF2 primitive: `derive_pbkdf2_hmac_sha256`; `DEFAULT_PBKDF2_ITERATIONS_STRONG` (magnitude used for persisted KDF defaults)
- Wire helpers: `b64encode`, `b64decode`

## Key ids (`gemstone_utils.key_id`)

- `new_key_id()` — new UUIDv7 string for DEK or KEK slot primary keys
- `normalize_key_id(value)` — canonical UUID string; raises `ValueError` if invalid

## Types (`gemstone_utils.types`)

- `KeyContext` — `keyid: str`, `key: bytes`, `alg: str`
- `KeyRecord` — encrypted key material; `keyid` may be `None` for KEK-check blobs only

## Encrypted fields (`gemstone_utils.encrypted_fields`)

- `format_encrypted_field`, `parse_encrypted_field`, `encrypt_string`, `decrypt_string`, `is_encrypted_prefix`

## Key management (`gemstone_utils.key_mgmt`)

- `derive_kek`, `recommended_kdf_params`, `rotate_kek`, `unwrap_key`, `verify_kek`, `wrap_key`
- `derive_and_verify_kek`, `reencrypt_keys`
- `make_kek_check_record`, `load_keyctx`, `init`, `load_passphrase`
- `KEKVerificationError` — structured failure when the KEK-check blob does not decrypt
- `is_supported_kdf`, `require_supported_kdf`, `SUPPORTED_KDF_NAMES` (from `key_mgmt.registry`)
- Package `gemstone_utils.key_mgmt.kdf` — protocols `RecommendedKdfParamsFn`, `HasKdfRegistryName`; per-algorithm modules (e.g. **`kdf.pbkdf2`**: `NAME`, `pbkdf2_params`, `recommended_pbkdf2_params`). `register_kdf` is first-party / allowlisted only (not an app extension hook).

## SQLAlchemy

### Encrypted columns (`gemstone_utils.sqlalchemy.encrypted_type`)

- `EncryptedString` — TypeDecorator; `set_current_keyctx`, `set_keyctx_resolver`
- `LazySecret` (`gemstone_utils.sqlalchemy.lazy_secret`) — returned on read; decrypt via `str()`, `get()`, or equality; see [sqlalchemy.md](sqlalchemy.md)

### Key storage (`gemstone_utils.sqlalchemy.key_storage`)

- Models: `GemstoneKeyKdf`, `GemstoneKeyRecord`
- KDF / canary: `new_kdf_params`, `set_kdf_params`, `get_kdf_params`, `set_kek_canary`, `set_app_reencrypt_pending`, `iter_kek_slots`
- DEK rows: `put_keyrecord`, `iter_wrapped_rows`, `get_wrapped`
- Wire helpers: `wire_wrap`, `wire_to_keyrecord`, `keyrecord_to_wire`, `unwrap_stored_key`
- App integration: `make_keyctx_resolver`
- Rotation: `rewrap_key_records`

## Database (`gemstone_utils.db`)

- `init_db`, `get_session`, `GemstoneDB` — as used by key storage, election, and optional resolver plugins

## Leader election (`gemstone_utils.election`)

Requires `init_db` and `import gemstone_utils.election` so ORM models register on `GemstoneDB.metadata` (same pattern as key storage). See [election.md](election.md).

- Config: `set_expire`
- Models: `ElectionCandidate`, `ElectionLeader`
- Lifecycle: `register_candidate`, `heartbeat`, `unregister_candidate`
- Election: `list_candidates`, `is_leader`, `elect`

## Experimental

- `gemstone_utils.experimental.secrets_resolver` — `resolve_secret` (dispatches built-in prefixes `env:`, `file:`, `secret:`, `literal:`, and registered backends); `set_keyctx_resolver`, `set_allowed_file_path_prefixes`, `allowed_file_path_prefixes`, `FilePathNotAllowed`, `register_backend`, `unregister_backend`, `is_backend_registered`, `list_backends`, `BackendNotImplemented` (`reason`: `"removed"` or `"unregistered"`). Scheme details: [secrets-resolver.md](secrets-resolver.md).

## Further reading

- [sqlalchemy.md](sqlalchemy.md) — `EncryptedString` usage
- [key-storage.md](key-storage.md) — persisted keys, two-level wire semantics, bootstrap
- [election.md](election.md) — SQL-backed leader election
- [secrets-resolver.md](secrets-resolver.md) — experimental resolver
- [RELEASE_NOTES.md](../RELEASE_NOTES.md) — breaking changes and migration notes
