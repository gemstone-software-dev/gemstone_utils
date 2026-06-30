# Experimental secrets resolver

The module `gemstone_utils.experimental.secrets_resolver` resolves string references to secret values (environment, files, container secret mounts, literals, and optional plugins). It is intended for **configuration bootstrap** (for example Pydantic `BeforeValidator`), not as a full secrets manager.

**Stability:** Experimental. The API and behavior may change; see [README.md](../README.md#experimental-components).

## Schemes

| Prefix | Behavior |
|--------|----------|
| `env:VAR` | Read `os.environ[VAR]`, cache, then **delete** the variable from the environment (scrub). |
| `file:/path` | Read UTF-8 file once, strip, cache. Path must be **absolute** (no `~`). Allowed only under configured prefixes (default: `/app/secret`). |
| `secret:name` | Search `CREDENTIALS_DIRECTORY`, `/run/secrets/`, `/var/run/secrets/`. Name must match `[A-Za-z0-9_-]+`. |
| `literal:opaque` | Return the substring after the first colon unchanged (URLs, connection strings, etc.). |

Custom prefixes can be registered with `register_backend(prefix, resolver, ...)`.

Values containing `:` must use one of the prefixes above (or a registered backend). Plain strings without `:` are returned unchanged.

## Path security

### `file:`

- Paths must be **absolute** (e.g. `file:/app/secret/passphrase`). Relative paths and `~` are rejected (no tilde expansion).
- By default, only paths under **`/app/secret`** are allowed (common container mount). Call **`set_allowed_file_path_prefixes([...])`** at startup to replace that list entirely (include `/app/secret` again if you still need it).
- **Do not** register bare `/etc` or filesystem root (`/`) if you can avoid it — the setter logs a **warning** but does not block them. Prefer narrow trees such as `/etc/yourapp/secrets/`.
- Paths outside the allowlist raise **`FilePathNotAllowed`**.

```python
from gemstone_utils.experimental.secrets_resolver import set_allowed_file_path_prefixes

set_allowed_file_path_prefixes(["/etc/myapp/secrets"])
```

### `secret:`

- The name segment must match **`[A-Za-z0-9_-]+`** (letters, digits, hyphen, underscore only).
- Secret mounts are read via fixed roots (`CREDENTIALS_DIRECTORY`, `/run/secrets`, `/var/run/secrets`) and are **not** subject to the `file:` allowlist.
- Names with dots or slashes (e.g. systemd-style dotted names) must use `file:` under a narrow allowed prefix instead.

## `BackendNotImplemented`

Subclass of **`RuntimeError`**. Raised when a reference names a removed or unregistered backend.

- **`reason="removed"`** — prefix was removed (e.g. `azexp:` in v0.5.0).
- **`reason="unregistered"`** — unknown prefix; use `literal:...` for opaque values or `register_backend`.
- **`prefix`** — normalized backend name from the reference.

## Encrypted wire values (`$A256GCM$...`)

If the resolved string looks like an encrypted field (`is_encrypted_prefix`), it is decrypted with **`decrypt_string`** after resolving a `KeyContext` via **`set_keyctx_resolver`**.

- Segment 2 of the wire is a **canonical UUID string** (logical key id), same as `EncryptedString` column ciphertext.
- **`secrets_resolver.set_keyctx_resolver`** is **separate** from **`EncryptedString.set_keyctx_resolver`**. If you use both encrypted config values and encrypted columns, register both (often with the same underlying lookup).

## API notes

- **`set_keyctx_resolver(func: Callable[[str], KeyContext])`** — must be called before resolving encrypted secrets.
- **`set_allowed_file_path_prefixes(prefixes)`** — replace the `file:` path allowlist (default `/app/secret` only).
- **`allowed_file_path_prefixes() -> frozenset[str]`** — resolved allowlist prefixes for introspection.
- **`resolve_secret(value: str) -> str`** — dispatches on prefix or decrypts encrypted blobs.
- **`FilePathNotAllowed`** — raised when a `file:` path is outside the allowlist.

## Operational caveats

- **`env:` scrubbing** removes variables after first read; behavior is process-global.
- **Caching** applies to env, file, and secret paths; treat the process as holding secrets in memory.

For backend-specific details, see [README.md](../README.md#secret-resolver-backends).
