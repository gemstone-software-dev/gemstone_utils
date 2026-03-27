# emerald_utils

**emerald_utils** provides a small, stable core of cryptographic helpers, transparent AES‑GCM encrypted SQLAlchemy fields, and a minimal experimental secrets resolver suitable for Pydantic’s `BeforeValidator`. It is designed for applications that need reversible secret storage with minimal plaintext exposure and predictable operational behavior.

The package is licensed under the **MPL‑2.0**, allowing use in both open‑source and proprietary projects while keeping modifications to this library itself open.

---

## Features

### 🔐 Cryptography core
- AES‑256‑GCM encryption and decryption
- PBKDF2‑HMAC‑SHA256 key derivation (no extra dependencies)
- URL‑safe base64 encoding helpers
- Minimal, dependency‑light design

### 🧩 Encrypted fields
- `$A256GCM$keyid$base64` encrypted‑field format
- `KeyContext` (`keyid`, `key`, `alg`) in `emerald_utils.types`
- `encrypt_string()` and `decrypt_string()` helpers in `emerald_utils.encrypted_fields`

### 🗄️ SQLAlchemy integration
- `EncryptedString` TypeDecorator
- Transparent encryption on write
- Lazy decryption on read via `LazySecret`
- Prevents accidental double‑encryption
- `EncryptedString.set_current_keyctx()` for the active write key
- `EncryptedString.set_keyctx_resolver()` to map `keyid` from stored ciphertext to a `KeyContext` on read

### 🧪 Experimental secret resolver
Suitable for Pydantic `BeforeValidator`:

Supports:
- `env:` — environment variables (cached + scrubbed)
- `file:` — read from filesystem
- `secret:` — systemd / container secret directories
- pluggable backends (`sqlexp:`, `azexp:`) enabled by explicitly importing plugin modules
- `$A256GCM$keyid$base64` encrypted values (requires `secrets_resolver.set_keyctx_resolver`)

Not intended to be the final vault/meta‑manager.

### 🧪 Experimental SQL backend (`sqlexp`)
- Simple key/value table using SQLAlchemy
- Stores encrypted values
- No ACLs, hierarchy, or versioning
- Intended for bootstrap use only

---

## Installation

```
pip install emerald_utils
```

With Azure Key Vault support:

```
pip install 'emerald_utils[azure]'
```

Or from a source tarball:

```
pip install emerald_utils-0.2.0.tar.gz
```

---

## Quick Start

### 1. Derive a data key and wire `EncryptedString`

```python
from emerald_utils.crypto import derive_kek_from_passphrase
from emerald_utils.types import KeyContext
from emerald_utils.sqlalchemy.encrypted_type import EncryptedString
from emerald_utils.experimental.secrets_resolver import resolve_secret

passphrase = resolve_secret("env:APP_DK_PASSPHRASE")
salt = resolve_secret("env:APP_DK_SALT").encode("utf-8")

dk = derive_kek_from_passphrase(passphrase, salt)
ctx = KeyContext(keyid=1, key=dk)

EncryptedString.set_current_keyctx(ctx)

def resolve_enc_keyctx(keyid: int) -> KeyContext:
    if keyid != ctx.keyid:
        raise ValueError(f"unknown keyid {keyid}")
    return ctx

EncryptedString.set_keyctx_resolver(resolve_enc_keyctx)
```

`set_current_keyctx` is used for new writes. `set_keyctx_resolver` is used on read to choose the correct `KeyContext` for each row’s embedded `keyid` (needed for rotation and multiple keys).

### 2. Use encrypted fields in SQLAlchemy models

```python
from sqlalchemy import Column, Integer
from emerald_utils.sqlalchemy.encrypted_type import EncryptedString

class OAuthToken(Base):
    __tablename__ = "oauth_tokens"

    id = Column(Integer, primary_key=True)
    refresh_token = Column(EncryptedString, nullable=False)
```

### 3. Use the experimental secrets resolver with Pydantic

```python
from pydantic import BaseModel, field_validator
from emerald_utils.experimental.secrets_resolver import resolve_secret
from emerald_utils.experimental import sqlexp_backend  # enables sqlexp:

class Config(BaseModel):
    api_token: str

    @field_validator("api_token", mode="before")
    @classmethod
    def load_secret(cls, v):
        return resolve_secret(v)
```

`sqlexp:` uses `emerald_utils.db.get_session()` internally. Call `init_db(...)` before resolving `sqlexp:` values.

Config example:

```
api_token = "secret:my_api_token"
```

---

## Secret Resolver Backends

### `env:VAR`
Reads from environment, caches, and scrubs the variable.

### `file:/path/to/file`
Reads a file once and caches it.

### `secret:name`
Searches:
- `$CREDENTIALS_DIRECTORY/name`
- `/run/secrets/name`
- `/var/run/secrets/name`

### `sqlexp:key`
Reads from the experimental SQL key/value store. Enabled by importing
`emerald_utils.experimental.sqlexp_backend` (or calling its `enable()`).
Uses `emerald_utils.db.get_session()` internally.

### `azexp:https://vault.vault.azure.net/secrets/name`
Fetches from Azure Key Vault. Enabled by importing
`emerald_utils.experimental.azexp_backend` (or calling its `enable()`).
Install `emerald_utils[azure]` and authenticate with `DefaultAzureCredential`.
Use `azexp_backend.set_azexp_credential(...)` to override credentials.

### `$A256GCM$keyid$base64`
Automatically decrypted using `secrets_resolver.set_keyctx_resolver` (separate from `EncryptedString.set_keyctx_resolver`).

---

## Experimental Components

The following modules are intentionally minimal and **will not** be part of the future vault/meta‑manager:

- `emerald_utils.experimental.secrets_resolver`
- `emerald_utils.experimental.sqlexp`

They exist to support early projects (EmeraldOps, Thaum, WebexCalling bridge) without constraining the design of the full resolver.

---

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL‑2.0)**.  
You may use it in proprietary applications, but modifications to this library itself must be published under the MPL.
