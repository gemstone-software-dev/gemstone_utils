# gemstone_utils

**gemstone_utils** provides a small, stable core of cryptographic helpers, transparent AES‑GCM encrypted SQLAlchemy fields, and a minimal experimental secrets resolver suitable for Pydantic’s `BeforeValidator`. It is designed for applications that need reversible secret storage with minimal plaintext exposure and predictable operational behavior.

The package is licensed under the **MPL‑2.0**, allowing use in both open‑source and proprietary projects while keeping modifications to this library itself open.

---

## Features

### 🔐 Cryptography core
- AES‑256‑GCM encryption and decryption
- PBKDF2‑HMAC‑SHA256 key derivation (no extra dependencies)
- URL‑safe base64 encoding helpers
- Minimal, dependency‑light design

### 🧩 Encrypted fields
- `$A256GCM$keyid$base64(json)$base64(blob)` encrypted‑field format (algorithm parameters + ciphertext)
- `KeyContext` (`keyid`, `key`, `alg`) in `gemstone_utils.types`
- `encrypt_string()` and `decrypt_string()` helpers in `gemstone_utils.encrypted_fields`

### 🗄️ SQLAlchemy integration
- `EncryptedString` TypeDecorator
- Transparent encryption on write
- Lazy decryption on read via `LazySecret`
- Prevents accidental double‑encryption
- `EncryptedString.set_current_keyctx()` for the active write key
- `EncryptedString.set_keyctx_resolver()` to map `keyid` from stored ciphertext to a `KeyContext` on read

### 🔐 Key management (`key_mgmt`)
- **`derive_kek(passphrase, params)`** plus a pluggable **`register_kdf`** registry; params JSON is the source of truth for which algorithm runs.
- **`recommended_kdf_params()`** — library default for *new* KDF rows (today: PBKDF2‑HMAC‑SHA256 with strong iteration count and random salt).
- **`gemstone_utils.key_mgmt.kdf`** — documented contract (`RecommendedKdfParamsFn`, `HasKdfRegistryName`) and per‑algorithm modules (e.g. **`kdf.pbkdf2`**: `NAME`, `pbkdf2_params`, `recommended_pbkdf2_params`) when you pin a specific algorithm instead of the default.

### 🔑 SQL key storage (`sqlalchemy.key_storage`)
- Tables `gemstone_key_kdf` (persisted KDF JSON per KEK slot) and `gemstone_key_record` (wrapped keys in the same five‑part wire format as encrypted columns)
- Logical `key_id` **0** holds the KEK **canary**; **1+** hold **DEKs** referenced by `EncryptedString` ciphertexts. The **segment** `keyid` inside each wire string is the KEK slot (foreign meaning: row in `gemstone_key_kdf`), not the DEK’s logical id.
- Bootstrap persisted KDF rows with **`new_kdf_params()`** (alias of **`recommended_kdf_params`**) or your own params dict; **`salt` must always be stored** in JSON for PBKDF2 rows.
- `make_keyctx_resolver()` wires `EncryptedString.set_keyctx_resolver()` to `get_session()` + persisted rows + `derive_kek` / `load_keyctx`.
- `rewrap_key_records()` performs `rotate_kek`‑style batch re‑wrap inside a transaction you open with `with session.begin(): ...`.

Back up `gemstone_key_kdf` with the same care as `gemstone_key_record`: salt and iteration counts are required to recover KEKs from the vault passphrase.

### 🧪 Experimental secret resolver
Suitable for Pydantic `BeforeValidator`:

Supports:
- `env:` — environment variables (cached + scrubbed)
- `file:` — read from filesystem
- `secret:` — systemd / container secret directories
- pluggable backends (`sqlexp:`, `azexp:`) enabled by explicitly importing plugin modules
- `$A256GCM$keyid$base64(json)$base64(blob)` encrypted values (requires `secrets_resolver.set_keyctx_resolver`)

Not intended to be the final vault/meta‑manager.

### 🧪 Experimental SQL backend (`sqlexp`)
- Simple key/value table using SQLAlchemy
- Stores encrypted values
- No ACLs, hierarchy, or versioning
- Intended for bootstrap use only

---

## Installation

```
pip install gemstone_utils
```

With Azure Key Vault support:

```
pip install 'gemstone_utils[azure]'
```

For running tests in a checkout:

```
pip install 'gemstone_utils[dev]'
```

Or from a source tarball:

```
pip install gemstone_utils-0.2.0.tar.gz
```

---

## Quick Start

### 1. Derive a data key and wire `EncryptedString`

```python
from gemstone_utils.key_mgmt import derive_kek, recommended_kdf_params
from gemstone_utils.key_mgmt.kdf.pbkdf2 import pbkdf2_params
from gemstone_utils.types import KeyContext
from gemstone_utils.sqlalchemy.encrypted_type import EncryptedString
from gemstone_utils.experimental.secrets_resolver import resolve_secret

passphrase = resolve_secret("env:APP_DK_PASSPHRASE")
salt = resolve_secret("env:APP_DK_SALT").encode("utf-8")

dk = derive_kek(passphrase, pbkdf2_params(salt))
# or: derive_kek(passphrase, recommended_kdf_params(salt))
ctx = KeyContext(keyid=1, key=dk)

EncryptedString.set_current_keyctx(ctx)

def resolve_enc_keyctx(keyid: int) -> KeyContext:
    if keyid != ctx.keyid:
        raise ValueError(f"unknown keyid {keyid}")
    return ctx

EncryptedString.set_keyctx_resolver(resolve_enc_keyctx)
```

`set_current_keyctx` is used for new writes. `set_keyctx_resolver` is used on read to choose the correct `KeyContext` for each row’s embedded `keyid` (needed for rotation and multiple keys).

### 1b. Optional: persisted keys + `EncryptedString` resolver

```python
import os

import gemstone_utils.sqlalchemy.key_storage  # registers ORM tables on GemstoneDB
from gemstone_utils.db import get_session, init_db
from gemstone_utils.key_mgmt import derive_kek, init as key_mgmt_init, make_kek_check_record
from gemstone_utils.sqlalchemy.encrypted_type import EncryptedString
from gemstone_utils.sqlalchemy.key_storage import (
    GemstoneKeyRecord,
    keyrecord_to_wire,
    make_keyctx_resolver,
    new_kdf_params,
    set_kdf_params,
    wire_wrap,
)
from gemstone_utils.types import KeyContext

init_db("sqlite:///./app.db")
key_mgmt_init("vault_passphrase", b"constant-canary-bytes", env_allowed=True)

passphrase = "human vault passphrase"
kdf = new_kdf_params()
kek = derive_kek(passphrase, kdf)
dek = KeyContext(keyid=1, key=os.urandom(32))

with get_session() as session:
    with session.begin():
        set_kdf_params(session, 1, kdf)
        session.add(
            GemstoneKeyRecord(
                key_id=0,
                wrapped=keyrecord_to_wire(make_kek_check_record(kek), 1),
            )
        )
        session.add(
            GemstoneKeyRecord(
                key_id=1,
                wrapped=wire_wrap(1, kek, dek.key),
            )
        )

EncryptedString.set_current_keyctx(dek)
EncryptedString.set_keyctx_resolver(
    make_keyctx_resolver(load_passphrase=lambda: passphrase)
)
```

KEK rotation (new passphrase or new KEK under the same KDF row) uses `rewrap_key_records` inside `with session.begin():` — see `gemstone_utils.sqlalchemy.key_storage`.

### 2. Use encrypted fields in SQLAlchemy models

```python
from sqlalchemy import Column, Integer
from gemstone_utils.sqlalchemy.encrypted_type import EncryptedString

class OAuthToken(Base):
    __tablename__ = "oauth_tokens"

    id = Column(Integer, primary_key=True)
    refresh_token = Column(EncryptedString, nullable=False)
```

### 3. Use the experimental secrets resolver with Pydantic

```python
from pydantic import BaseModel, field_validator
from gemstone_utils.experimental.secrets_resolver import resolve_secret
from gemstone_utils.experimental import sqlexp_backend  # enables sqlexp:

class Config(BaseModel):
    api_token: str

    @field_validator("api_token", mode="before")
    @classmethod
    def load_secret(cls, v):
        return resolve_secret(v)
```

`sqlexp:` uses `gemstone_utils.db.get_session()` internally. Call `init_db(...)` before resolving `sqlexp:` values.

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
`gemstone_utils.experimental.sqlexp_backend` (or calling its `enable()`).
Uses `gemstone_utils.db.get_session()` internally.

### `azexp:https://vault.vault.azure.net/secrets/name`
Fetches from Azure Key Vault. Enabled by importing
`gemstone_utils.experimental.azexp_backend` (or calling its `enable()`).
Install `gemstone_utils[azure]` and authenticate with `DefaultAzureCredential`.
Use `azexp_backend.set_azexp_credential(...)` to override credentials.

### Encrypted field values (`$A256GCM$…`)
Values use the wire form `$A256GCM$<keyid>$<base64(json)>$<base64(blob)>`: URL-safe base64 of a JSON object for per-algorithm parameters (currently `{}` for `A256GCM`), then URL-safe base64 of the ciphertext blob. Automatically decrypted using `secrets_resolver.set_keyctx_resolver` (separate from `EncryptedString.set_keyctx_resolver`).

---

## Experimental Components

The following modules are intentionally minimal and **will not** be part of the future vault/meta‑manager:

- `gemstone_utils.experimental.secrets_resolver`
- `gemstone_utils.experimental.sqlexp`

They exist to support early projects (GemstoneOps, Thaum, WebexCalling bridge) without constraining the design of the full resolver.

---

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL‑2.0)**.  
You may use it in proprietary applications, but modifications to this library itself must be published under the MPL.
