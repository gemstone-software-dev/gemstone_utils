# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/key_mgmt.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Iterable, Callable, Dict, Any

from gemstone_utils.experimental.secrets_resolver import resolve_secret
from .types import KeyRecord, KeyContext
from .crypto import encrypt_with_alg, decrypt_with_alg


# ---------------------------------------------------------------------------
# Module-level configuration (set by init())
# ---------------------------------------------------------------------------

SECRET_NAME: Optional[str] = None
CHECK_PLAINTEXT: Optional[bytes] = None
ENV_ALLOWED: bool = False
ENV_VAR_NAME: Optional[str] = None


def init(
    secret_name: str,
    check_plaintext: bytes,
    env_allowed: bool = False,
    env_var_name: Optional[str] = None,
):
    """
    Configure the key management subsystem.
    """
    global SECRET_NAME, CHECK_PLAINTEXT, ENV_ALLOWED, ENV_VAR_NAME

    SECRET_NAME = secret_name
    CHECK_PLAINTEXT = check_plaintext
    ENV_ALLOWED = env_allowed
    ENV_VAR_NAME = env_var_name or secret_name


# ---------------------------------------------------------------------------
# Custom exception type for structured KEK failures
# ---------------------------------------------------------------------------

class KEKVerificationError(ValueError):
    """
    Raised when the KEK-check blob cannot be decrypted with the derived KEK.
    Includes structured fields for Virgil to log cleanly.
    """
    def __init__(self, secret_name: str, last_updated_iso: str):
        super().__init__(
            f"secret '{secret_name}' holds an incorrect passphrase. "
            f"Passphrase was last rotated on {last_updated_iso}."
        )
        self.secret_name = secret_name
        self.last_updated_iso = last_updated_iso


# ---------------------------------------------------------------------------
# KDF registry / dispatcher
# ---------------------------------------------------------------------------

_KDF_REGISTRY: Dict[str, Callable[[str, Dict[str, Any]], bytes]] = {}


def register_kdf(name: str):
    def decorator(fn):
        _KDF_REGISTRY[name] = fn
        return fn
    return decorator


def derive_kek(passphrase: str, params: dict) -> bytes:
    """
    Dispatch to the correct KDF implementation based on params["kdf"].
    """
    kdf_name = params.get("kdf")
    if not kdf_name:
        raise ValueError("KDF parameters missing 'kdf' field")

    fn = _KDF_REGISTRY.get(kdf_name)
    if not fn:
        raise ValueError(f"Unsupported KDF: {kdf_name}")

    return fn(passphrase, params)


# ---------------------------------------------------------------------------
# KEK-check handling (keyid = 0)
# ---------------------------------------------------------------------------

def make_kek_check_record(kek: bytes, alg: str = "A256GCM") -> KeyRecord:
    """
    Create a KeyRecord(keyid=0) containing the KEK-check blob.
    """
    if CHECK_PLAINTEXT is None:
        raise RuntimeError("key_mgmt.init() must be called before use")

    blob = encrypt_with_alg(alg, kek, CHECK_PLAINTEXT)
    return KeyRecord(keyid=0, alg=alg, encrypted_key=blob)


def verify_kek(
    kek: bytes,
    record: KeyRecord,
    last_updated: Optional[datetime] = None
) -> None:
    """
    Verify that the KEK decrypts the KEK-check record correctly.
    Raises KEKVerificationError with structured fields if verification fails.
    """
    if record.keyid != 0:
        raise ValueError("verify_kek() requires keyid=0 record")

    if CHECK_PLAINTEXT is None:
        raise RuntimeError("key_mgmt.init() must be called before use")

    try:
        pt = decrypt_with_alg(record.alg, kek, record.encrypted_key)
    except Exception:
        pt = None

    if pt != CHECK_PLAINTEXT:
        iso_ts = (
            last_updated.astimezone(timezone.utc).isoformat()
            if last_updated else "unknown"
        )
        raise KEKVerificationError(SECRET_NAME, iso_ts)


# ---------------------------------------------------------------------------
# Key unwrap / wrap
# ---------------------------------------------------------------------------

def unwrap_key(kek: bytes, record: KeyRecord) -> bytes:
    """Decrypt the key using the KEK and the record's alg."""
    if record.keyid == 0:
        raise ValueError("unwrap_key() called on KEK-check record")
    return decrypt_with_alg(record.alg, kek, record.encrypted_key)


def wrap_key(kek: bytes, key: bytes, alg: str = "A256GCM") -> KeyRecord:
    """Encrypt a key using the KEK and return a KeyRecord (caller sets keyid)."""
    blob = encrypt_with_alg(alg, kek, key)
    return KeyRecord(keyid=-1, alg=alg, encrypted_key=blob)


def load_keyctx(kek: bytes, record: KeyRecord) -> KeyContext:
    """Produce a KeyContext from a KEK + KeyRecord."""
    key = unwrap_key(kek, record)
    return KeyContext(keyid=record.keyid, key=key, alg=record.alg)


# ---------------------------------------------------------------------------
# Passphrase loading (secret store or environment)
# ---------------------------------------------------------------------------

def load_passphrase() -> str:
    """
    Load the Vault Passphrase using the standard secret resolver.
    Tries secret:{SECRET_NAME}, then env:{ENV_VAR_NAME} if ENV_ALLOWED.
    """
    if SECRET_NAME is None:
        raise RuntimeError("key_mgmt.init() must be called before use")

    # 1. Try secret store
    try:
        return resolve_secret(f"secret:{SECRET_NAME}")
    except Exception:
        pass

    # 2. Try environment variable (only if allowed)
    if ENV_ALLOWED:
        try:
            return resolve_secret(f"env:{ENV_VAR_NAME}")
        except Exception:
            pass

    # 3. Fail cleanly
    if ENV_ALLOWED:
        raise ValueError(
            f"Unable to load passphrase: neither secret:{SECRET_NAME} "
            f"nor env:{ENV_VAR_NAME} resolved successfully."
        )
    else:
        raise ValueError(
            f"Unable to load passphrase: secret:{SECRET_NAME} did not resolve "
            f"and environment fallback is disabled (ENV_ALLOWED=False)."
        )


# ---------------------------------------------------------------------------
# KEK derivation + verification
# ---------------------------------------------------------------------------

def derive_and_verify_kek(
    passphrase: str,
    kdf_params: dict,
    kek_check_record: KeyRecord,
    last_updated: Optional[datetime] = None,
) -> bytes:
    """
    Derive KEK from passphrase + KDF params, then verify via KEK-check.
    Returns KEK bytes or raises KEKVerificationError.
    """
    kek = derive_kek(passphrase, kdf_params)
    verify_kek(kek, kek_check_record, last_updated=last_updated)
    return kek


def reencrypt_keys(
    old_kek: bytes,
    new_kek: bytes,
    records: Iterable[KeyRecord],
    new_alg: Optional[str] = None,
) -> list[KeyRecord]:
    """
    Re-encrypt all keys under a new KEK.
    If new_alg is provided, rewrap using that algorithm.
    Otherwise preserve each record's existing algorithm.
    """
    updated = []

    for rec in records:
        if rec.keyid == 0:
            continue  # KEK-check handled separately

        key = unwrap_key(old_kek, rec)
        alg = new_alg or rec.alg
        new_blob = encrypt_with_alg(alg, new_kek, key)

        updated.append(
            KeyRecord(
                keyid=rec.keyid,
                alg=alg,
                encrypted_key=new_blob,
            )
        )

    return updated


def rotate_kek(
    old_kek: bytes,
    new_kek: bytes,
    records: Iterable[KeyRecord],
    new_alg: Optional[str] = None,
) -> tuple[KeyRecord, list[KeyRecord]]:
    """
    Rotate the KEK:
      - Rewrap all keys under the new KEK
      - Create a new KEK-check record
      - Optionally update the encryption algorithm for all keys

    Returns:
      (new_kek_check_record, updated_key_records)
    """
    new_check = make_kek_check_record(new_kek)
    updated = reencrypt_keys(old_kek, new_kek, records, new_alg=new_alg)
    return new_check, updated
