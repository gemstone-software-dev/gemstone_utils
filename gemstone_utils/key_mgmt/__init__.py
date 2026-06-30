# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/key_mgmt/__init__.py

"""KEK derivation, wrap/unwrap, passphrase loading, and rotation helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from gemstone_utils.crypto import decrypt_alg, encrypt_alg
from gemstone_utils.experimental.secrets_resolver import resolve_secret
from gemstone_utils.types import KeyContext, KeyRecord

# Register built-in KDFs (side effect).
from .kdf import pbkdf2 as _kdf_pbkdf2  # noqa: F401
from .kdf.pbkdf2 import recommended_pbkdf2_params
from .registry import derive_kek, register_kdf


def recommended_kdf_params(salt: Optional[bytes] = None) -> dict[str, Any]:
    """Return params for the library's current recommended KDF.

    Today: PBKDF2-HMAC-SHA256 via ``kdf.pbkdf2.recommended_pbkdf2_params``.

    Args:
        salt: Optional fixed salt; random 16-byte salt when omitted.

    Returns:
        Params dict suitable for ``derive_kek`` and ``set_kdf_params``.
    """
    return recommended_pbkdf2_params(salt=salt)


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
) -> None:
    """Configure module-level key management settings.

    Must be called before ``make_kek_check_record``, ``verify_kek``, or
    ``load_passphrase``.

    Args:
        secret_name: Name passed to ``resolve_secret("secret:...")``.
        check_plaintext: Fixed plaintext bytes encrypted into the KEK-check blob.
        env_allowed: Whether to fall back to ``env:`` when the secret mount fails.
        env_var_name: Environment variable name for fallback (defaults to
            ``secret_name``).
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
    """Raised when a derived KEK fails KEK-check decryption.

    Attributes:
        secret_name: Configured secret name from ``init()``.
        last_updated_iso: UTC ISO timestamp of last passphrase rotation, or
            ``"unknown"``.
    """

    def __init__(self, secret_name: str, last_updated_iso: str):
        super().__init__(
            f"secret '{secret_name}' holds an incorrect passphrase. "
            f"Passphrase was last rotated on {last_updated_iso}."
        )
        self.secret_name = secret_name
        self.last_updated_iso = last_updated_iso


# ---------------------------------------------------------------------------
# KEK-check handling (KeyRecord with ``keyid is None``)
# ---------------------------------------------------------------------------


def make_kek_check_record(kek: bytes, alg: str = "A256GCM") -> KeyRecord:
    """Build a KEK-check ``KeyRecord`` (``keyid is None``).

    Args:
        kek: Key-encryption key bytes.
        alg: Symmetric wrap algorithm id.

    Returns:
        ``KeyRecord`` with encrypted ``CHECK_PLAINTEXT`` from ``init()``.

    Raises:
        RuntimeError: If ``init()`` was not called.
    """
    if CHECK_PLAINTEXT is None:
        raise RuntimeError("key_mgmt.init() must be called before use")

    blob, sym_params = encrypt_alg(alg, kek, CHECK_PLAINTEXT, None)
    return KeyRecord(keyid=None, alg=alg, encrypted_key=blob, params=sym_params)


def verify_kek(
    kek: bytes,
    record: KeyRecord,
    last_updated: Optional[datetime] = None,
) -> None:
    """Verify that ``kek`` decrypts the KEK-check record.

    Args:
        kek: Derived key-encryption key bytes.
        record: KEK-check record (``keyid`` must be ``None``).
        last_updated: Optional timestamp included in ``KEKVerificationError``.

    Raises:
        ValueError: If ``record`` is not a KEK-check record.
        RuntimeError: If ``init()`` was not called.
        KEKVerificationError: If decryption does not yield ``CHECK_PLAINTEXT``.
    """
    if record.keyid is not None:
        raise ValueError("verify_kek() requires a KEK-check record (keyid=None)")

    if CHECK_PLAINTEXT is None:
        raise RuntimeError("key_mgmt.init() must be called before use")

    try:
        pt = decrypt_alg(record.alg, kek, record.encrypted_key, record.params)
    except Exception:
        pt = None

    if pt != CHECK_PLAINTEXT:
        iso_ts = (
            last_updated.astimezone(timezone.utc).isoformat()
            if last_updated
            else "unknown"
        )
        raise KEKVerificationError(SECRET_NAME, iso_ts)


# ---------------------------------------------------------------------------
# Key unwrap / wrap
# ---------------------------------------------------------------------------


def unwrap_key(kek: bytes, record: KeyRecord) -> bytes:
    """Decrypt a DEK from a wrapped ``KeyRecord``.

    Args:
        kek: Key-encryption key bytes.
        record: DEK record (``keyid`` must be set).

    Returns:
        Unwrapped key bytes.

    Raises:
        ValueError: If ``record`` is a KEK-check record.
    """
    if record.keyid is None:
        raise ValueError("unwrap_key() called on KEK-check record")
    return decrypt_alg(record.alg, kek, record.encrypted_key, record.params)


def wrap_key(kek: bytes, key: bytes, alg: str = "A256GCM") -> KeyRecord:
    """Encrypt key material under a KEK.

    Args:
        kek: Key-encryption key bytes.
        key: Plaintext key bytes to wrap.
        alg: Symmetric wrap algorithm id.

    Returns:
        ``KeyRecord`` with ``keyid=None``; caller sets ``keyid`` when persisting.
    """
    blob, sym_params = encrypt_alg(alg, kek, key, None)
    return KeyRecord(keyid=None, alg=alg, encrypted_key=blob, params=sym_params)


def load_keyctx(kek: bytes, record: KeyRecord) -> KeyContext:
    """Build a ``KeyContext`` from a KEK and DEK ``KeyRecord``.

    Args:
        kek: Key-encryption key bytes.
        record: DEK record (``keyid`` must be set).

    Returns:
        ``KeyContext`` with unwrapped key and metadata from ``record``.

    Raises:
        ValueError: If ``record`` is a KEK-check record.
    """
    if record.keyid is None:
        raise ValueError("load_keyctx() requires a DEK KeyRecord (keyid set)")
    key = unwrap_key(kek, record)
    return KeyContext(keyid=record.keyid, key=key, alg=record.alg)


# ---------------------------------------------------------------------------
# Passphrase loading (secret store or environment)
# ---------------------------------------------------------------------------


def load_passphrase() -> str:
    """Load the vault passphrase via ``resolve_secret``.

    Tries ``secret:{SECRET_NAME}``, then ``env:{ENV_VAR_NAME}`` when
    ``ENV_ALLOWED`` is true.

    Returns:
        Passphrase string.

    Raises:
        RuntimeError: If ``init()`` was not called.
        ValueError: If neither configured source resolves.
    """
    if SECRET_NAME is None:
        raise RuntimeError("key_mgmt.init() must be called before use")

    try:
        return resolve_secret(f"secret:{SECRET_NAME}")
    except Exception:
        pass

    if ENV_ALLOWED:
        try:
            return resolve_secret(f"env:{ENV_VAR_NAME}")
        except Exception:
            pass

    if ENV_ALLOWED:
        raise ValueError(
            f"Unable to load passphrase: neither secret:{SECRET_NAME} "
            f"nor env:{ENV_VAR_NAME} resolved successfully."
        )
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
    """Derive a KEK and verify it against the KEK-check record.

    Args:
        passphrase: Vault passphrase.
        kdf_params: Persisted KDF params dict (must include ``"kdf"``).
        kek_check_record: KEK-check ``KeyRecord``.
        last_updated: Optional timestamp for ``KEKVerificationError``.

    Returns:
        Verified KEK bytes.

    Raises:
        KEKVerificationError: If the check blob does not decrypt correctly.
        ValueError: If KDF params are invalid.
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
    """Re-wrap DEK records under a new KEK.

    Args:
        old_kek: Current key-encryption key.
        new_kek: New key-encryption key.
        records: Iterable of DEK ``KeyRecord`` instances.
        new_alg: Optional wrap algorithm; preserves each record's ``alg`` when
            omitted.

    Returns:
        New ``KeyRecord`` list with updated ciphertext. KEK-check records
        (``keyid is None``) are skipped.
    """
    updated = []

    for rec in records:
        if rec.keyid is None:
            continue

        key = unwrap_key(old_kek, rec)
        alg = new_alg or rec.alg
        new_blob, new_params = encrypt_alg(alg, new_kek, key, None)

        updated.append(
            KeyRecord(
                keyid=rec.keyid,
                alg=alg,
                encrypted_key=new_blob,
                params=new_params,
            )
        )

    return updated


def rotate_kek(
    old_kek: bytes,
    new_kek: bytes,
    records: Iterable[KeyRecord],
    new_alg: Optional[str] = None,
) -> tuple[KeyRecord, list[KeyRecord]]:
    """Rotate KEK: rewrap DEKs and produce a new KEK-check record.

    Args:
        old_kek: Current key-encryption key.
        new_kek: New key-encryption key.
        records: Iterable of DEK ``KeyRecord`` instances.
        new_alg: Optional wrap algorithm for all DEK records.

    Returns:
        Tuple ``(new_kek_check_record, updated_dek_records)``.
    """
    new_check = make_kek_check_record(new_kek)
    updated = reencrypt_keys(old_kek, new_kek, records, new_alg=new_alg)
    return new_check, updated
