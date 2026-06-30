# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/encrypted_fields.py

from __future__ import annotations

import json
import warnings
from typing import Any, Dict, Optional, Tuple

from .crypto import (
    b64decode,
    b64encode,
    decrypt_alg,
    encrypt_alg,
    is_supported_sym_alg,
    require_supported_sym_alg,
)
from .key_id import normalize_key_id
from .types import KeyContext


def is_encrypted_prefix(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith("$"):
        return False
    parts = value.split("$")
    if len(parts) < 4 or parts[0] != "":
        return False
    return is_supported_sym_alg(parts[1])


def _params_json_bytes(params: Dict[str, Any]) -> bytes:
    return json.dumps(params, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _encode_params_segment(params: Dict[str, Any]) -> str:
    return b64encode(_params_json_bytes(params))


def _decode_params_segment(segment: str) -> Dict[str, Any]:
    raw = b64decode(segment)
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError("invalid algorithm parameters (not valid JSON)") from e
    if not isinstance(data, dict):
        raise ValueError("algorithm parameters must be a JSON object")
    return data


def _parse_key_id_segment(seg: str) -> str:
    if seg.isdigit():
        raise ValueError(
            "legacy integer key id in encrypted field; migrate ciphertext to UUID "
            "key ids (see gemstone_utils migration docs) before using this version"
        )
    return normalize_key_id(seg)


def format_encrypted_field(
    alg: str,
    keyid: str,
    blob: bytes,
    params: Optional[Dict[str, Any]] = None,
) -> str:
    require_supported_sym_alg(alg)
    p = {} if params is None else params
    kid = normalize_key_id(keyid)
    return f"${alg}${kid}${_encode_params_segment(p)}${b64encode(blob)}"


def parse_encrypted_field(value: str) -> Tuple[str, str, Dict[str, Any], bytes]:
    parts = value.split("$")
    if parts[0] != "":
        raise ValueError("invalid encrypted field format")

    if len(parts) == 4:
        warnings.warn(
            "Four-part encrypted fields (no algorithm-parameters segment) are deprecated "
            "and will be removed in gemstone_utils 0.9.0; re-encrypt or run a key rotation "
            "with gemstone_utils >= 0.3.0 to migrate.",
            DeprecationWarning,
            stacklevel=2,
        )
        alg_id = parts[1]
        keyid = _parse_key_id_segment(parts[2])
        blob = b64decode(parts[3])
        require_supported_sym_alg(alg_id)
        return alg_id, keyid, {}, blob

    if len(parts) == 5:
        alg_id = parts[1]
        keyid = _parse_key_id_segment(parts[2])
        params = _decode_params_segment(parts[3])
        blob = b64decode(parts[4])
        require_supported_sym_alg(alg_id)
        return alg_id, keyid, params, blob

    raise ValueError("invalid encrypted field format")


def _validate_alg_params(alg_id: str, params: Dict[str, Any]) -> None:
    spec = require_supported_sym_alg(alg_id)
    spec.validate_sym_params(params)


def encrypt_string(plaintext: Optional[str], keyctx: KeyContext) -> Optional[str]:
    if plaintext is None:
        return None
    blob, out_params = encrypt_alg(
        keyctx.alg, keyctx.key, plaintext.encode("utf-8"), None
    )
    return format_encrypted_field(keyctx.alg, keyctx.keyid, blob, out_params)


def decrypt_string(value: Optional[str], keyctx: KeyContext) -> Optional[str]:
    if value is None:
        return None

    alg_id, keyid, params, blob = parse_encrypted_field(value)

    if alg_id != keyctx.alg:
        raise ValueError(f"unsupported algorithm: {alg_id}")
    if keyid != keyctx.keyid:
        raise ValueError(f"unexpected keyid {keyid}")

    _validate_alg_params(alg_id, params)

    return decrypt_alg(keyctx.alg, keyctx.key, blob, params).decode("utf-8")
