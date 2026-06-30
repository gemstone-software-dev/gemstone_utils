# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/types.py

"""Shared types for field encryption and wrapped key material."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from gemstone_utils.crypto import recommended_data_alg


@dataclass
class KeyRecord:
    """Encrypted key material and metadata for wrap/unwrap operations.

    Applications construct instances from their own storage layer. ``params``
    matches the JSON params segment in the encrypted-field wire format.

    Attributes:
        keyid: Logical DEK id (canonical UUID string), or ``None`` for a
            KEK-check (canary) blob that is not a DEK.
        alg: Symmetric wrap algorithm id.
        encrypted_key: Ciphertext blob (algorithm-specific layout).
        params: Per-algorithm parameters persisted alongside the blob.
    """

    keyid: Optional[str]
    alg: str
    encrypted_key: bytes
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KeyContext:
    """Active data key context for field encryption.

    Attributes:
        keyid: Canonical UUID string (segment 2 in encrypted-field wire format).
        key: Raw data-encryption key bytes.
        alg: Symmetric algorithm id for application field encryption.
    """

    keyid: str
    key: bytes
    alg: str = field(default_factory=recommended_data_alg)
