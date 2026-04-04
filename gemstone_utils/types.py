# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/types.py

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class KeyRecord:
    """
    Generic encrypted-key metadata container.

    Applications construct this from their own storage layer.
    """
    keyid: int
    alg: str
    encrypted_key: bytes


@dataclass
class KeyContext:
    """
    Active key context for field encryption (data key + keyid + algorithm).
    """
    keyid: int
    key: bytes
    alg: str = "A256GCM"
