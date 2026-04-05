# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/types.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from gemstone_utils.crypto import recommended_data_alg


@dataclass
class KeyRecord:
    """
    Generic encrypted-key metadata container.

    Applications construct this from their own storage layer.
    ``params`` matches the JSON params segment in the encrypted-field wire format.
    """
    keyid: int
    alg: str
    encrypted_key: bytes
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KeyContext:
    """
    Active key context for field encryption (data key + keyid + algorithm).
    """
    keyid: int
    key: bytes
    alg: str = field(default_factory=recommended_data_alg)
