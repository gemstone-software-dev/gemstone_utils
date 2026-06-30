# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/key_mgmt/kdf/__init__.py

"""
Algorithm-specific KDF helpers under ``gemstone_utils.key_mgmt.kdf``.

**Contributor contract** for each submodule (e.g. ``pbkdf2``, future ``argon2id``):

- Add the registry id to ``_ALLOWED_KDF_NAMES`` in
  :mod:`gemstone_utils.key_mgmt.registry` in the **same release** as the submodule.
- Register with :func:`gemstone_utils.key_mgmt.register_kdf` when the submodule
  is imported (typically triggered by importing ``gemstone_utils.key_mgmt``).
  ``register_kdf`` is for first-party modules only; third-party runtime
  registration is not supported.
- Expose module-level **NAME** (``str``): registry id stored in persisted JSON
  as ``params[\"kdf\"]``.
- Expose **recommended_<algorithm>_params(salt=None) -> dict** with strong
  defaults for *new* key material (e.g. random salt when ``salt is None``).
  Examples: ``recommended_pbkdf2_params``, future ``recommended_argon2id_params``.
- Optionally expose an explicit params builder (e.g. ``pbkdf2_params``) for
  fixed salt / custom tuning; document its name in the submodule.

The function name ``recommended_*_params`` is by convention; its callable
shape matches :class:`RecommendedKdfParamsFn`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class RecommendedKdfParamsFn(Protocol):
    """Callable shape for ``recommended_<algorithm>_params`` factories.

    Implementations return a params dict for ``derive_kek``.
    """

    def __call__(self, salt: Optional[bytes] = None) -> Dict[str, Any]:
        ...


class HasKdfRegistryName(Protocol):
    """Module-level registry id for a KDF algorithm package.

    Attributes:
        NAME: String stored in persisted JSON as ``params["kdf"]``.
    """

    NAME: str


__all__ = [
    "HasKdfRegistryName",
    "RecommendedKdfParamsFn",
]
