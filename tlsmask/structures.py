"""A dict whose keys ignore case, as HTTP header names do."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, MutableMapping
from typing import Any


def _low(key: Any) -> Any:
    return key.lower() if isinstance(key, str) else key


class CaseInsensitiveDict(MutableMapping):
    """Keys match whatever their case; iteration gives the latest spelling of
    each key, in the order the keys were first set (the order headers go out)."""

    def __init__(self, data: Any = None, **kwargs: Any) -> None:
        self._store: dict[Any, tuple[Any, Any]] = {}
        self.update(data or {}, **kwargs)

    def __setitem__(self, key: Any, value: Any) -> None:
        self._store[_low(key)] = (key, value)

    def __getitem__(self, key: Any) -> Any:
        return self._store[_low(key)][1]

    def __delitem__(self, key: Any) -> None:
        del self._store[_low(key)]

    def __iter__(self) -> Iterator[Any]:
        return (key for key, _ in self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def lower_items(self) -> Iterator[tuple[Any, Any]]:
        return ((low, pair[1]) for low, pair in self._store.items())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return NotImplemented
        return dict(self.lower_items()) == dict(CaseInsensitiveDict(other).lower_items())

    def copy(self) -> CaseInsensitiveDict:
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self) -> str:
        return str(dict(self.items()))
