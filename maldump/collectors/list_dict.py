from __future__ import annotations

from dataclasses import dataclass, field

from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass
class ListDict(Generic[T]):
    args: list[T] = field(default_factory=list)
    kwargs: dict[str, T] = field(default_factory=dict)
    _type: None | type = None
    _itemtype: None | type = None

    def push(self, value: T) -> "ListDict":
        if self._type not in (None, list):
            raise TypeError("ListDict contains key-value pairs")
        if self._itemtype is not None and type(value) is not self._itemtype:
            raise TypeError(
                "Inserted incorrect type to ListDict, actual type %s",
                self._itemtype.__name__,
            )

        self._type = list
        self._itemtype = type(value)

        self.args.append(value)

        return self

    def put(self, key: str, value: T) -> "ListDict":
        if self._type not in (None, dict):
            raise TypeError("ListDict contains list items.")
        if not isinstance(key, str):
            raise TypeError("Key must be a string.")
        if self._itemtype is not None and type(value) is not self._itemtype:
            raise TypeError(
                "Inserted incorrect type to ListDict, actual type %s",
                self._itemtype.__name__,
            )
        self._type = dict
        self._itemtype = type(value)

        self.kwargs[key] = value

        return self

    @property
    def itemtype(self) -> type[None, dict, list]:
        return self._itemtype

    def __setitem__(self, key: str, value: T) -> None:
        self.put(key, value)

    def __getitem__(self, key: str) -> T:
        return self.kwargs[key]

    def get(self, key: type | str):
        if isinstance(key, str):
            return self.kwargs[key]

        filtered = self.get_alike(key)
        if len(filtered) != 1:
            raise KeyError(
                "ListDict item is not distinguishable based on the type or name."
            )

        return filtered[0]

    def get_alike(self, key: type):
        if not isinstance(key, type):
            raise TypeError("Key is not a type.")

        filtered = [item for item in self.args if isinstance(item, key)]

        return filtered

    def __contains__(self, item: str) -> bool:
        if self._type == dict:
            return item in self.kwargs
        if self._type == list:
            return item in self.args

        return False

    def __iter__(self):
        if self._type == dict:
            return self.kwargs.__iter__()
        if self._type == list:
            return self.args.__iter__()

        return [].__iter__()

    def __len__(self):
        if self._type == dict:
            return self.kwargs.__len__()
        if self._type == list:
            return self.args.__len__()

        return 0
