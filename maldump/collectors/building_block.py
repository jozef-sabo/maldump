from __future__ import annotations

from abc import abstractmethod, ABC
from typing import TypeVar, Generic, Callable, Any

from maldump.collectors.list_dict import ListDict

T = TypeVar("T")


class BuildingBlock(ABC, Generic[T]):

    def __init__(
        self,
        data: T | None = None,
        in_blocks: list[BuildingBlock] | dict[str, BuildingBlock] | None = None,
    ):
        self._in_blocks: ListDict = ListDict()
        self._data: T | None = None

        if in_blocks is not None:
            if isinstance(in_blocks, list):
                for item in in_blocks:
                    self._in_blocks.push(item)
            if isinstance(in_blocks, dict):
                for key, item in in_blocks:
                    self._in_blocks.put(key, item)
            else:
                raise TypeError(f"Input blocks must be a list or dict.")
        if data is not None:
            self.data = data

    def register_input(
        self, in_block: BuildingBlock, name: str | None = None
    ) -> BuildingBlock:
        if name is None:
            self._in_blocks.push(in_block)
        else:
            self._in_blocks.put(name, in_block)

        return self

    @staticmethod
    def _comp_wrapper(func: Callable) -> Callable:
        def wrapper(
            self: BuildingBlock, *args: list[Any], **kwargs: dict[str, Any]
        ) -> None:
            self._register_input()
            res = func(self, *args, **kwargs)
            self.data = res
            return res

        return wrapper

    @abstractmethod
    def _register_input(self) -> None:
        pass

    @property
    def data(self) -> T | None:
        return self._data

    @data.setter
    @abstractmethod
    def data(self, value: T) -> None:
        pass

    @abstractmethod
    def compute(self) -> T:
        pass
