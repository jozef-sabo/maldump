from __future__ import annotations

from abc import abstractmethod
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.path_input import PathInput
from maldump.structures import QuarEntry


class Parser(BuildingBlock):

    @abstractmethod
    def compute(self) -> list[QuarEntry]:
        pass

    def __init__(self) -> None:
        super().__init__()
        self._path: Path | None = None

    @property
    def path(self) -> Path | None:
        return self._path

    @BuildingBlock.data.setter  # type: ignore [attr-defined]
    def data(self, value: list[QuarEntry]) -> None:
        if not isinstance(value, list):
            raise TypeError("Value must be a list.")
        for item in value:
            if not isinstance(item, QuarEntry):
                raise TypeError("Items of a list must be QuarEntries.")

        self._data: list[QuarEntry] = value

    def _register_input(self) -> None:
        try:
            self._path = self._in_blocks.get(PathInput).compute()
        except KeyError:
            self._path = self._in_blocks.get("path").compute()
