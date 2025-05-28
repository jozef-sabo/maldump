from __future__ import annotations

from abc import abstractmethod
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.text_input import TextInput


class PathInput(BuildingBlock):

    def __init__(self, data: Path | None = None):
        super().__init__(data)
        self._text: None | str = None

    @BuildingBlock.data.setter
    def data(self, value: Path) -> None:
        if not isinstance(value, Path):
            raise TypeError("Value must be a Path.")
        self._data: Path = value

    @property
    def path(self) -> str:
        return self._text

    def compute(self) -> Path:
        if self.data is None:
            self._register_input()
            self.data = Path(self._text)

        return self.data

    def _register_input(self) -> None:
        try:
            self._text = self._in_blocks.get(TextInput).compute()
        except KeyError:
            self._text = self._in_blocks.get("text").compute()
