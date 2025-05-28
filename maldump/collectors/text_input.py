from __future__ import annotations

from maldump.collectors.building_block import BuildingBlock, T


class TextInput(BuildingBlock):
    @BuildingBlock.data.setter
    def data(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Value must be a string.")
        self._data: str = value

    @BuildingBlock._comp_wrapper
    def compute(self) -> str:
        return self.data

    def _register_input(self) -> None:
        if len(self._in_blocks) != 0:
            raise ValueError("Text input cannot have any input blocks.")
