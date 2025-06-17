from __future__ import annotations

from abc import abstractmethod

from maldump.collectors.building_block import BuildingBlock
from maldump.structures import QuarEntry


class Extractor(BuildingBlock):

    @abstractmethod
    def compute(self) -> QuarEntry:
        pass

    def __init__(self) -> None:
        super().__init__()
        self._quarentry: QuarEntry | None = None

    @property
    def quarentry(self) -> QuarEntry | None:
        return self._quarentry

    @BuildingBlock.data.setter  # type: ignore [attr-defined]
    def data(self, value: QuarEntry) -> None:
        if not isinstance(value, QuarEntry):
            raise TypeError("Value must be a Quarentry.")

        self._data: QuarEntry = value

    def _register_input(self) -> None:
        try:
            self._quarentry = self._in_blocks.get(QuarEntry).compute()
        except KeyError:
            self._quarentry = self._in_blocks.get("quarantine_entry").compute()
