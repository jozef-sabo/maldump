from __future__ import annotations

from abc import abstractmethod
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.path_input import PathInput
from maldump.filters.filter import Filter
from maldump.structures import QuarEntry


class GenricFilter(Filter):

    def compute(self) -> list[QuarEntry]:

        entries = {entry.id: entry for entry in self.quarentries}

        return list(entries.values())
