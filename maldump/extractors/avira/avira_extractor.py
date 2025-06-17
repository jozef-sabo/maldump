from __future__ import annotations
import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.extractors.extractor import Extractor
from maldump.structures import QuarEntry
from maldump.parsers.kaitai.avira_parser import AviraParser
from maldump.utils import Parser as parse


logger = logging.getLogger(__name__)


class AviraExtractor(Extractor):

    @BuildingBlock._comp_wrapper
    def compute(self) -> QuarEntry:
        logger.debug('Parsing entry, path "%s"', self.quarentry.local_path)

        kt = parse(self).kaitai(AviraParser, self.quarentry.local_path)
        if kt is None:
            logger.debug('Skipping entry, path "%s"', self.quarentry.local_path)
            return self.quarentry

        self.quarentry.malfile = kt.mal_file
        kt.close()

        return self.quarentry
