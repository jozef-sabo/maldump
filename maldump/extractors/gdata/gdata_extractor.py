import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.extractors.extractor import Extractor
from maldump.parsers.kaitai.gdata_parser import GdataParser
from maldump.structures import QuarEntry
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class GdataExtractor(Extractor):

    @BuildingBlock._comp_wrapper
    def compute(self) -> QuarEntry:
        logger.debug('Parsing entry, path "%s"', self.quarentry.local_path)

        kt = parse(self).kaitai(GdataParser, self.quarentry.local_path)
        if kt is None:
            logger.debug('Skipping entry, path "%s"', self.quarentry.local_path)
            return self.quarentry

        self.quarentry.malfile = kt.mal_file
        # TODO
        # quarfiles[str(metafile)] = q
        kt.close()

        return self.quarentry
