import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.parsers.kaitai.gdata_parser import GdataParser
from maldump.structures import QuarEntry
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class GdataFilesystemParser(Parser):

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.__class__.__name__)
        quarfiles = []

        for idx, metafile in enumerate(self.path.glob("*.q")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)

            kt = parse(self).kaitai(GdataParser, metafile)
            if kt is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            q = QuarEntry(self)
            q.timestamp = parse(self).timestamp(kt.data1.quatime)
            q.threat = kt.data1.malwaretype.string_content
            q.path = kt.data2.path.string_content[4:]
            q.size = kt.data2.filesize
            # TODO
            # q.malfile = kt.mal_file
            # quarfiles[str(metafile)] = q
            quarfiles.append(q)
            kt.close()

        return quarfiles
