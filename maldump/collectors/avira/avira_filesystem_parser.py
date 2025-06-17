from __future__ import annotations
import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.structures import QuarEntry
from maldump.parsers.kaitai.avira_parser import AviraParser
from maldump.utils import Parser as parse


logger = logging.getLogger(__name__)


class AviraFilesystemParser(Parser):

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.__class__.__name__)
        quarfiles = []
        for idx, metafile in enumerate(self.path.glob("*.qua")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)

            kt = parse(self).kaitai(AviraParser, metafile)
            if kt is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            q = QuarEntry(self)
            q.timestamp = parse(self).timestamp(kt.qua_time)
            q.threat = kt.mal_type
            q.path = kt.filename[4:]
            q.local_path = metafile
            # TODO q.malfile = kt.mal_file
            quarfiles.append(q)
            kt.close()

        return quarfiles
