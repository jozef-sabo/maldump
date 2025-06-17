from datetime import datetime
import logging
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.structures import QuarEntry
from maldump.utils import Parser as parse
from maldump.utils import Logger as log
from maldump.parsers.kaitai.forticlient_parser import ForticlientParser

logger = logging.getLogger(__name__)


class ForticlientFilesystemParser(Parser):

    @log.log(lgr=logger)
    def _normalize_path(self, path: str) -> str:
        if path[2:4] == "?\\":
            path = path[4:]
        return path

    @log.log(lgr=logger)
    def _get_time(self, ts: ForticlientParser.Timestamp):
        return datetime(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second)

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from log in %s", self.__class__.__name__)
        quarfiles = []

        for idx, metafile in enumerate(self.path.glob("*[!.meta]")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)

            kt = parse(self).kaitai(ForticlientParser, metafile)
            if kt is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            q = QuarEntry(self)
            q.timestamp = self._get_time(kt.timestamp)
            q.threat = kt.mal_type
            q.path = Path(self._normalize_path(kt.mal_path))
            q.local_path = metafile
            q.size = kt.mal_len
            # TODO
            # q.malfile = kt.mal_file
            # quarfiles[str(metafile)] = q
            quarfiles.append(q)
            kt.close()

        return quarfiles
