from __future__ import annotations

import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.constants import ThreatMetadata
from maldump.structures import QuarEntry
from maldump.utils import DatetimeConverter as DTC
from maldump.utils import Parser as parse


logger = logging.getLogger(__name__)


class KasperskyFilesystemParser(Parser):

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.__class__.__name__)
        quarfiles = []

        for idx, entry in enumerate(self.path.glob("{*}")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, entry)
            if not entry.is_file():
                logger.debug("Entry (idx %s) is not a file, skipping", idx)
                continue

            # TODO:
            # filename = entry.name
            # filename = entry.name
            #
            # if filename in data:
            #     logger.debug("Entry (idx %s) already found, skipping", idx)
            #     continue

            # malfile = self._get_malfile(filename)

            entry_stat = parse(self).entry_stat(entry)
            if entry_stat is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, entry)
                continue
            timestamp = DTC.get_dt_from_stat(entry_stat)
            size = entry_stat.st_size

            q = QuarEntry(self)
            q.path = entry
            q.local_path = entry
            q.timestamp = timestamp
            q.size = size
            q.threat = ThreatMetadata.UNKNOWN_THREAT
            # q.malfile = malfile
            # quarfiles[filename] = q
            quarfiles.append(q)

        return quarfiles
