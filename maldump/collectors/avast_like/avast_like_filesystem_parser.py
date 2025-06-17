import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.constants import ThreatMetadata
from maldump.structures import QuarEntry
from maldump.utils import Parser as parse
from maldump.utils import DatetimeConverter as DTC

logger = logging.getLogger(__name__)


class AvastLikeFilesystemParser(Parser):

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.__class__.__name__)
        quarfiles = []

        # iterating over bigger files, which were not logged to vault.db
        for idx, entry in enumerate(self.path.glob("*")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, entry)
            chest_id = entry.name

            if not entry.is_file():
                logger.debug("Entry (idx %s) is not a file, skipping", idx)
                continue

            if chest_id == "index.xml":
                logger.debug("Entry (idx %s) is index.xml itself, skipping", idx)
                continue

            # TODO:
            # if chest_id in data:
            #     logger.debug("Entry (idx %s) already found, skipping", idx)
            #     continue
            #
            # TODO:
            # malfile = self._getRawFromFile(chest_id)

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
            quarfiles.append(q)

        return quarfiles
