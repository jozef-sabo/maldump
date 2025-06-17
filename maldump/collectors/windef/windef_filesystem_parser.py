import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.constants import ThreatMetadata
from maldump.parsers.kaitai.windef_resource_data import (
    WindefResourceData as KaitaiParserResourceData,
)
from maldump.structures import QuarEntry
from maldump.utils import DatetimeConverter as DTC
from maldump.utils import Logger as log
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class WindefFilesystemParser(Parser):

    @log.log(lgr=logger)
    def _get_metadata(self, guid: str):
        quarfile = self.path / "ResourceData" / guid[:2] / guid

        kt = parse(self).kaitai(KaitaiParserResourceData, quarfile)
        if kt is not None:
            kt.close()

        return kt

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.__class__.__name__)
        quarfiles = []

        # if the metadata are lost, but we still have access to data themselves
        for idx, entry in enumerate(self.path.glob("ResourceData/*/*")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, entry)
            if not entry.is_file():
                logger.debug("Entry (idx %s) is not a file, skipping", idx)
                continue

            guid = entry.name

            # if guid in data:
            #     logger.debug("Entry (idx %s) already found, skipping", idx)
            #     continue

            entry_stat = parse(self).entry_stat(entry)
            if entry_stat is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, entry)
                continue
            timestamp = DTC.get_dt_from_stat(entry_stat)

            # malfile = self._get_malfile(guid)
            kt_data = self._get_metadata(guid)

            # if malfile is None:
            #     logger.debug('Skipping entry idx %s, path "%s"', idx, entry)
            #     continue

            q = QuarEntry(self)
            q.path = entry
            q.local_path = entry  # TODO: local path - self.location / "ResourceData" / guid[:2] / guid
            q.timestamp = timestamp
            q.size = kt_data.encryptedfile.len_malfile
            q.threat = ThreatMetadata.UNKNOWN_THREAT
            # q.malfile = malfile

            quarfiles.append(q)
            # quarfiles[guid] = q

        return quarfiles
