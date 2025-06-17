from __future__ import annotations

import logging

from maldump.collectors.building_block import BuildingBlock
from maldump.extractors.extractor import Extractor
from maldump.structures import QuarEntry
from maldump.utils import Logger as log
from maldump.utils import Reader as read
from maldump.utils import xor


logger = logging.getLogger(__name__)


class KasperskyExtractor(Extractor):

    @log.log(lgr=logger)
    def _get_malfile(self, file) -> bytes:
        key = bytes([0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC])

        data = read.contents(file, filetype="malware")
        if data is None:
            return b""
        return xor(data, key)

    @BuildingBlock._comp_wrapper
    def compute(self) -> QuarEntry:
        logger.debug('Parsing entry, path "%s"', self.quarentry)

        # TODO:
        # filename = entry.name
        # filename = entry.name
        #
        # if filename in data:
        #     logger.debug("Entry (idx %s) already found, skipping", idx)
        #     continue

        malfile = self._get_malfile(self.quarentry.local_path)

        self.quarentry.malfile = malfile
        # quarfiles[filename] = q

        return self.quarentry
