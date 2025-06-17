## TODO: license
from __future__ import annotations

import logging
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.extractors.extractor import Extractor
from maldump.utils import Logger as log
from maldump.structures import QuarEntry
from maldump.utils import Reader as read

logger = logging.getLogger(__name__)


class EsetExtractor(Extractor):

    @log.log(lgr=logger)
    def _decrypt(self, data: bytes) -> bytes:
        return bytes([((b - 84) % 256) ^ 0xA5 for b in data])

    @log.log(lgr=logger)
    def _get_malfile(self, path: Path) -> bytes:
        data = read.contents(path, filetype="malware")
        if data is None:
            return b""

        return self._decrypt(data)

    @BuildingBlock._comp_wrapper
    def compute(self) -> QuarEntry:
        logger.debug('Parsing entry, idx %s, path "%s"', self.quarentry.local_path)

        self.quarentry.malfile = self._get_malfile(self.quarentry.local_path)

        # quarfiles[q.sha1, user] = q

        return self.quarentry
