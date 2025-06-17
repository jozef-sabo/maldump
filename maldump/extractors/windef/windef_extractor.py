import logging
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.extractors.extractor import Extractor
from maldump.parsers.kaitai.windef_resource_data import (
    WindefResourceData as KaitaiParserResourceData,
)
from maldump.structures import QuarEntry
from maldump.utils import Logger as log
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class WindefExtractor(Extractor):

    @log.log(lgr=logger)
    def _get_metadata(self, path: Path):

        kt = parse(self).kaitai(KaitaiParserResourceData, path)
        if kt is not None:
            kt.close()

        return kt

    @log.log(lgr=logger)
    def _get_malfile(self, path: Path) -> bytes:
        kt = self._get_metadata(path)
        if kt is None:
            return b""
        return kt.encryptedfile.mal_file

    @BuildingBlock._comp_wrapper
    def compute(self) -> QuarEntry:
        logger.debug('Parsing entry, idx %s, path "%s"', self.quarentry.local_path)

        # TODO: filters
        # if guid in data:
        #     logger.debug("Entry (idx %s) already found, skipping", idx)
        #     continue

        malfile = self._get_malfile(self.quarentry.local_path)

        if malfile is None:
            logger.debug('Skipping entry, path "%s"', self.quarentry.local_path)
            return self.quarentry

        self.quarentry.malfile = malfile

        # TODO:
        # quarfiles[guid] = q

        return self.quarentry
