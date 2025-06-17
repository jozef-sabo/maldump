from __future__ import annotations

import logging
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.parsers.kaitai.windef_entries import WindefEntries as KaitaiParserEntries
from maldump.structures import QuarEntry
from maldump.utils import Logger as log
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class WindefMetadataParser(Parser):
    ##TODO: forticlient the same?
    @log.log(lgr=logger)
    def _normalize(self, path_chrs) -> str:
        path_str = "".join(map(chr, path_chrs[:-1]))
        if path_str[2:4] == "?\\":
            path_str = path_str[4:]
        return path_str

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from log in %s", self.__class__.__name__)
        quarfiles = []

        for idx, metafile in enumerate(self.path.glob("Entries/{*}")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)
            kt = parse(self).kaitai(KaitaiParserEntries, metafile)
            if kt is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            ts = parse(self).timestamp(kt.data1.time.unixts)

            # Loop through all entries, if they exist
            for idx_e, e in enumerate(kt.data2.entries):
                logger.debug("Parsing entry inside metadata file, idx_e %s", idx_e)
                # Support only 'file' type for now
                if e.entry.typestr != "file":
                    logger.debug("Entry (idx_e %s) is not a file, skipping", idx_e)
                    continue

                guid = e.entry.element[0].content.value.hex().upper()
                # malfile = self._get_malfile(guid)
                q = QuarEntry(self)
                q.timestamp = ts
                q.threat = kt.data1.mal_type
                q.path = Path(self._normalize(e.entry.path.character))
                q.local_path = None  # TODO: local path - self.location / "ResourceData" / guid[:2] / guid
                # q.malfile = malfile
                quarfiles[guid] = q

            kt.close()

        return quarfiles
