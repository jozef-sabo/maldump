## TODO: license
from __future__ import annotations

import logging
import re
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.parsers.kaitai.eset_ndf_parser import EsetNdfParser as KaitaiParserMetadata
from maldump.utils import DatetimeConverter as DTC
from maldump.utils import Logger as log
from maldump.utils import Parser as parse
from maldump.constants import ThreatMetadata
from maldump.structures import QuarEntry

logger = logging.getLogger(__name__)


class EsetFilesystemParser(Parser):
    # Quarantine folder per user
    quarpath = "Users/{username}/AppData/Local/ESET/ESET Security/Quarantine/"
    regex_user = re.compile(
        r"Users[/\\]([^/\\]*)[/\\]AppData[/\\]Local[/\\]ESET[/\\]ESET Security[/\\]Quarantine[/\\]"  # noqa: E501
    )
    regex_entry = re.compile(r"([0-9a-fA-F]+)\.NQF$")

    @log.log(lgr=logger)
    def _get_metadata(self, path: Path, objhash: str) -> KaitaiParserMetadata | None:
        # metadata file has .NDF extension
        metadata_path = path / (objhash + ".NDF")
        if not metadata_path.is_file():
            logger.debug("Metadata file not found")
            return None

        kt = parse(self).kaitai(KaitaiParserMetadata, metadata_path)
        if kt is None:
            return None

        kt.close()
        return kt

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.__class__.__name__)
        quarfiles = []

        actual_path = Path("Users/")
        for idx, entry in enumerate(
            actual_path.glob("*/AppData/Local/ESET/ESET Security/Quarantine/*.NQF")
        ):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, entry)
            res_path = re.match(self.regex_entry, entry.name)
            res_user = re.match(self.regex_user, str(entry))

            if not res_path:
                logger.debug(
                    "Entry's (idx %s) filename of incorrect format, skipping", idx
                )
                continue

            user = res_user.group(1)
            objhash = res_path.group(1)

            # if (objhash.lower(), user) in data:
            #     logger.debug("Entry (idx %s) already found, skipping", idx)
            #     continue

            entry_stat = parse(self).entry_stat(entry)
            if entry_stat is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, entry)
                continue
            timestamp = DTC.get_dt_from_stat(entry_stat)
            path = entry
            sha1 = None
            size = entry_stat.st_size
            threat = ThreatMetadata.UNKNOWN_THREAT

            kt = self._get_metadata(entry.parent, objhash)
            if kt is not None:
                timestamp = kt.datetime_unix.date_time
                path = Path(kt.findings[0].mal_path.str)
                sha1 = hex(int.from_bytes(kt.mal_hash_sha1, "big")).lstrip("0x")
                size = kt.mal_size
                threat = kt.findings[0].threat_canonized.str

            q = QuarEntry(self)
            q.timestamp = timestamp
            q.path = path
            q.local_path = entry
            q.sha1 = sha1
            q.size = size
            q.threat = threat
            # q.malfile = self._get_malfile(user, objhash)

            quarfiles.append(q)
            # quarfiles[q.sha1, user] = q

        return quarfiles
