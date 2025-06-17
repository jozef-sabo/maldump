from __future__ import annotations

import logging
import sqlite3
from datetime import datetime
from pathlib import Path

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.structures import QuarEntry

from maldump.utils import Logger as log


logger = logging.getLogger(__name__)


class KasperskyMetadataParser(Parser):
    @log.log(lgr=logger)
    def _normalize_time(self, number: int) -> datetime:
        year = (number >> 48) & 0xFFFF
        month = (number >> 40) & 0xFF
        days = (number >> 32) & 0xFF
        hours = (number >> 24) & 0xFF
        minutes = (number >> 16) & 0xFF
        seconds = (number >> 8) & 0xFF

        return datetime(year, month, days, hours, minutes, seconds)

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from log in %s", self.__class__.__name__)
        quarfiles = []

        db_file = self.path.joinpath("quarantine.db").resolve()
        try:
            logger.debug(
                'Trying to open and read from database file, path "%s"', db_file
            )
            conn = sqlite3.connect(db_file)
            logger.debug('Opening cursor to a database connection, path "%s"', db_file)
            cursor = conn.cursor()
            logger.debug(
                'Exectuting a command with a database connection, path "%s"', db_file
            )
            cursor.execute("SELECT * FROM 'objects'")
            rows = cursor.fetchall()
        except sqlite3.Error as e:
            logger.exception(
                'Cannot open nor read from a database file, path "%s"',
                db_file,
                exc_info=e,
            )
            return quarfiles

        for row in rows:
            # filename = row[0]
            # TODO:
            # malfile = self._get_malfile(filename)
            q = QuarEntry(self)
            q.timestamp = self._normalize_time(row[6])
            q.threat = row[3]
            q.path = Path(row[1] + row[2])
            q.local_path = None  # TODO: local path - self.location / data
            q.size = row[7]
            # q.malfile = malfile
            # quarfiles[filename] = q
            quarfiles.append(q)

        conn.close()

        return quarfiles
