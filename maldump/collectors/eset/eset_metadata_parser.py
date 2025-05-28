import logging
from typing import Any

from maldump.collectors.building_block import BuildingBlock
from maldump.collectors.parser import Parser
from maldump.structures import QuarEntry
from maldump.parsers.kaitai.eset_virlog_parser import EsetVirlogParser
from maldump.utils import Logger as log
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class EsetMetadataParser(Parser):

    @log.log(lgr=logger)
    def _parse_record(self, record: dict) -> dict[str, Any]:
        return {
            "timestamp": record.get("timestamp"),
            "virusdb": (
                record.get("virus_db").str
                if record.get("virus_db") is not None
                else None
            ),
            "obj": (
                record.get("object_name").str
                if record.get("object_name") is not None
                else None
            ),
            "objhash": (
                record.get("object_hash").hash.hex()
                if record.get("object_hash") is not None
                else None
            ),
            "infiltration": (
                record.get("infiltration_name").str
                if record.get("infiltration_name") is not None
                else None
            ),
            "user": (
                record.get("user_name").str.split("\\")[1]
                if record.get("user_name") is not None
                else None
            ),
            "progname": (
                record.get("program_name").str
                if record.get("program_name") is not None
                else None
            ),
            "proghash": (
                record.get("program_hash").hash.hex()
                if record.get("program_hash") is not None
                else None
            ),
            "firstseen": record.get("firstseen"),
        }

    @log.log(lgr=logger)
    def _convert_to_dict(self, parser: EsetVirlogParser) -> list:
        return [
            {
                **{
                    y.name.name: y.arg if hasattr(y, "arg") else None
                    for y in x.record.data_fields
                },
                "timestamp": x.record.win_timestamp.date_time,
            }
            for x in parser.threats
        ]

    @log.log(lgr=logger)
    def _main_parsing(self, virlog_path) -> list[dict]:
        kt = parse(self).kaitai(EsetVirlogParser, virlog_path)
        if kt is None:
            logger.warning("Skipping virlog.dat parsing")
            return []
        kt.close()

        threats = self._convert_to_dict(kt)

        parsed_records = []
        for idx, record in enumerate(threats):
            logger.debug("Parsing raw record %s/%s", idx + 1, len(threats))
            parsed_records.append(self._parse_record(record))

        return [self._parse_record(record) for record in threats]

    @BuildingBlock._comp_wrapper
    def compute(self) -> list[QuarEntry]:
        logger.info("Parsing from log in %s", self.__class__.__name__)
        quarfiles = []

        for idx, metadata in enumerate(self._main_parsing(self.path)):
            logger.debug("Parsing entry, idx %s", idx)
            if metadata["user"] == "SYSTEM":
                logger.debug("Entry's (idx %s) user is SYSTEM, skipping", idx)
                continue
            q = QuarEntry(self)
            q.timestamp = metadata["timestamp"]
            q.threat = metadata["infiltration"]
            q.path = metadata["obj"]
            # q.malfile = self._get_malfile(metadata["user"], metadata["objhash"])
            if (q.sha1, metadata["user"]) in quarfiles:
                logger.debug("Entry (idx %s) already found, skipping", idx)
            # quarfiles[q.sha1, metadata["user"]] = q
            quarfiles.append(q)

        return quarfiles
