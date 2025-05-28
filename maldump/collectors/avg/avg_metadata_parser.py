import logging
from pathlib import Path

from maldump.collectors.avast_like.avast_like_metadata_parser import (
    AvastLikeMetadataParser,
)

logger = logging.getLogger(__name__)


class AvgMetadataParser(AvastLikeMetadataParser):

    vault_folder: Path = Path("$AV_AVG")

    def __init__(self) -> None:
        super().__init__()
        logger.debug("Initialized AVG Parser")
