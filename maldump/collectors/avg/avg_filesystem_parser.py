import logging

from maldump.collectors.avast_like.avast_like_filesystem_parser import (
    AvastLikeFilesystemParser,
)

logger = logging.getLogger(__name__)


class AvgFilesystemParser(AvastLikeFilesystemParser):

    def __init__(self) -> None:
        super().__init__()
        logger.debug("Initialized AVG Filesystem Parser")
