"""Submodule containing the CLI command handlers."""

import logging
import sys

from iceflix.authenticator import authenticator


LOG_FORMAT = '%(asctime)s - %(levelname)-7s - %(module)s:%(funcName)s:%(lineno)d - %(message)s'


def setup_logging():
    """Configure the logging."""
    logging.basicConfig(
        level=logging.DEBUG,
        format=LOG_FORMAT,
    )

def authentication_service():
    """Handles the `authenticationservice` CLI command."""
    setup_logging()
    logging.info("Authentication service")
    app = authenticator()
    app.main(sys.argv)
    return 0
