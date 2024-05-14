import logging
import os

def logger():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    print("LOGGER", logger)
    return logger
