import logging
import sys

# Create custom logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Remove any default handlers
if logger.hasHandlers():
    logger.handlers.clear()

# Create handler for console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)

# Create formatter with filename and line number
formatter = logging.Formatter(
    '[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Add formatter to handler
console_handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(console_handler)

# Test logs
# logging.debug("Debug log")
# logging.info("Info log")
# logging.warning("Warning log")
# logging.error("Error log")

def is_level_debug():
    return logging.getLevelName(logging.getLogger().getEffectiveLevel()) == "DEBUG"

# print(is_level_debug())