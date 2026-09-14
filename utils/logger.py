import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
class _L:
    def info(self, m): logging.info(m)
    def success(self, m): logging.info("✅ " + m)
    def warning(self, m): logging.warning(m)
    def error(self, m): logging.error(m)
log = _L()
