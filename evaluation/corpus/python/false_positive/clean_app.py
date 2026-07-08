import logging

logger = logging.getLogger(__name__)


def login_failed(username: str) -> dict[str, str]:
    logger.warning("login failed", extra={"username": username})
    return {"error": "request failed"}
