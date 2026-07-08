import logging

logger = logging.getLogger(__name__)


def login(username: str, password: str) -> None:
    logger.info("login failed username=%s password=%s", username, password)


def handler() -> dict[str, str]:
    try:
        raise RuntimeError("database password leaked")
    except RuntimeError as exc:
        return {"error": str(exc)}
