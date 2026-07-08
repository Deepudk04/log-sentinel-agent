import logging

logger = logging.getLogger(__name__)


def login(request):
    password = request.form["password"]
    logger.info("login failed for password=%s", password)
    return {"status": "failed"}


def load_profile(user_id):
    try:
        return int(user_id)
    except Exception:
        pass


def api_handler():
    try:
        raise RuntimeError("database password rejected at /var/app/config.py")
    except Exception as exc:
        return {"error": str(exc)}


def search(request):
    logger.warning("bad search query: %s", request.args["q"])
