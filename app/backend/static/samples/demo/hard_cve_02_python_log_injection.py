import logging
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/login")
def login():
    username = request.args.get("username", "")
    logger.info(f"Login attempt from user: {username}")
    return "Login processed"
