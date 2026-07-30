from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/login_xpath")
def login_xpath():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    xpath = f"//user[username='{username}' and password='{password}']"
    tree = etree.parse("users.xml")
    result = tree.xpath(xpath)
    if result:
        return "Login success"
    return "Invalid", 401
