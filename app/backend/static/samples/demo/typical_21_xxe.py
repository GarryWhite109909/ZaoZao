from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    raw = request.get_data()
    parser = etree.XMLParser()
    root = etree.fromstring(raw, parser=parser)
    return etree.tostring(root, encoding="unicode")
