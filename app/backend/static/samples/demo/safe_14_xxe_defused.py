from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse_xml_safe", methods=["POST"])
def parse_xml_safe():
    raw = request.get_data()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
    )
    root = etree.fromstring(raw, parser=parser)
    return etree.tostring(root, encoding="unicode")
