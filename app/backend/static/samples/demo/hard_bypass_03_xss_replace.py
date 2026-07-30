from flask import Flask, request

app = Flask(__name__)


@app.route("/comment")
def comment():
    text = request.args.get("text", "")
    text = text.replace("<script>", "").replace("</script>", "")
    return f"<html><body><p>{text}</p></body></html>"
