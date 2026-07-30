from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/admin/export_all_users")
def export_all_users():
    if "user_id" not in session:
        return "Please login", 401
    return "Exporting all users data..."
