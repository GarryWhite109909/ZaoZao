from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient("mongodb://localhost:27017")
db = client["testdb"]


@app.route("/login_nosql", methods=["POST"])
def login_nosql():
    username = request.form.get("username")
    password = request.form.get("password")
    user = db.users.find_one({"username": username, "password": password})
    if user:
        return "Login success"
    return "Invalid", 401
