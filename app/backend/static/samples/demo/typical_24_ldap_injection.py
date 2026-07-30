from flask import Flask, request
import ldap

app = Flask(__name__)


@app.route("/login_ldap")
def login_ldap():
    username = request.args.get("username", "")
    filter_str = f"(uid={username})"
    conn = ldap.initialize("ldap://localhost:389")
    result = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
    return str(result)
