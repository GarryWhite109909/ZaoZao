from flask import Flask, request
import ldap

app = Flask(__name__)


@app.route("/login_ldap_safe")
def login_ldap_safe():
    username = request.args.get("username", "")
    filter_str = "(uid=%s)"
    conn = ldap.initialize("ldap://localhost:389")
    # ldap 模块支持参数化查询
    result = conn.search_s(
        "dc=example,dc=com",
        ldap.SCOPE_SUBTREE,
        filter_str,
        [username],
    )
    return str(result)
