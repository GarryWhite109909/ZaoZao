# Pattern reference: CVE-2019-12419 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:SQL injection in loan schedule
# Real pattern: user-controlled path param concatenated into SQL query
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
db = sqlite3.connect("fineract.db", check_same_thread=False)


@app.route("/loans/<loan_id>/charges/<charge_id>", methods=["GET"])
def get_loan_charge(loan_id, charge_id):
    """Get a specific charge applied to a loan."""
    # Vulnerable: charge_id from path directly concatenated into SQL
    query = "SELECT id, loan_id, charge_id, amount, due_date FROM loan_charges " \
            "WHERE loan_id = %s AND charge_id = %s" % (loan_id, charge_id)
    cursor = db.cursor()
    cursor.execute(query)
    row = cursor.fetchone()
    if row is None:
        return jsonify({"error": "charge not found"}), 404
    return jsonify({
        "id": row[0],
        "loan_id": row[1],
        "charge_id": row[2],
        "amount": float(row[3]),
        "due_date": str(row[4]),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
