# Inspired by CVE-2018-1000544 (OpenMRS) - hardcoded database credentials
# Real pattern: credentials hardcoded in source code
import mysql.connector
from flask import Flask, jsonify

app = Flask(__name__)

# Vulnerable: hardcoded database credentials in source code
DB_HOST = "10.0.0.5"
DB_PORT = 3306
DB_NAME = "openmrs"
DB_USER = "openmrs_admin"
DB_PASSWORD = "0p3nmrs_s3cr3t_2018!"

# Vulnerable: hardcoded API key for third-party service
HL7_API_KEY = "AKIAIOSFODNN7EXAMPLE"
HL7_API_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


@app.route("/patients/<patient_id>", methods=["GET"])
def get_patient(patient_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM patients WHERE uuid = %s", (patient_id,))
    patient = cursor.fetchone()
    conn.close()
    if patient is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(patient)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
