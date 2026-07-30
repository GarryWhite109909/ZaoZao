import sqlite3

name = "admin"
query = "SELECT * FROM users WHERE name = '" + name + "'"
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute(query)
print(cursor.fetchone())
