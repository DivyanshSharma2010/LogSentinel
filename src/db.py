import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv(override=True)

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
    )

conn = get_connection()
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        marks INT NOT NULL
    )
""")

cursor.execute(
    "INSERT INTO students (name, marks) VALUES (%s, %s)",
    ("Aman", 88),
)
cursor.execute(
    "INSERT INTO students (name, marks) VALUES (%s, %s)",
    ("Riya", 91),
)

conn.commit()
cursor.close()
conn.close()
