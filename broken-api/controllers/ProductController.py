import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database.db"

class ProductController:
    @staticmethod
    def initialize_database():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)"
        )
        cursor.execute("SELECT COUNT(*) FROM products")
        if cursor.fetchone()[0] == 0:
            cursor.executemany(
                "INSERT INTO products (name, price) VALUES (?, ?)",
                [
                    ("Laptop", 1500.0),
                    ("Mouse", 25.0),
                    ("Keyboard", 75.0),
                ],
            )
            conn.commit()
        conn.close()

    @staticmethod
    def get_products():
        # API4:2023 - Unrestricted Resource Consumption
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        conn.close()
        return products
