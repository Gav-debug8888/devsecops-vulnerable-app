"""SQLite setup for the deliberately vulnerable training app.

Seeds a few demo users and notes. Passwords are stored in plain text ON PURPOSE
(see docs/vulnerabilities-found.md) - never do this in a real application.
"""
import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "vulnapp.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            account_balance REAL NOT NULL DEFAULT 0,
            secret_note TEXT
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL
        );
        """
    )
    cur.executemany(
        "INSERT INTO users (username, password, email, role, account_balance, secret_note) VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("admin", "admin-demo-pass", "admin@example.test", "admin", 99999.0, "FLAG{idor_admin_note}"),
            ("alice", "alice-demo-pass", "alice@example.test", "user", 1520.5, "Alice's private savings goal"),
            ("bob", "bob-demo-pass", "bob@example.test", "user", 310.0, "Bob's recovery codes: DEMO-ONLY"),
        ],
    )
    cur.executemany(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        [
            ("Hardware Key", "FIDO2 security key", 45.0),
            ("Password Manager", "12-month licence", 30.0),
            ("VPN", "Annual subscription", 60.0),
            ("Security Training", "Secure coding course", 199.0),
        ],
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialised at {DB_PATH}")
