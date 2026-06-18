"""Acceso a datos de la app de notas.

RAMA `vulnerable`: contiene vulnerabilidades intencionales con fines educativos.
Cada una está marcada con un bloque [VULN]. La rama `secure` las corrige.
"""
import sqlite3
import hashlib

DB_PATH = "notes.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ──────────────────────────────────────────────────────────────────────────
# [VULN] A02:2021 – Cryptographic Failures
#   Hash de contraseñas con MD5: rápido, sin sal y criptográficamente roto.
#   Detectado por: Bandit (B303/B324), Semgrep
#   Fix en `secure`: bcrypt o argon2 con sal por usuario.
# ──────────────────────────────────────────────────────────────────────────
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS notes")
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)"
    )
    cur.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "owner TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL)"
    )
    for u, p in [("alice", "alice123"), ("bob", "bob123")]:
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (u, hash_password(p)),
        )
    seed_notes = [
        ("alice", "Bienvenida", "Esta es mi primera nota privada."),
        ("alice", "Lista de compras", "Pan, leche, café."),
        ("bob", "Secreto de Bob", "Nota privada de Bob que Alice no debería ver."),
    ]
    for owner, title, body in seed_notes:
        cur.execute(
            "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
            (owner, title, body),
        )
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────────────────────────────────
# [VULN] A03:2021 – Injection (SQL Injection)
#   La consulta se construye concatenando la entrada del usuario.
#   PoC: en el usuario, escribir   ' OR '1'='1' --   evade la autenticación.
#   Detectado por: Bandit (B608), Semgrep, DAST (OWASP ZAP)
#   Fix en `secure`: consultas parametrizadas (placeholders ?).
# ──────────────────────────────────────────────────────────────────────────
def verify_user(username, password):
    conn = get_conn()
    cur = conn.cursor()
    pw = hash_password(password)
    query = (
        "SELECT username FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + pw
        + "'"
    )
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row["username"] if row else None


def get_user_notes(owner):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, title, body FROM notes WHERE owner = ?", (owner,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_note(note_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, owner, title, body FROM notes WHERE id = ?", (note_id,))
    row = cur.fetchone()
    conn.close()
    return row


def add_note(owner, title, body):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
        (owner, title, body),
    )
    conn.commit()
    conn.close()
