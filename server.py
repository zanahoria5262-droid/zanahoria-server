import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, request
from flask_socketio import SocketIO, join_room

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", str(BASE_DIR / "chat.sqlite3")))
TOKEN_DAYS = 30
PBKDF2_ROUNDS = 310000

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
connected_users = {}
connected_users_lock = threading.RLock()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        yield conn
    finally:
        conn.close()


def initialize_database():
    with database() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                username_lower TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                email_lower TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS friends (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, friend_id),
                CHECK (user_id <> friend_id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_pair_id
                ON messages(sender_id, recipient_id, id);
            """
        )


initialize_database()


def normalize_username(value):
    display = unicodedata.normalize("NFKC", str(value or "").strip())
    if not re.fullmatch(r"[A-Za-z0-9_.]{3,24}", display):
        return None, None
    return display, display.casefold()


def hash_password(password, salt=None, rounds=PBKDF2_ROUNDS):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return "pbkdf2_sha256${}${}${}".format(rounds, salt.hex(), digest.hex())


def verify_password(password, encoded):
    try:
        scheme, rounds, salt_hex, expected = encoded.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(conn, user_id):
    token = secrets.token_urlsafe(40)
    expires = (datetime.now(timezone.utc) + timedelta(days=TOKEN_DAYS)).isoformat(timespec="seconds")
    conn.execute("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                 (token_digest(token), user_id, expires))
    return token


def current_user():
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token = header[7:].strip()
    if not token:
        return None
    with database() as conn:
        row = conn.execute(
            "SELECT u.id, u.username, u.email FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>?",
            (token_digest(token), utc_now()),
        ).fetchone()
    return dict(row) if row else None


def error(message, status=400, code=None):
    payload = {"error": message}
    if code:
        payload["code"] = code
    return jsonify(payload), status


def require_user():
    user = current_user()
    if not user:
        return None, error("Inicia sesión para continuar.", 401, "unauthorized")
    return user, None


def find_friend(conn, user_id, username):
    display, username_lower = normalize_username(username)
    if not display:
        return None
    return conn.execute(
        "SELECT u.id, u.username, u.email FROM users u JOIN friends f ON f.friend_id=u.id "
        "WHERE f.user_id=? AND u.username_lower=?",
        (user_id, username_lower),
    ).fetchone()


@app.get("/")
def home():
    return jsonify({"online": True, "service": "Nexo Chat", "message": "Servidor en línea"})


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username, username_lower = normalize_username(data.get("username"))
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    if not username:
        return error("El ID debe tener 3 a 24 caracteres: letras, números, punto o guion bajo.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return error("Escribe un email válido.")
    if len(password) < 8 or len(password) > 128:
        return error("La contraseña debe tener entre 8 y 128 caracteres.")
    email_lower = unicodedata.normalize("NFKC", email).casefold()
    password_hash = hash_password(password)
    conn = None
    try:
        conn = sqlite3.connect(str(DATABASE_PATH), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT id FROM users WHERE username_lower=?", (username_lower,)).fetchone()
        if existing:
            conn.rollback()
            return error("ID ya tomado", 409, "id_taken")
        existing_email = conn.execute("SELECT id FROM users WHERE email_lower=?", (email_lower,)).fetchone()
        if existing_email:
            conn.rollback()
            return error("Ese email ya está registrado.", 409, "email_taken")
        cursor = conn.execute(
            "INSERT INTO users(username, username_lower, email, email_lower, password_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, username_lower, email, email_lower, password_hash, utc_now()),
        )
        token = create_session(conn, cursor.lastrowid)
        conn.commit()
        return jsonify({"token": token, "user": {"id": cursor.lastrowid, "username": username, "email": email}}), 201
    except sqlite3.IntegrityError as exc:
        if conn:
            conn.rollback()
        with database() as check_conn:
            if check_conn.execute("SELECT 1 FROM users WHERE username_lower=?", (username_lower,)).fetchone():
                return error("ID ya tomado", 409, "id_taken")
            if check_conn.execute("SELECT 1 FROM users WHERE email_lower=?", (email_lower,)).fetchone():
                return error("Ese email ya está registrado.", 409, "email_taken")
        return error("No se pudo crear la cuenta.", 409, "duplicate")
    except sqlite3.OperationalError:
        if conn:
            conn.rollback()
        return error("Base de datos ocupada; intenta de nuevo.", 503, "database_busy")
    finally:
        if conn:
            conn.close()


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    email_lower = unicodedata.normalize("NFKC", email).casefold()
    with database() as conn:
        row = conn.execute("SELECT * FROM users WHERE email_lower=?", (email_lower,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return error("Email o contraseña incorrectos.", 401, "bad_login")
        conn.execute("BEGIN IMMEDIATE")
        token = create_session(conn, row["id"])
        conn.commit()
        return jsonify({"token": token, "user": {"id": row["id"], "username": row["username"], "email": row["email"]}})


@app.post("/api/logout")
def logout():
    user, failure = require_user()
    if failure:
        return failure
    token = request.headers.get("Authorization", "")[7:].strip()
    with database() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(token),))
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    user, failure = require_user()
    if failure:
        return failure
    return jsonify({"user": user})


@app.get("/api/search/<username>")
def search_user(username):
    user, failure = require_user()
    if failure:
        return failure
    display, username_lower = normalize_username(username)
    if not display:
        return error("Escribe el ID exacto, de 3 a 24 caracteres.")
    with database() as conn:
        row = conn.execute("SELECT id, username FROM users WHERE username_lower=?", (username_lower,)).fetchone()
    if not row:
        return error("No existe ese ID.", 404, "not_found")
    if row["id"] == user["id"]:
        return error("Ese es tu propio ID.", 400, "self")
    return jsonify({"user": {"id": row["id"], "username": row["username"]}})


@app.post("/api/friends/add")
def add_friend():
    user, failure = require_user()
    if failure:
        return failure
    data = request.get_json(silent=True) or {}
    display, username_lower = normalize_username(data.get("username"))
    if not display:
        return error("ID no válido.")
    conn = None
    try:
        conn = sqlite3.connect(str(DATABASE_PATH), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("BEGIN IMMEDIATE")
        friend = conn.execute("SELECT id, username FROM users WHERE username_lower=?", (username_lower,)).fetchone()
        if not friend:
            conn.rollback()
            return error("No existe ese ID.", 404, "not_found")
        if friend["id"] == user["id"]:
            conn.rollback()
            return error("No puedes agregarte a ti mismo.")
        now = utc_now()
        conn.execute("INSERT OR IGNORE INTO friends(user_id, friend_id, created_at) VALUES (?, ?, ?)",
                     (user["id"], friend["id"], now))
        conn.execute("INSERT OR IGNORE INTO friends(user_id, friend_id, created_at) VALUES (?, ?, ?)",
                     (friend["id"], user["id"], now))
        conn.commit()
        return jsonify({"ok": True, "friend": {"id": friend["id"], "username": friend["username"]}})
    except sqlite3.OperationalError:
        if conn:
            conn.rollback()
        return error("Base de datos ocupada; intenta de nuevo.", 503)
    finally:
        if conn:
            conn.close()


@app.get("/api/friends")
def list_friends():
    user, failure = require_user()
    if failure:
        return failure
    with database() as conn:
        rows = conn.execute(
            "SELECT u.id, u.username FROM friends f JOIN users u ON u.id=f.friend_id "
            "WHERE f.user_id=? ORDER BY u.username_lower", (user["id"],)
        ).fetchall()
    return jsonify({"friends": [dict(row) for row in rows]})


@app.get("/api/messages/<username>")
def get_messages(username):
    user, failure = require_user()
    if failure:
        return failure
    try:
        after_id = max(0, int(request.args.get("after_id", "0")))
    except ValueError:
        return error("after_id no válido.")
    with database() as conn:
        friend = find_friend(conn, user["id"], username)
        if not friend:
            return error("Agrega a esa persona antes de chatear.", 403, "not_friends")
        rows = conn.execute(
            "SELECT m.id, a.username AS sender, b.username AS recipient, m.body, m.created_at "
            "FROM messages m JOIN users a ON a.id=m.sender_id JOIN users b ON b.id=m.recipient_id "
            "WHERE m.id>? AND ((m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?)) "
            "ORDER BY m.id LIMIT 300",
            (after_id, user["id"], friend["id"], friend["id"], user["id"]),
        ).fetchall()
    return jsonify({"messages": [dict(row) for row in rows]})


@app.post("/api/messages")
def send_message():
    user, failure = require_user()
    if failure:
        return failure
    data = request.get_json(silent=True) or {}
    to_username = str(data.get("to_username", ""))
    body = str(data.get("body", "")).strip()
    if not body or len(body) > 4000:
        return error("El mensaje debe tener entre 1 y 4000 caracteres.")
    conn = None
    try:
        conn = sqlite3.connect(str(DATABASE_PATH), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("BEGIN IMMEDIATE")
        friend = find_friend(conn, user["id"], to_username)
        if not friend:
            conn.rollback()
            return error("Agrega a esa persona antes de chatear.", 403, "not_friends")
        cursor = conn.execute(
            "INSERT INTO messages(sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], friend["id"], body, utc_now()),
        )
        row = conn.execute(
            "SELECT m.id, a.username AS sender, b.username AS recipient, m.body, m.created_at "
            "FROM messages m JOIN users a ON a.id=m.sender_id JOIN users b ON b.id=m.recipient_id WHERE m.id=?",
            (cursor.lastrowid,),
        ).fetchone()
        conn.commit()
        message = dict(row)
        payload = {"message": message}
        socketio.emit("new_message", payload, room="user_{}".format(user["id"]))
        socketio.emit("new_message", payload, room="user_{}".format(friend["id"]))
        return jsonify({"message": message}), 201
    except sqlite3.OperationalError:
        if conn:
            conn.rollback()
        return error("Base de datos ocupada; intenta de nuevo.", 503)
    finally:
        if conn:
            conn.close()


@socketio.on("connect")
def socket_connect(auth):
    auth = auth or {}
    token = str(auth.get("token", ""))
    with database() as conn:
        row = conn.execute(
            "SELECT u.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
            (token_digest(token), utc_now()),
        ).fetchone()
    if not row:
        return False
    user_id = int(row["id"])
    from flask import request as flask_request
    join_room("user_{}".format(user_id))
    with connected_users_lock:
        connected_users[flask_request.sid] = user_id
    return True


@socketio.on("disconnect")
def socket_disconnect(reason=None):
    from flask import request as flask_request
    with connected_users_lock:
        connected_users.pop(flask_request.sid, None)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)
