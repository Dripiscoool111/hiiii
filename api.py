import os
import secrets
import string
import sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app    = Flask(__name__)
DB     = "keys.db"
MASTER = os.getenv("API_MASTER_KEY", "William@2013")

# ─── Database ─────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key         TEXT PRIMARY KEY,
                created_at  TEXT NOT NULL,
                expires_at  TEXT,
                revoked     INTEGER NOT NULL DEFAULT 0,
                hwid        TEXT,
                note        TEXT,
                max_uses    INTEGER,
                use_count   INTEGER NOT NULL DEFAULT 0
            )
        """)
        try:
            conn.execute("ALTER TABLE keys ADD COLUMN max_uses INTEGER")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE keys ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass
        conn.commit()


init_db()

# ─── Auth middleware ──────────────────────────────────────────────────────────

def require_master(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if token != MASTER:
            return jsonify({"success": False, "message": "Unauthorized."}), 401
        return f(*args, **kwargs)
    return wrapper


# ─── Key helpers ─────────────────────────────────────────────────────────────

def gen_key() -> str:
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(6)) for _ in range(4)]
    return "-".join(parts)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.post("/keys/generate")
@require_master
def generate_key():
    body       = request.get_json(silent=True) or {}
    days       = body.get("expires_in_days")
    max_uses   = body.get("max_uses")
    note       = body.get("note", "")
    key        = gen_key()
    created_at = now_iso()
    expires_at = None

    if days is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=int(days))).isoformat()
    if max_uses is not None:
        max_uses = int(max_uses)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO keys (key, created_at, expires_at, note, max_uses, use_count) VALUES (?,?,?,?,?,0)",
            (key, created_at, expires_at, note, max_uses),
        )
        conn.commit()

    return jsonify({
        "success":    True,
        "key":        key,
        "created_at": created_at,
        "expires_at": expires_at,
        "max_uses":   max_uses,
        "note":       note,
    })


@app.get("/keys/validate")
def validate_key():
    key  = request.args.get("key", "").strip().upper()
    hwid = request.args.get("hwid", "").strip()

    if not key:
        return jsonify({"success": False, "message": "No key provided."}), 400

    with get_db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE key = ?", (key,)).fetchone()

        if not row:
            return jsonify({"success": False, "message": "Invalid key."})
        if row["revoked"]:
            return jsonify({"success": False, "message": "This key has been revoked."})
        if row["expires_at"]:
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > expires:
                return jsonify({"success": False, "message": "This key has expired."})
        if row["max_uses"] is not None and row["use_count"] >= row["max_uses"]:
            return jsonify({"success": False, "message": f"This key has reached its maximum uses ({row['max_uses']})."})

        if row["hwid"] is None and hwid:
            conn.execute("UPDATE keys SET hwid = ?, use_count = use_count + 1 WHERE key = ?", (hwid, key))
        elif row["hwid"] and hwid and row["hwid"] != hwid:
            return jsonify({"success": False, "message": "HWID mismatch. Key is locked to another device."})
        else:
            conn.execute("UPDATE keys SET use_count = use_count + 1 WHERE key = ?", (key,))
        conn.commit()

        row = conn.execute("SELECT * FROM keys WHERE key = ?", (key,)).fetchone()

    uses_left = (row["max_uses"] - row["use_count"]) if row["max_uses"] is not None else None
    return jsonify({
        "success":   True,
        "message":   "Key is valid.",
        "uses_left": uses_left,
    })


@app.post("/keys/revoke")
@require_master
def revoke_key():
    body = request.get_json(silent=True) or {}
    key  = body.get("key", "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "No key provided."}), 400
    with get_db() as conn:
        cur = conn.execute("UPDATE keys SET revoked = 1 WHERE key = ?", (key,))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"success": False, "message": "Key not found."})
    return jsonify({"success": True, "message": f"Key {key} revoked."})


@app.post("/keys/reset-hwid")
@require_master
def reset_hwid():
    body = request.get_json(silent=True) or {}
    key  = body.get("key", "").strip().upper()
    with get_db() as conn:
        cur = conn.execute("UPDATE keys SET hwid = NULL WHERE key = ?", (key,))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"success": False, "message": "Key not found."})
    return jsonify({"success": True, "message": "HWID reset."})


@app.get("/keys/info")
@require_master
def key_info():
    key = request.args.get("key", "").strip().upper()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE key = ?", (key,)).fetchone()
    if not row:
        return jsonify({"success": False, "message": "Key not found."})
    return jsonify({"success": True, **dict(row)})


@app.get("/keys/list")
@require_master
def list_keys():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    return jsonify({"success": True, "keys": [dict(r) for r in rows]})


@app.delete("/keys/delete")
@require_master
def delete_key():
    body = request.get_json(silent=True) or {}
    key  = body.get("key", "").strip().upper()
    with get_db() as conn:
        cur = conn.execute("DELETE FROM keys WHERE key = ?", (key,))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"success": False, "message": "Key not found."})
    return jsonify({"success": True, "message": f"Key {key} deleted."})


if __name__ == "__main__":
    # Railway injects PORT automatically
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
