#!/usr/bin/env python3
"""
ARX-PacketGuard Local Python Flask Relay & PacketGuard Monitor API
Educational Information Security Prototype — Non-Root Relay & Metadata Inspector
"""

import hashlib
import hmac
import json
import math
import os
import secrets
import shutil
import sqlite3
import subprocess
import time
from collections import defaultdict
from flask import Flask, jsonify, request

app = Flask(__name__)
# Limit request payload size to 64 KB (Section 10 Web & App Security)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

DB_PATH = os.environ.get("ARX_SQLITE_PATH", "arx_packetguard_local.sqlite")
LOCAL_DEMO_ENABLED = os.environ.get("ARX_LOCAL_DEMO", "1") == "1"

# Simple per-IP sliding window rate limiter (120 requests / 10s)
_rate_buckets: dict[str, list[float]] = defaultdict(list)
_csrf_tokens: dict[str, str] = {}


def check_rate_limit(client_ip: str, limit: int = 120, window_sec: float = 10.0) -> bool:
    now = time.time()
    bucket = [t for t in _rate_buckets[client_ip] if now - t < window_sec]
    if len(bucket) >= limit:
        _rate_buckets[client_ip] = bucket
        return False
    bucket.append(now)
    _rate_buckets[client_ip] = bucket
    return True


def hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000, dklen=32)
    return dk.hex()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT PRIMARY KEY,
                participant_a TEXT NOT NULL,
                participant_b TEXT NOT NULL,
                handshake_json TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS relay_envelopes (
                seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                envelope_id TEXT UNIQUE NOT NULL,
                conversation_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                protocol_version TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                direction TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                msg_num INTEGER NOT NULL,
                nonce_hex TEXT NOT NULL,
                ciphertext_hex TEXT NOT NULL,
                auth_tag_hex TEXT NOT NULL,
                mode TEXT NOT NULL,
                serialized_envelope_bytes INTEGER NOT NULL,
                crypto_overhead_bytes INTEGER NOT NULL,
                tampered_flag TEXT NOT NULL,
                delivery_status TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS packet_metadata (
                seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id TEXT UNIQUE NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                source_type TEXT NOT NULL,
                scenario_name TEXT NOT NULL,
                interface_name TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                captured_bytes INTEGER NOT NULL,
                tcp_flags TEXT,
                arp_sender_mac TEXT,
                arp_sender_ip TEXT,
                dns_query_name TEXT
            );
            """
        )
        now_ms = int(time.time() * 1000)
        for user in ("alice", "bob", "mallory"):
            salt = f"arx-salt-{user}"
            pw_hash = hash_password(f"{user}-demo-pass", salt)
            conn.execute(
                "INSERT OR IGNORE INTO accounts (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (user, pw_hash, salt, now_ms),
            )
        conn.execute(
            "INSERT OR IGNORE INTO conversations (conversation_id, participant_a, participant_b, handshake_json, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("conv-alice-bob", "alice", "bob", None, now_ms),
        )
        conn.commit()


def verify_membership(conn: sqlite3.Connection, conversation_id: str, username: str) -> bool:
    row = conn.execute(
        "SELECT participant_a, participant_b FROM conversations WHERE conversation_id = ?",
        (conversation_id,),
    ).fetchone()
    if not row:
        return False
    return username in (row["participant_a"], row["participant_b"])


def shannon_entropy(label: str) -> float:
    if not label:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in label:
        counts[ch] += 1
    length = len(label)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 2)


@app.before_request
def enforce_security_controls():
    client_ip = request.remote_addr or "127.0.0.1"
    if not check_rate_limit(client_ip):
        return jsonify({"ok": False, "error": "Rate limit exceeded"}), 429


@app.route("/api/health", methods=["GET"])
def health():
    tshark_path = shutil.which("tshark")
    return jsonify({
        "ok": True,
        "service": "ARX-PacketGuard Python Flask Relay",
        "tsharkInstalled": tshark_path is not None,
        "localDemoEnabled": LOCAL_DEMO_ENABLED,
    })


@app.route("/api/relay/envelopes/<conversation_id>", methods=["GET", "POST"])
def handle_envelopes(conversation_id: str):
    acting_user = (request.headers.get("X-ARX-User") or "").lower()
    with get_db() as conn:
        if not verify_membership(conn, conversation_id, acting_user):
            return jsonify({"ok": False, "error": "Cross-conversation access denied"}), 403

        if request.method == "GET":
            rows = conn.execute(
                "SELECT * FROM relay_envelopes WHERE conversation_id = ? ORDER BY seq_id ASC",
                (conversation_id,),
            ).fetchall()
            return jsonify({"ok": True, "envelopes": [dict(r) for r in rows]})

        payload = request.get_json(force=True)
        header = payload["header"]
        conn.execute(
            """
            INSERT INTO relay_envelopes (
                envelope_id, conversation_id, session_id, protocol_version,
                sender, recipient, direction, epoch, msg_num,
                nonce_hex, ciphertext_hex, auth_tag_hex, mode,
                serialized_envelope_bytes, crypto_overhead_bytes,
                tampered_flag, delivery_status, timestamp_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["envelopeId"],
                conversation_id,
                header["sessionId"],
                header["protocolVersion"],
                header["sender"],
                header["recipient"],
                header["direction"],
                int(header["epoch"]),
                int(header["msgNum"]),
                header["nonceHex"],
                payload["ciphertextHex"],
                payload["authTagHex"],
                payload["mode"],
                int(payload.get("serializedEnvelopeBytes", 0)),
                int(payload.get("cryptoOverheadBytes", 28)),
                payload.get("tamperedFlag", "NONE"),
                "RELAYED_TO_RECIPIENT",
                int(payload.get("timestampMs", time.time() * 1000)),
            ),
        )
        conn.commit()
        return jsonify({"ok": True, "envelopeId": payload["envelopeId"]})


@app.route("/api/monitor/ingest-packets", methods=["POST"])
def ingest_packets():
    data = request.get_json(force=True)
    packets = data.get("packets", [])
    with get_db() as conn:
        for p in packets:
            conn.execute(
                """
                INSERT OR REPLACE INTO packet_metadata (
                    packet_id, timestamp_ms, source_type, scenario_name, interface_name,
                    src_ip, dst_ip, src_port, dst_port, protocol, captured_bytes,
                    tcp_flags, arp_sender_mac, arp_sender_ip, dns_query_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    p["packetId"],
                    int(p["timestampMs"]),
                    p.get("sourceType", "LIVE_CAPTURE_WORKER"),
                    p.get("scenarioName", "Live TShark Stream"),
                    p.get("interfaceName", "lo0"),
                    p["srcIp"],
                    p["dstIp"],
                    p.get("srcPort"),
                    p.get("dstPort"),
                    p["protocol"],
                    int(p["capturedBytes"]),
                    p.get("tcpFlags"),
                    p.get("arpSenderMac"),
                    p.get("arpSenderIp"),
                    p.get("dnsQueryName"),
                ),
            )
        conn.commit()
    return jsonify({"ok": True, "ingested": len(packets)})


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    print(f"ARX-PacketGuard Flask Backend listening on http://127.0.0.1:{port}")
    # Debug mode disabled by default (Section 10 requirement)
    app.run(host="127.0.0.1", port=port, debug=False)
