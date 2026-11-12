# api/index.py
# ECI Voter Search API — Vercel Deployment
# GET /voterinfo?voterid=XXXXXXXX
# Credit: alam_web_master

import base64
import json
import os
import time
import requests
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

BASE = "https://gateway-voters.eci.gov.in"
CAPTCHA_SOLVER_URL = "https://captcha-solver-api-beta.vercel.app/solve"
MAX_RETRIES = 3

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "applicationName": "ELECTORAL-SEARCH",
    "appName": "ELECTORAL-SEARCH",
    "channelidobo": "ELECTORAL-SEARCH",
    "Origin": "https://electoralsearch.eci.gov.in",
    "Referer": "https://electoralsearch.eci.gov.in/",
}

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArb7++BxL/YN8OIln+6FL
9Gnw5DNmQ/VFZXss+J+TuQyJc891JbqbijxYQNEin2c2u+CnpXpoGQ/1gUSzDMJe
NS3sNSlIUykp2dt7xIm/cmV4sZ/c769vCxVRosMfRaZJnBAah+m1X26lEhnOo0wp
AB9Txr8RIyBe6h7PiQWykeJeh6UacOBBX28kgkq7+vJhW8HgB38lt32XRocznRYw
S9LqR7ZweFmQhTr1+EGrqiEKCOCxMYgHR2SQckb96hZ9kWzfzeun4bUO5oXKJciL
kiS1IgKieADEvYLgu129ZIpn1H+8H+8ikNNVETqEDDMtqcQcQmWppJvcWHaXAs+f
8QIDAQAB
-----END PUBLIC KEY-----"""

PO = "SFfIO0YsOlOKawZe855n97lc4tcPkj7WWsi38yNWpalLBLZzQdkqHWYbZ0=GhSJk2raUo"
PO_SLICE = PO[15:59]


# ─────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────
def load_pub():
    return serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())


def b64decode_padded(s: str) -> bytes:
    s = str(s).strip()
    return base64.b64decode(s + "=" * ((-len(s)) % 4))


def encrypt_body(obj: dict) -> dict:
    pub = load_pub()
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    pt = json.dumps(obj, separators=(",", ":")).encode()
    ct = AESGCM(aes_key).encrypt(iv, pt, None)
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "encryptedPayload": base64.b64encode(ct).decode(),
        "encryptedKey": base64.b64encode(enc_key).decode(),
        "iv": base64.b64encode(iv).decode(),
    }


def decrypt_with_po(data_b64: str):
    raw = b64decode_padded(data_b64)
    if len(raw) < 28:
        return None
    key = b64decode_padded(PO_SLICE)
    if len(key) >= 32:
        key = key[:32]
    elif len(key) not in (16, 24, 32):
        key = key.ljust(32, b"\0")[:32]
    try:
        return AESGCM(key).decrypt(raw[:12], raw[12:], None)
    except Exception:
        return None


def solve_captcha_api(img_b64: str) -> str:
    try:
        r = requests.post(
            CAPTCHA_SOLVER_URL,
            json={
                "image": img_b64,
                "charset": "alnum",
                "min_len": 4,
                "max_len": 8,
            },
            timeout=15,
        )
        if r.status_code != 200:
            return ""
        data = r.json()
        if data.get("ok") and data.get("text"):
            return str(data["text"]).strip()
        return ""
    except Exception:
        return ""


def fetch_and_solve_captcha():
    try:
        r = requests.get(
            f"{BASE}/api/v1/captcha-service/getCaptcha/sir",
            headers=HEADERS,
            timeout=10,
        )
        r.raise_for_status()
        data_b64 = r.json().get("data") or ""
        pt = decrypt_with_po(data_b64)
        if not pt:
            return None, None
        obj = json.loads(pt.decode())
        captcha_id = obj.get("id")
        img_b64 = obj.get("captcha") or ""
        if "," in img_b64:
            img_b64 = img_b64.split(",", 1)[1]
        captcha_text = solve_captcha_api(img_b64)
        return captcha_id, captcha_text
    except Exception:
        return None, None


def search_epic(epic: str) -> dict:
    """Try up to MAX_RETRIES. Returns dict with success/data/attempts."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            captcha_id, captcha_text = fetch_and_solve_captcha()
            if not captcha_id or not captcha_text:
                continue

            payload = {
                "epicNumber": epic,
                "captchaId": captcha_id,
                "captchaData": captcha_text,
                "securityKey": "na",
            }
            body = encrypt_body(payload)

            r = requests.post(
                f"{BASE}/api/v1/elastic/search-by-epic-from-national-display-v1",
                headers=HEADERS,
                json=body,
                timeout=12,
            )

            if r.status_code == 400:
                time.sleep(0.6)
                continue
            if r.status_code != 200:
                continue

            data = r.json()
            if isinstance(data, list) and data:
                return {
                    "success": True,
                    "attempts": attempt,
                    "raw": data,
                }
            return {
                "success": False,
                "attempts": attempt,
                "error": "No record found for this EPIC number.",
            }
        except Exception as e:
            continue

    return {
        "success": False,
        "attempts": MAX_RETRIES,
        "error": "Failed after retries (captcha/network). Try again.",
    }


def parse_voter_record(raw_list):
    if not raw_list or not isinstance(raw_list, list):
        return None
    try:
        content = raw_list[0].get("content", {})
        return {
            "epic": content.get("epicNumber"),
            "name": content.get("fullName"),
            "name_local": content.get("fullNameL1"),
            "relation_type": content.get("relationType"),
            "relation_name": content.get("relationName"),
            "relative_full_name": content.get("relativeFullName"),
            "age": content.get("age"),
            "gender": content.get("gender"),
            "address": content.get("buildingAddress"),
            "assembly": content.get("asmblyName"),
            "assembly_no": content.get("acNumber"),
            "district": content.get("districtValue"),
            "state": content.get("stateName"),
            "part_no": content.get("partNumber"),
            "serial_no": content.get("partSerialNumber"),
            "polling_station": content.get("psbuildingName"),
            "room": content.get("psRoomDetails"),
            "gps": content.get("partLatLong"),
            "status": "Active" if content.get("isActive") else "Inactive",
        }
    except Exception:
        return None


# ─────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "ok": True,
        "name": "ECI Voter Search API",
        "credit": "alam_web_master",
        "endpoints": {
            "voterinfo": "GET /voterinfo?voterid=XXXXXXXX",
            "health": "GET /health",
        },
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "voter-info", "time": int(time.time())})


@app.route("/voterinfo", methods=["GET"])
def voterinfo():
    voterid = (
        request.args.get("voterid")
        or request.args.get("epic")
        or request.args.get("id")
        or ""
    ).upper().strip()

    if not voterid:
        return jsonify({
            "success": False,
            "error": "voterid parameter is required",
            "example": "/voterinfo?voterid=ZJJ2263770",
        }), 400

    if len(voterid) < 6 or len(voterid) > 20:
        return jsonify({
            "success": False,
            "error": "Invalid voterid format",
        }), 400

    t0 = time.time()
    result = search_epic(voterid)
    elapsed_ms = int((time.time() - t0) * 1000)

    if not result["success"]:
        return jsonify({
            "success": False,
            "voterid": voterid,
            "attempts": result.get("attempts"),
            "elapsed_ms": elapsed_ms,
            "error": result.get("error", "Unknown error"),
        }), 502

    parsed = parse_voter_record(result["raw"])

    return jsonify({
        "success": True,
        "voterid": voterid,
        "attempts": result["attempts"],
        "elapsed_ms": elapsed_ms,
        "parsed": parsed,
        "data": result["raw"],
        "credit": "alam_web_master",
    }), 200


# Vercel/WSGI entry (some platforms need it)
application = app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
