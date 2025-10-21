import os
import requests
from flask import Flask, request, jsonify
from firebase_admin import auth, credentials, initialize_app, firestore
from dotenv import load_dotenv
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from flask_cors import CORS

load_dotenv()

# --- ENV ---
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")
B2_BUCKET_ID = os.getenv("B2_BUCKET_ID")
DEFAULT_VALID_SECONDS = 9000  # 2h 30m for movies
SERIES_VALID_SECONDS = 86400  # 24h
CLIP_VALID_SECONDS = 86400      # 24h
POSTER_VALID_SECONDS = 86400    # 24h
MAX_THREADS = 10              # parallelism for bulk URL generation

# --- FIREBASE ---
cred = credentials.Certificate("/etc/secrets/serviceAccountKey.json")
initialize_app(cred)
db = firestore.client()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# --- B2 Caching ---
b2_auth_cache = {"expires": datetime.min, "auth_data": None}

def authorize_b2_cached():
    """Authorize with B2 and cache token."""
    if datetime.utcnow() < b2_auth_cache["expires"]:
        return b2_auth_cache["auth_data"]
    try:
        resp = requests.get(
            "https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
            auth=(B2_KEY_ID, B2_APP_KEY),
            timeout=10
        )
        resp.raise_for_status()
        auth_data = resp.json()
        # Cache for 23 hours to avoid token expiration issues
        b2_auth_cache.update({
            "auth_data": auth_data,
            "expires": datetime.utcnow() + timedelta(hours=23)
        })
        return auth_data
    except Exception as e:
        raise RuntimeError(f"B2 authorization failed: {e}")

# --- Firebase Auth ---
def require_firebase_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth_header.split(" ", 1)[1]
    try:
        decoded = auth.verify_id_token(token)
        return decoded, None, None
    except Exception as e:
        return None, jsonify({"error": "Invalid Firebase token", "detail": str(e)}), 401

# --- B2 Signed URL ---
def generate_signed_url(file_name, valid_seconds, auth_data=None):
    """Return signed download URL for a file."""
    try:
        if not auth_data:
            auth_data = authorize_b2_cached()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]
        r = requests.post(
            f"{api_url}/b2api/v2/b2_get_download_authorization",
            headers={"Authorization": auth_token},
            json={
                "bucketId": B2_BUCKET_ID,
                "fileNamePrefix": file_name,
                "validDurationInSeconds": valid_seconds
            },
            timeout=10
        )
        r.raise_for_status()
        token = r.json()["authorizationToken"]
        download_base = f"{auth_data['downloadUrl']}/file/{B2_BUCKET_NAME}"
        return f"{download_base}/{file_name}?Authorization={token}"
    except Exception as e:
        raise RuntimeError(f"Failed to generate signed URL for {file_name}: {e}")

# --- Routes ---
@app.route("/get_signed_url", methods=["POST"])
def get_signed_url():
    user, err, code = require_firebase_user()
    if err: return err, code

    payload = request.get_json() or {}
    file_name = payload.get("file")
    if not file_name: return jsonify({"error": "Missing file"}), 400

    uid = user["uid"]
    purchase = db.collection("purchases") \
        .where("userId", "==", uid) \
        .where("itemId", "==", os.path.basename(file_name)) \
        .where("itemType", "==", "movie") \
        .where("status", "==", "completed") \
        .limit(1).get()
    if not purchase: return jsonify({"error": "Not purchased"}), 403

    try:
        signed_url = generate_signed_url(file_name, DEFAULT_VALID_SECONDS)
        return jsonify({"url": signed_url, "expiresIn": DEFAULT_VALID_SECONDS}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_series_signed_urls", methods=["POST"])
def get_series_signed_urls():
    user, err, code = require_firebase_user()
    if err: return err, code

    payload = request.get_json() or {}
    folder = payload.get("folder")
    item_id = payload.get("itemId")
    season = payload.get("season")
    if not folder or not item_id or not season:
        return jsonify({"error": "Missing folder, itemId or season"}), 400

    uid = user["uid"]
    purchase = db.collection("purchases") \
        .where("userId", "==", uid) \
        .where("itemId", "==", item_id) \
        .where("itemType", "==", "series") \
        .where("season", "==", int(season)) \
        .where("status", "==", "completed") \
        .limit(1).get()
    if not purchase: return jsonify({"error": "Season not purchased"}), 403

    try:
        auth_data = authorize_b2_cached()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]
        resp = requests.post(
            f"{api_url}/b2api/v2/b2_list_file_names",
            headers={"Authorization": auth_token},
            json={"bucketId": B2_BUCKET_ID, "prefix": folder, "maxFileCount": 1000},
            timeout=10
        )
        resp.raise_for_status()
        files = resp.json().get("files", [])

        urls = []
        def make_url(f):
            return {"file": f["fileName"], "url": generate_signed_url(f["fileName"], SERIES_VALID_SECONDS, auth_data)}

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            urls = list(executor.map(make_url, files))

        return jsonify({"season": season, "urls": urls, "expiresIn": SERIES_VALID_SECONDS}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_clip_url", methods=["POST"])
def get_clip_url():
    payload = request.get_json() or {}
    file_name = payload.get("file")
    if not file_name: return jsonify({"error": "Missing file"}), 400
    try:
        signed_url = generate_signed_url(file_name, CLIP_VALID_SECONDS)
        return jsonify({"url": signed_url, "expiresIn": CLIP_VALID_SECONDS}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_bulk_previews", methods=["POST"])
def get_bulk_previews():
    payload = request.get_json() or {}
    folder = payload.get("folder", "posters/")

    try:
        auth_data = authorize_b2_cached()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        resp = requests.post(
            f"{api_url}/b2api/v2/b2_list_file_names",
            headers={"Authorization": auth_token},
            json={"bucketId": B2_BUCKET_ID, "prefix": folder, "maxFileCount": 1000},
            timeout=10
        )
        resp.raise_for_status()
        files = resp.json().get("files", [])

        def make_url(f):
            fn = f["fileName"]
            if not fn.lower().endswith((".jpg", ".png", ".jpeg", ".webp")):
                return None
            return {"file": fn, "url": generate_signed_url(fn, POSTER_VALID_SECONDS, auth_data)}

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            previews = [res for res in executor.map(make_url, files) if res]

        return jsonify({"count": len(previews), "previews": previews, "expiresIn": POSTER_VALID_SECONDS}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_collection_signed_urls", methods=["POST"])
def get_collection_signed_urls():
    user, err, code = require_firebase_user()
    if err: return err, code

    payload = request.get_json() or {}
    folder = payload.get("folder")
    item_id = payload.get("itemId")
    if not folder or not item_id:
        return jsonify({"error": "Missing folder or itemId"}), 400

    uid = user["uid"]
    purchase = db.collection("purchases") \
        .where("userId", "==", uid) \
        .where("itemId", "==", item_id) \
        .where("itemType", "==", "collection") \
        .where("status", "==", "completed") \
        .limit(1).get()
    if not purchase: return jsonify({"error": "Collection not purchased"}), 403

    try:
        auth_data = authorize_b2_cached()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        resp = requests.post(
            f"{api_url}/b2api/v2/b2_list_file_names",
            headers={"Authorization": auth_token},
            json={"bucketId": B2_BUCKET_ID, "prefix": folder, "maxFileCount": 1000},
            timeout=10
        )
        resp.raise_for_status()
        files = [f for f in resp.json().get("files", []) if f["fileName"].lower().endswith((".mp4", ".mkv", ".mov"))]

        def make_url(f): return {"file": f["fileName"], "url": generate_signed_url(f["fileName"], SERIES_VALID_SECONDS, auth_data)}
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            urls = list(executor.map(make_url, files))

        return jsonify({
            "collection": os.path.basename(folder.strip("/")),
            "count": len(urls),
            "urls": urls,
            "expiresIn": SERIES_VALID_SECONDS
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))


