import os
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Tuple, Optional

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from dotenv import load_dotenv
from cachetools import TTLCache

import firebase_admin
from firebase_admin import credentials, auth, firestore

load_dotenv()

# --- CONFIGURATION ---
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")
B2_BUCKET_ID = os.getenv("B2_BUCKET_ID")

# Signed URL TTLs
MOVIE_TTL = 14400        # 4 hours
SERIES_TTL = 86400       # 24 hours
COLLECTION_TTL = 86400   # 24 hours
MAX_THREADS = 10
PER_USER_RESPONSE_TTL = 600 

# Initialize Firebase
try:
    # Path for Render Secret File
    cred = credentials.Certificate("/etc/secrets/serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
except Exception:
    # Fallback for local testing
    firebase_admin.initialize_app()
    
db = firestore.client()
app = Flask(__name__)
CORS(app)

# --- CACHING ---
b2_auth_cache = {"expires": datetime.min, "data": None}
signed_url_cache = TTLCache(maxsize=5000, ttl=max(MOVIE_TTL, SERIES_TTL))
per_user_response_cache = TTLCache(maxsize=2000, ttl=PER_USER_RESPONSE_TTL)

# --- AUTH & ENTITLEMENT ---

def require_auth() -> Tuple[Optional[str], bool, Optional[Response], Optional[int]]:
    """Verifies Firebase Token and returns (UID, is_admin)."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None, False, jsonify({"error": "Missing token"}), 401
    try:
        token = header.split(" ", 1)[1]
        decoded = auth.verify_id_token(token)
        uid = decoded["uid"]
        is_admin = decoded.get("admin", False) 
        return uid, is_admin, None, None
    except Exception:
        return None, False, jsonify({"error": "Auth failed"}), 401

def assert_entitlement(uid: str, is_admin: bool, content_id: str, content_type: str, series_id: Optional[str] = None, movie_id: Optional[str] = None):
    """Checks purchase record OR Admin bypass."""
    if is_admin: return # Admins can watch anything

    purchases_ref = db.collection("users").document(uid).collection("purchases")\
                      .where("purchaseStatus", "==", "complete")

    if content_type == "season":
        snaps = purchases_ref.where("itemType", "in", ["series", "season"]).get()
        is_entitled = any(
            (s.to_dict()["itemId"] == series_id and s.to_dict()["itemType"] == "series") or
            (s.to_dict()["itemId"] == content_id and s.to_dict()["itemType"] == "season")
            for s in snaps
        )
    elif content_type == "collectionMovie":
        snaps = purchases_ref.where("itemType", "in", ["collection", "collectionMovie"]).get()
        is_entitled = any(
            (s.to_dict()["itemId"] == content_id and s.to_dict()["itemType"] == "collection") or
            (s.to_dict()["itemId"] == movie_id and s.to_dict()["itemType"] == "collectionMovie")
            for s in snaps
        )
    else:
        snap = purchases_ref.where("itemId", "==", content_id).where("itemType", "==", content_type).limit(1).get()
        is_entitled = len(snap) > 0

    if not is_entitled:
        raise PermissionError(f"Access denied to {content_type} {content_id}")

# --- B2 CORE HELPERS ---

def authorize_b2():
    global b2_auth_cache
    if datetime.utcnow() < b2_auth_cache["expires"]:
        return b2_auth_cache["data"]
    r = requests.get("https://api.backblazeb2.com/b2api/v2/b2_authorize_account", auth=(B2_KEY_ID, B2_APP_KEY))
    r.raise_for_status()
    data = r.json()
    b2_auth_cache = {"data": data, "expires": datetime.utcnow() + timedelta(hours=23)}
    return data

def sign_b2(file_path: str, expires: int) -> str:
    if file_path in signed_url_cache: return signed_url_cache[file_path]
    auth_data = authorize_b2()
    r = requests.post(
        f"{auth_data['apiUrl']}/b2api/v2/b2_get_download_authorization",
        headers={"Authorization": auth_data["authorizationToken"]},
        json={"bucketId": B2_BUCKET_ID, "fileNamePrefix": file_path, "validDurationInSeconds": expires}
    )
    r.raise_for_status()
    token = r.json()["authorizationToken"]
    url = f"{auth_data['downloadUrl']}/file/{B2_BUCKET_NAME}/{file_path}?Authorization={token}"
    signed_url_cache[file_path] = url
    return url

def delete_b2_file(file_path: str, file_id: str) -> bool:
    """Permanently removes a file version from Backblaze."""
    try:
        auth_data = authorize_b2()
        r = requests.post(
            f"{auth_data['apiUrl']}/b2api/v2/b2_delete_file_version",
            headers={"Authorization": auth_data["authorizationToken"]},
            json={"fileName": file_path, "fileId": file_id},
            timeout=15
        )
        return r.status_code == 200
    except Exception as e:
        print(f"B2 Delete Error: {e}")
        return False

# --- ORPHAN LOGIC ---

def get_all_orphans():
    """Scans B2 and Firestore to find unlinked files."""
    auth_data = authorize_b2()
    all_b2_files = {}
    next_file_name = None

    # Step 1: Paginated B2 Scan
    while True:
        r = requests.post(
            f"{auth_data['apiUrl']}/b2api/v2/b2_list_file_names",
            headers={"Authorization": auth_data["authorizationToken"]},
            json={"bucketId": B2_BUCKET_ID, "maxFileCount": 1000, "startFileName": next_file_name}
        )
        r.raise_for_status()
        data = r.json()
        for f in data.get("files", []):
            all_b2_files[f["fileName"]] = f["fileId"]
        next_file_name = data.get("nextFileName")
        if not next_file_name: break

    # Step 2: Firestore Path Collection
    db_paths = set()
    for m in db.collection("movies").stream():
        db_paths.add(m.to_dict().get("videoPath"))
    for ep in db.collection_group("episodes").stream():
        db_paths.add(ep.to_dict().get("videoPath"))
    for coll in db.collection("collections").stream():
        for item in coll.to_dict().get("movies", []):
            db_paths.add(item.get("videoPath"))

    return [{"path": p, "id": i} for p, i in all_b2_files.items() if p not in db_paths]

# --- API ROUTES ---

@app.post("/sign/movie")
def sign_movie():
    uid, is_admin, err, code = require_auth()
    if err: return err, code
    try:
        movie_id = request.json["movieId"]
        assert_entitlement(uid, is_admin, movie_id, "movie")
        doc = db.collection("movies").document(movie_id).get()
        if not doc.exists: return jsonify({"error": "Not found"}), 404
        movie = doc.to_dict()
        return jsonify({"url": sign_b2(movie["videoPath"], MOVIE_TTL), "expiresIn": MOVIE_TTL})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.delete("/content/movie/<movie_id>")
def delete_movie(movie_id):
    uid, is_admin, err, code = require_auth()
    if err: return err, code
    
    doc_ref = db.collection("movies").document(movie_id)
    doc = doc_ref.get()
    if not doc.exists: return jsonify({"error": "Not found"}), 404
    
    data = doc.to_dict()
    # Security: Owner or Admin only
    if not is_admin and data.get("uploaderId") != uid:
        return jsonify({"error": "Unauthorized"}), 403

    b2_success = delete_b2_file(data.get("videoPath"), data.get("fileId"))
    doc_ref.delete()
    return jsonify({"success": True, "b2_deleted": b2_success})

@app.get("/admin/cleanup/orphans")
def list_orphans():
    uid, is_admin, err, code = require_auth()
    if err or not is_admin: return jsonify({"error": "Admin only"}), 403
    orphans = get_all_orphans()
    return jsonify({"count": len(orphans), "orphans": orphans})

@app.post("/admin/cleanup/purge-orphans")
def purge_orphans():
    uid, is_admin, err, code = require_auth()
    if err or not is_admin: return jsonify({"error": "Admin only"}), 403

    dry_run = request.args.get("dry_run", "true").lower() == "true"
    orphans = get_all_orphans()
    
    if dry_run:
        return jsonify({"mode": "DRY RUN", "would_delete": len(orphans), "orphans": orphans})

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        results = list(ex.map(lambda o: delete_b2_file(o["path"], o["id"]), orphans))
    
    return jsonify({"mode": "LIVE PURGE", "deleted": results.count(True), "failed": results.count(False)})

@app.get("/health")
@app.get("/")
def health():
    return {"status": "ok"}, 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
