import os
import requests
from flask import Flask, request, jsonify
from firebase_admin import auth, credentials, initialize_app, firestore
from dotenv import load_dotenv

load_dotenv()

# --- ENV ---
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")
B2_BUCKET_ID = os.getenv("B2_BUCKET_ID")
DEFAULT_VALID_SECONDS = 9000  # 2 hour 30 mins for movies
SERIES_VALID_SECONDS = 86400  # 24 hours
CLIP_VALID_SECONDS = 900      # 15 min
POSTER_VALID_SECONDS = 600    # 10 min

# --- FIREBASE ---
cred = credentials.Certificate("/etc/secrets/serviceAccountKey.json")
initialize_app(cred)
db = firestore.client()

app = Flask(__name__)

# --- UTILITIES ---

def authorize_b2():
    """Authorize with Backblaze B2."""
    resp = requests.get("https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
                        auth=(B2_KEY_ID, B2_APP_KEY))
    resp.raise_for_status()
    return resp.json()

def require_firebase_user():
    """Extract and verify Firebase ID token."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth_header.split(" ", 1)[1]
    try:
        decoded = auth.verify_id_token(token)
        return decoded, None, None
    except Exception as e:
        return None, jsonify({"error": "Invalid Firebase token", "detail": str(e)}), 401

def get_download_url():
    """Fetch the correct download URL from Backblaze account."""
    auth_data = authorize_b2()
    return f"{auth_data['downloadUrl']}/file/{B2_BUCKET_NAME}"

def generate_signed_url(file_name, valid_seconds):
    """Return a signed download URL for a specific file."""
    auth_data = authorize_b2()
    api_url = auth_data["apiUrl"]
    auth_token = auth_data["authorizationToken"]

    r = requests.post(f"{api_url}/b2api/v2/b2_get_download_authorization",
                      headers={"Authorization": auth_token},
                      json={
                          "bucketId": B2_BUCKET_ID,
                          "fileNamePrefix": file_name,
                          "validDurationInSeconds": valid_seconds
                      })
    r.raise_for_status()
    token = r.json()["authorizationToken"]

    download_base = f"{auth_data['downloadUrl']}/file/{B2_BUCKET_NAME}"
    return f"{download_base}/{file_name}?Authorization={token}"

# --- ROUTES ---

@app.route("/get_signed_url", methods=["POST"])
def get_signed_url():
    """Generate signed URL for purchased movie."""
    user, err, code = require_firebase_user()
    if err:
        return err, code

    payload = request.get_json() or {}
    file_name = payload.get("file")
    if not file_name:
        return jsonify({"error": "Missing file"}), 400

    uid = user["uid"]
    purchase = db.collection("purchases") \
        .where("userId", "==", uid) \
        .where("itemId", "==", os.path.basename(file_name)) \
        .where("itemType", "==", "movie") \
        .where("status", "==", "completed") \
        .limit(1).get()
    if not purchase:
        return jsonify({"error": "Not purchased"}), 403

    try:
        signed_url = generate_signed_url(file_name, DEFAULT_VALID_SECONDS)
        return jsonify({"url": signed_url, "expiresIn": DEFAULT_VALID_SECONDS}), 200
    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500


@app.route("/get_series_signed_urls", methods=["POST"])
def get_series_signed_urls():
    """Generate signed URLs for all episodes in a purchased series season."""
    user, err, code = require_firebase_user()
    if err:
        return err, code

    payload = request.get_json() or {}
    folder = payload.get("folder")  # e.g., "uploads/dj_junior/series/TULSA_KING/season_1/"
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
    if not purchase:
        return jsonify({"error": "Season not purchased"}), 403

    try:
        # List all files under the season folder (episodes)
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        resp = requests.post(f"{api_url}/b2api/v2/b2_list_file_names",
                             headers={"Authorization": auth_token},
                             json={"bucketId": B2_BUCKET_ID, "prefix": folder, "maxFileCount": 1000})
        resp.raise_for_status()
        files = resp.json().get("files", [])

        urls = []
        for f in files:
            file_name = f["fileName"]
            signed_url = generate_signed_url(file_name, SERIES_VALID_SECONDS)
            urls.append({"file": file_name, "url": signed_url})

        return jsonify({"season": season, "urls": urls, "expiresIn": SERIES_VALID_SECONDS}), 200

    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500


@app.route("/get_clip_url", methods=["POST"])
def get_clip_url():
    """Generate signed URL for a public clip (no purchase required)."""
    payload = request.get_json() or {}
    file_name = payload.get("file")
    if not file_name:
        return jsonify({"error": "Missing file"}), 400

    try:
        signed_url = generate_signed_url(file_name, CLIP_VALID_SECONDS)
        return jsonify({"url": signed_url, "expiresIn": CLIP_VALID_SECONDS}), 200
    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500


@app.route("/get_bulk_previews", methods=["POST"])
def get_bulk_previews():
    """Get signed URLs for all posters in a folder or all subfolders."""
    payload = request.get_json() or {}
    folder = payload.get("folder", "posters/")

    try:
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        folders = []
        if folder.endswith("/"):
            # Get top-level posters/movies, posters/series, etc.
            resp = requests.post(f"{api_url}/b2api/v2/b2_list_file_names",
                                 headers={"Authorization": auth_token},
                                 json={"bucketId": B2_BUCKET_ID, "prefix": folder, "maxFileCount": 1000})
            resp.raise_for_status()
            files = resp.json().get("files", [])
        else:
            # Per-folder only
            resp = requests.post(f"{api_url}/b2api/v2/b2_list_file_names",
                                 headers={"Authorization": auth_token},
                                 json={"bucketId": B2_BUCKET_ID, "prefix": folder, "maxFileCount": 1000})
            resp.raise_for_status()
            files = resp.json().get("files", [])

        previews = []
        for f in files:
            file_name = f["fileName"]
            if not file_name.lower().endswith((".jpg", ".png", ".jpeg", ".webp")):
                continue
            signed_url = generate_signed_url(file_name, POSTER_VALID_SECONDS)
            previews.append({"file": file_name, "url": signed_url})

        return jsonify({"count": len(previews), "previews": previews, "expiresIn": POSTER_VALID_SECONDS}), 200

    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500

@app.route("/get_collection_signed_urls", methods=["POST"])
def get_collection_signed_urls():
    """Generate signed URLs for all movies in a purchased collection."""
    user, err, code = require_firebase_user()
    if err:
        return err, code

    payload = request.get_json() or {}
    folder = payload.get("folder")  # e.g., "uploads/DJ_DHAVEMAN/collections/INSIDIOUS_1_5/"
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

    if not purchase:
        return jsonify({"error": "Collection not purchased"}), 403

    try:
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        # List all movie files in that collection folder
        resp = requests.post(f"{api_url}/b2api/v2/b2_list_file_names",
                             headers={"Authorization": auth_token},
                             json={"bucketId": B2_BUCKET_ID, "prefix": folder, "maxFileCount": 1000})
        resp.raise_for_status()
        files = resp.json().get("files", [])

        urls = []
        for f in files:
            file_name = f["fileName"]
            if not file_name.lower().endswith((".mp4", ".mkv", ".mov")):
                continue
            signed_url = generate_signed_url(file_name, SERIES_VALID_SECONDS)  # reuse 24h validity
            urls.append({"file": file_name, "url": signed_url})

        return jsonify({
            "collection": os.path.basename(folder.strip("/")),
            "count": len(urls),
            "urls": urls,
            "expiresIn": SERIES_VALID_SECONDS
        }), 200

    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500

@app.route("/")
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))

