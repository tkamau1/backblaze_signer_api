import os
import requests
from flask import Flask, request, jsonify
from firebase_admin import auth, credentials, initialize_app, firestore
from dotenv import load_dotenv

load_dotenv()

# --- ENV VARIABLES ---
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")
B2_BUCKET_ID = os.getenv("B2_BUCKET_ID")  # ✅ use this instead of list_buckets
DEFAULT_VALID_SECONDS = 3600  # 1 hour default for signed URLs

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


# --- ROUTES ---

@app.route("/get_signed_url", methods=["POST"])
def get_signed_url():
    """Generate temporary signed URL for purchased file."""
    user, err, code = require_firebase_user()
    if err:
        return err, code

    payload = request.get_json() or {}
    file_name = payload.get("file")
    valid_seconds = int(payload.get("validSeconds", DEFAULT_VALID_SECONDS))

    if not file_name:
        return jsonify({"error": "Missing file name"}), 400

    # Check purchase
    uid = user.get("uid")
    purchases = db.collection("purchases") \
        .where("userId", "==", uid) \
        .where("file", "==", file_name) \
        .where("status", "==", "success") \
        .limit(1).get()
    if not purchases:
        return jsonify({"error": "Not purchased"}), 403

    try:
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        # Request signed authorization token
        resp = requests.post(f"{api_url}/b2api/v2/b2_get_download_authorization",
                             headers={"Authorization": auth_token},
                             json={
                                 "bucketId": B2_BUCKET_ID,
                                 "fileNamePrefix": file_name,
                                 "validDurationInSeconds": valid_seconds
                             })
        resp.raise_for_status()
        data = resp.json()
        signed_url = f"https://f000.backblazeb2.com/file/{B2_BUCKET_NAME}/{file_name}?Authorization={data['authorizationToken']}"
        return jsonify({"url": signed_url, "expiresIn": valid_seconds}), 200

    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500


@app.route("/get_upload_url", methods=["POST"])
def get_upload_url():
    """Allow DJ/admin users to upload a file."""
    user, err, code = require_firebase_user()
    if err:
        return err, code

    uid = user.get("uid")
    doc = db.collection("users").document(uid).get()
    role = doc.to_dict().get("role") if doc.exists else None
    if role not in ["dj", "admin"]:
        return jsonify({"error": "Unauthorized - not a DJ or admin"}), 403

    data = request.get_json() or {}
    file_name = data.get("fileName")
    if not file_name:
        return jsonify({"error": "Missing fileName"}), 400

    # Enforce folder naming (each DJ uploads to their folder)
    if role == "dj" and not file_name.startswith(f"uploads/{uid}/"):
        return jsonify({"error": "Upload path not allowed"}), 403

    try:
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        resp = requests.post(f"{api_url}/b2api/v2/b2_get_upload_url",
                             headers={"Authorization": auth_token},
                             json={"bucketId": B2_BUCKET_ID})
        resp.raise_for_status()
        upload_info = resp.json()

        return jsonify({
            "uploadUrl": upload_info["uploadUrl"],
            "uploadAuthToken": upload_info["authorizationToken"],
            "fileName": file_name
        }), 200

    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500


@app.route("/get_preview_url", methods=["POST"])
def get_preview_url():
    """Public or limited access short-lived URL (e.g. trailer)."""
    payload = request.get_json() or {}
    file_name = payload.get("file")
    valid_seconds = int(payload.get("validSeconds", 300))  # shorter: 5 min

    if not file_name:
        return jsonify({"error": "Missing file"}), 400

    try:
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        resp = requests.post(f"{api_url}/b2api/v2/b2_get_download_authorization",
                             headers={"Authorization": auth_token},
                             json={
                                 "bucketId": B2_BUCKET_ID,
                                 "fileNamePrefix": file_name,
                                 "validDurationInSeconds": valid_seconds
                             })
        resp.raise_for_status()
        data = resp.json()

        signed_url = f"https://f000.backblazeb2.com/file/{B2_BUCKET_NAME}/{file_name}?Authorization={data['authorizationToken']}"
        return jsonify({"url": signed_url, "expiresIn": valid_seconds}), 200

    except Exception as e:
        return jsonify({"error": "Backblaze error", "detail": str(e)}), 500


@app.route("/")
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
