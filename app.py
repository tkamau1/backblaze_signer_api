import os
import requests
from flask import Flask, request, jsonify
from firebase_admin import auth, credentials, initialize_app, firestore
from dotenv import load_dotenv

load_dotenv()

B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")  # name (not bucketId) used in URLs
FIREBASE_CRED_JSON = os.getenv("FIREBASE_CRED_JSON")

# Init Firebase Admin
cred = credentials.Certificate(FIREBASE_CRED_JSON)
initialize_app(cred)
db = firestore.client()

app = Flask(__name__)

def authorize_b2():
    """Authorize with Backblaze B2 and return dict with apiUrl and authToken"""
    resp = requests.get("https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
                        auth=(B2_KEY_ID, B2_APP_KEY))
    resp.raise_for_status()
    return resp.json()

@app.route("/get_signed_url", methods=["POST"])
def get_signed_url():
    """
    Body JSON: { "file": "uploads/dj_afro/movies/FastX.mp4", "validSeconds": 600 }
    Header: Authorization: Bearer <Firebase ID token>
    """
    id_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        id_token = auth_header.split(" ", 1)[1]

    if not id_token:
        return jsonify({"error":"Missing auth token"}), 401

    try:
        decoded = auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error":"Invalid Firebase token", "detail": str(e)}), 401

    payload = request.get_json() or {}
    file_name = payload.get("file")
    valid_seconds = int(payload.get("validSeconds", 600))
    if not file_name:
        return jsonify({"error":"Missing file name"}), 400

    # 1) Check Firestore if user is allowed (payment verified)
    uid = decoded.get("uid")
    # Example: check collection 'purchases' for doc { userId: uid, file: file_name, status: 'success' }
    purchases = db.collection("purchases").where("userId", "==", uid).where("file", "==", file_name).where("status", "==", "success").limit(1).get()
    if not purchases:
        return jsonify({"error":"Not purchased"}), 403

    # 2) Authorize with B2 and request download authorization
    try:
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        # b2_get_download_authorization expects bucketId, so we need the bucketId:
        # Get bucketId via b2_list_buckets or store it in env. We'll call list buckets here for simplicity.
        r = requests.post(f"{api_url}/b2api/v2/b2_list_buckets",
                          headers={"Authorization": auth_token},
                          json={"accountId": auth_data["accountId"]})
        r.raise_for_status()
        buckets = r.json().get("buckets", [])
        bucket = next((b for b in buckets if b["bucketName"] == B2_BUCKET_NAME), None)
        if not bucket:
            return jsonify({"error":"Bucket not found"}), 500
        bucket_id = bucket["bucketId"]

        # Request download authorization for this exact filename.
        payld = {
            "bucketId": bucket_id,
            "fileNamePrefix": file_name,
            "validDurationInSeconds": valid_seconds
        }
        r2 = requests.post(f"{api_url}/b2api/v2/b2_get_download_authorization",
                           headers={"Authorization": auth_token},
                           json=payld)
        r2.raise_for_status()
        auth_resp = r2.json()

        # Construct the signed URL: public file URL + query param Authorization=<token>
        signed_url = f"https://f000.backblazeb2.com/file/{B2_BUCKET_NAME}/{file_name}?Authorization={auth_resp['authorizationToken']}"
        return jsonify({"url": signed_url, "expiresIn": valid_seconds}), 200

    except Exception as e:
        return jsonify({"error":"Backblaze error", "detail": str(e)}), 500


@app.route("/get_upload_url", methods=["POST"])
def get_upload_url():
    """
    Used to let a trusted DJ client upload directly to B2.
    Body: { "fileName": "uploads/dj_afro/movies/FastX_Dubbed.mp4" }
    Auth: Bearer Firebase ID token.
    """
    id_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        id_token = auth_header.split(" ", 1)[1]
    if not id_token:
        return jsonify({"error":"Missing auth token"}), 401
    try:
        decoded = auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error":"Invalid Firebase token", "detail": str(e)}), 401

    # Check DJ role in Firestore (simple example)
    uid = decoded.get("uid")
    userdoc = db.collection("users").document(uid).get()
    if not userdoc.exists or userdoc.to_dict().get("role") not in ["dj","admin"]:
        return jsonify({"error":"Unauthorized - not a DJ"}), 403

    data = request.get_json() or {}
    file_name = data.get("fileName")
    if not file_name:
        return jsonify({"error":"Missing fileName"}), 400

    try:
        auth_data = authorize_b2()
        api_url = auth_data["apiUrl"]
        auth_token = auth_data["authorizationToken"]

        # Get bucketId as above
        r = requests.post(f"{api_url}/b2api/v2/b2_list_buckets",
                          headers={"Authorization": auth_token},
                          json={"accountId": auth_data["accountId"]})
        r.raise_for_status()
        buckets = r.json().get("buckets", [])
        bucket = next((b for b in buckets if b["bucketName"] == B2_BUCKET_NAME), None)
        if not bucket:
            return jsonify({"error":"Bucket not found"}), 500
        bucket_id = bucket["bucketId"]

        # Get upload URL & token
        r2 = requests.post(f"{api_url}/b2api/v2/b2_get_upload_url",
                           headers={"Authorization": auth_token},
                           json={"bucketId": bucket_id})
        r2.raise_for_status()
        up = r2.json()
        # Return uploadUrl and uploadAuthToken - client should PUT to uploadUrl with Authorization header uploadAuthToken
        return jsonify({
            "uploadUrl": up["uploadUrl"],
            "uploadAuthToken": up["authorizationToken"],
            "fileName": file_name
        }), 200

    except Exception as e:
        return jsonify({"error":"Backblaze error", "detail": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))

