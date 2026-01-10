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
import base64
from requests.auth import HTTPBasicAuth

load_dotenv()

# --- CONFIGURATION ---
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")
B2_BUCKET_ID = os.getenv("B2_BUCKET_ID")

# --- MPESA CONFIG ---
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET")
MPESA_CALLBACK_URL = "https://backblaze-signer-api.onrender.com/v1/payments/callback"
MPESA_STORE_NUMBER = os.getenv("MPESA_STORE_NUMBER") # Business ShortCode
MPESA_TILL_NUMBER = os.getenv("MPESA_TILL_NUMBER")   # The actual Till
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY")
MPESA_TRANSACTION_TYPE = 'CustomerPayBillOnline' # CustomerPayBillOnline for sandbox, while CustomerBuyGoodsOnline for Live

# Signed URL TTLs
MOVIE_TTL = 86400        # 24 hours
SERIES_TTL = 86400       # 24 hours
COLLECTION_TTL = 86400   # 24 hours
MAX_THREADS = 10

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
# Set the TTLCache to 18 hours (64800 seconds)
# This is the "secret sauce": Python expires its cache BEFORE Flutter's 20h buffer
signed_url_cache = TTLCache(maxsize=5000, ttl=64800)
user_purchase_cache = TTLCache(maxsize=2000, ttl=60)

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

def get_user_purchases(uid: str) -> List[Dict]:
    """Retrieves all completed purchases for a user (1 Firestore Read)."""
    if uid in user_purchase_cache:
        return user_purchase_cache[uid]
    
    # Single read: Fetch all completed items at once
    snaps = db.collection("users").document(uid).collection("purchases")\
              .where("purchaseStatus", "==", "complete").get()
    
    purchases = [s.to_dict() for s in snaps]
    user_purchase_cache[uid] = purchases
    return purchases

def assert_entitlement(uid: str, is_admin: bool, content_id: str, content_type: str, parent_id: Optional[str] = None):
    """Refactored: Uses 1 read max by validating in-memory."""
    if is_admin: return 

    purchases = get_user_purchases(uid)
    is_entitled = False

    if content_type == "season":
        # Check if they own this season OR the parent series
        is_entitled = any(
            (p["itemId"] == content_id and p["itemType"] == "season") or
            (parent_id and p["itemId"] == parent_id and p["itemType"] == "series")
            for p in purchases
        )
    elif content_type == "collectionMovie":
        # Check if they own this movie OR the parent collection
        is_entitled = any(
            (p["itemId"] == content_id and p["itemType"] == "collectionMovie") or
            (parent_id and p["itemId"] == parent_id and p["itemType"] == "collection")
            for p in purchases
        )
    else:
        # Standard check (movie, series, collection)
        is_entitled = any(p["itemId"] == content_id and p["itemType"] == content_type for p in purchases)

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

@app.post("/sign/series")
def sign_series():
    uid, is_admin, err, code = require_auth()
    if err: return err, code

    try:
        series_id = request.json["seriesId"]
        season_id = request.json["seasonId"]

        # entitlement: season OR series
        assert_entitlement(uid, is_admin, season_id, "season", parent_id=series_id)
        
        episodes = db.collection("series") \
            .document(series_id) \
            .collection("seasons") \
            .document(season_id) \
            .collection("episodes") \
            .stream()

        signed = []
        for ep in episodes:
            data = ep.to_dict()
            signed.append({
                "episodeId": ep.id,
                "title": data.get("title"),
                "url": sign_b2(data["videoPath"], SERIES_TTL),
                "expiresIn": SERIES_TTL
            })

        return jsonify({
            "seriesId": series_id,
            "seasonId": season_id,
            "episodes": signed,
            "expiresIn": SERIES_TTL
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/sign/collection")
def sign_collection():
    uid, is_admin, err, code = require_auth()
    if err: return err, code

    try:
        collection_id = request.json["collectionId"]
        assert_entitlement(uid, is_admin, collection_id, "collection")

        coll = db.collection("collections").document(collection_id).get()
        if not coll.exists:
            return jsonify({"error": "Not found"}), 404

        movies = coll.to_dict().get("movies", [])
        signed = []

        for m in movies:
            signed.append({
                "movieId": m["movieId"],
                "url": sign_b2(m["videoPath"], COLLECTION_TTL),
                "expiresIn": COLLECTION_TTL
            })

        return jsonify({
            "collectionId": collection_id,
            "movies": signed,
            "expiresIn": COLLECTION_TTL
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400
        
@app.post("/sign/collection/movie")
def sign_collection_movie():
    uid, is_admin, err, code = require_auth()
    if err: return err, code

    try:
        movie_id = request.json["movieId"]
        collection_id = request.json["collectionId"]
        assert_entitlement(uid, is_admin, movie_id, "collectionMovie", parent_id=collection_id)
        
        coll = db.collection("collections").document(collection_id).get()
        if not coll.exists:
            return jsonify({"error": "Not found"}), 404

        movie = next(
            (m for m in coll.to_dict().get("movies", []) if m["movieId"] == movie_id),
            None
        )

        if not movie:
            return jsonify({"error": "Movie not in collection"}), 404

        return jsonify({
            "movieId": movie_id,
            "url": sign_b2(movie["videoPath"], MOVIE_TTL),
            "expiresIn": MOVIE_TTL
        })

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

@app.post("/v1/auth/b2-token")
def get_b2_upload_token():
    uid, is_admin, err, code = require_auth()
    if err: return err, code
    
    try:
        # B2 Authorize
        auth_data = authorize_b2()
        
        # Get Upload URL for the specific bucket
        r = requests.post(
            f"{auth_data['apiUrl']}/b2api/v2/b2_get_upload_url",
            headers={"Authorization": auth_data["authorizationToken"]},
            json={"bucketId": B2_BUCKET_ID}
        )
        r.raise_for_status()
        data = r.json()
        
        # Return what the DirectUploadService expects
        return jsonify({
            "uploadUrl": data["uploadUrl"],
            "uploadAuthToken": data["authorizationToken"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/v1/payments/stk-push")
def mpesa_stk_push():
    uid, is_admin, err, code = require_auth()
    if err: return err, code

    data = request.json
    print(f"DEBUG: Incoming Flutter Data: {data}")
    phone = data["phone"] 
    amount = int(data["amount"])
    item_id = data["item_id"]
    item_name = data["item_name"]
    item_type = data["item_type"]

    # 1. Get Access Token (Standard for all M-Pesa APIs)
    api_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    r = requests.get(api_url, auth=HTTPBasicAuth(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
    
    if r.status_code != 200:
        print(f"DEBUG: Token Error: {r.text}")
        return jsonify({"error": "Failed to get access token"}), 500
        
    access_token = r.json()['access_token']

    # 2. Generate Password using STORE_NUMBER (BusinessShortCode)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    pass_str = f"{MPESA_STORE_NUMBER}{MPESA_PASSKEY}{timestamp}"
    password = base64.b64encode(pass_str.encode()).decode()

    # 3. Request STK Push for Buy Goods (Till)
    stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    headers = {"Authorization": f"Bearer {access_token}"}

    safe_ref = item_name.replace(" ", "")[:12] if item_name else "Payment"
    
    payload = {
        "BusinessShortCode": MPESA_STORE_NUMBER, # The Store Number
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": MPESA_TRANSACTION_TYPE, # CRITICAL for Till/ Paybill for sandbox
        "Amount": amount,
        "PartyA": phone, # Customer phone
        "PartyB": MPESA_TILL_NUMBER, # The actual Till Number
        "PhoneNumber": phone,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": safe_ref,
        "TransactionDesc": f"Payment for {item_id}"
    }

    print(f"DEBUG: Safaricom Request Payload: {payload}")
    res = requests.post(stk_url, json=payload, headers=headers)
    res_data = res.json()
    
    print(f"DEBUG: Safaricom RAW Response: {res_data}")
    if res.status_code == 200:
        checkout_id = res_data["CheckoutRequestID"]
        # Save to Firestore so Flutter Stream hears it
        db.collection("users").document(uid).collection("payments").document(checkout_id).set({
            "itemId": item_id,
            "itemName": item_name,
            "item_type": item_type,
            "amount": amount,
            "status": "PENDING",
            "createdAt": firestore.SERVER_TIMESTAMP,
            "checkoutRequestId": checkout_id,
            "paymentType": "till_buy_goods"
        })
        return jsonify(res_data)
    
    return jsonify({"error": "Mpesa request failed", "details": res_data}), 400
    
@app.post("/v1/payments/callback")
def mpesa_callback():
    # LOG: See what Safaricom sends back after payment
    print(f"DEBUG: Mpesa Callback Received: {request.json}")
    
    try:
        data = request.json["Body"]["stkCallback"]
        checkout_id = data["CheckoutRequestID"]
        result_code = data["ResultCode"]

        payment_query = db.collection_group("payments").where("checkoutRequestId", "==", checkout_id).limit(1).get()
        
        if payment_query:
            payment_doc = payment_query[0]
            pay_data = payment_doc.to_dict()
            uid = payment_doc.reference.parent.parent.id
            
            if result_code == 0:
                # Safaricom sends metadata in a list of Key-Value pairs
                metadata = data.get("CallbackMetadata", {}).get("Item", [])
                receipt = next((item["Value"] for item in metadata if item["Name"] == "MpesaReceiptNumber"), "UNKNOWN")
                
                payment_doc.reference.update({
                    "status": "COMPLETED", 
                    "updatedAt": firestore.SERVER_TIMESTAMP,
                    "mpesaReceipt": receipt # Save the actual M-Pesa code
                })
                
                # Also add it to the purchase record
                db.collection("users").document(uid).collection("purchases").add({
                    "amount": pay_data.get("amount"),
                    "currency": "KES",
                    "itemId": pay_data["itemId"],
                    "itemType": pay_data["itemType"],
                    "paymentMethod": "M-PESA",
                    "purchaseDate": firestore.SERVER_TIMESTAMP,
                    "purchaseStatus": "complete",
                    "receiptData": receipt,
                })
    
            else:
                result_desc = data.get("ResultDesc", "Payment failed")
                payment_doc.reference.update({
                    "status": "FAILED",
                    "errorCode": result_code,
                    "errorMessage": result_desc,
                    "updatedAt": firestore.SERVER_TIMESTAMP
                })
                print(f"DEBUG: Payment {checkout_id} marked as FAILED code {result_code}")

        return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})
    except Exception as e:
        print(f"DEBUG: Callback processing error: {e}")
        return jsonify({"ResultCode": 1, "ResultDesc": "Internal Error"}), 500

@app.get("/v1/debug/config-check")
def config_check():
    """Checks if Environment Variables are loaded without showing full secrets."""
    uid, is_admin, err, code = require_auth()
    if err or not is_admin: 
        return jsonify({"error": "Admin only"}), 403

    config_status = {
        "MPESA_CONSUMER_KEY_LOADED": bool(os.getenv("MPESA_CONSUMER_KEY")),
        "MPESA_CONSUMER_SECRET_LOADED": bool(os.getenv("MPESA_CONSUMER_SECRET")),
        "MPESA_PASSKEY_LOADED": bool(os.getenv("MPESA_PASSKEY")),
        "MPESA_STORE_NUMBER": os.getenv("MPESA_STORE_NUMBER"),
        "MPESA_TILL_NUMBER": os.getenv("MPESA_TILL_NUMBER"),
        "FIREBASE_SECRET_FILE_EXISTS": os.path.exists("/etc/secrets/serviceAccountKey.json"),
        "ENV_MODE": "Production" if os.getenv("RENDER") else "Local"
    }
    
    # Log it to Render console too
    print(f"DEBUG CONFIG CHECK: {config_status}")
    return jsonify(config_status)
    
@app.get("/health")
@app.get("/")
def health():
    return {"status": "ok"}, 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)






