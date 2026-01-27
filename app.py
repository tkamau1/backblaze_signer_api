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
import time
from requests.auth import HTTPBasicAuth

load_dotenv()

# --- CONFIGURATION ---
B2_PRIVATE_KEY_ID = os.getenv("B2_PRIVATE_KEY_ID")
B2_PRIVATE_APP_KEY = os.getenv("B2_PRIVATE_APPLICATION_KEY") 
B2_PUBLIC_KEY_ID = os.getenv("B2_PUBLIC_KEY_ID")
B2_PUBLIC_APP_KEY = os.getenv("B2_PUBLIC_APPLICATION_KEY")

# Primary Private Bucket (Videos)
B2_PRIVATE_BUCKET_NAME = os.getenv("B2_PRIVATE_BUCKET_NAME")
B2_PRIVATE_BUCKET_ID = os.getenv("B2_PRIVATE_BUCKET_ID")

# Public Bucket (Posters)
B2_PUBLIC_BUCKET_NAME = os.getenv("B2_PUBLIC_BUCKET_NAME") 
B2_PUBLIC_BUCKET_ID = os.getenv("B2_PUBLIC_BUCKET_ID")

# --- MPESA CONFIG ---
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET")
MPESA_CALLBACK_URL = "https://backblaze-signer-api.onrender.com/v1/payments/callback"
MPESA_STORE_NUMBER = os.getenv("MPESA_STORE_NUMBER") # Business ShortCode
MPESA_TILL_NUMBER = os.getenv("MPESA_TILL_NUMBER")   # The actual Till
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY")
MPESA_TRANSACTION_TYPE = 'CustomerPayBillOnline' # CustomerPayBillOnline for sandbox, while CustomerBuyGoodsOnline for Live

# Add Lipana configuration
LIPANA_TILL_NUMBER = os.getenv("LIPANA_TILL_NUMBER")
LIPANA_SECRET_KEY = os.getenv("LIPANA_SECRET_KEY")  # lip_sk_test_...
LIPANA_ENVIRONMENT = os.getenv("LIPANA_ENVIRONMENT", "sandbox")

# CORRECT URLs
if LIPANA_ENVIRONMENT == "production":
    LIPANA_BASE_URL = "https://api.lipana.dev/v1"
else:
    LIPANA_BASE_URL = "https://api.lipana.dev/sandbox"

LIPANA_CALLBACK_URL = "https://backblaze-signer-api.onrender.com/v1/payments/lipana-callback"

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
# This is the "secret sauce": Python expires its cache BEFORE Flutter's 20h buffer
signed_url_cache = TTLCache(maxsize=5000, ttl=64800)
user_purchase_cache = TTLCache(maxsize=2000, ttl=60)

# --- AUTH & ENTITLEMENT ---

def require_auth() -> Tuple[Optional[str], bool, Optional[dict], Optional[Response], Optional[int]]:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None, False, None, jsonify({"error": "Missing token"}), 401
    try:
        token = header.split(" ", 1)[1]
        decoded = auth.verify_id_token(token)
        uid = decoded["uid"]
        is_admin = decoded.get("admin", False)
        return uid, is_admin, decoded, None, None
    except Exception:
        return None, False, None, jsonify({"error": "Auth failed"}), 401


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

def assert_entitlement(uid: str,is_admin: bool,decoded: dict,content_id: str,content_type: str,parent_id: str = None,part_id: str = None):
    """
    Check if user has access to the content.
    - Admin / Premium users bypass checks
    - Supports per-part purchase for series
    """
    if is_admin or time.time() < decoded.get("premiumUntil", 0):
        return

    purchases = get_user_purchases(uid)
    allowed = False

    if content_type == "seriesPart" and parent_id and part_id:
        # Check if user bought the part or the whole series
        allowed = any(
            (p["itemId"] == part_id and p["itemType"] == "seriesPart") or
            (p["itemId"] == parent_id and p["itemType"] == "series")
            for p in purchases
        )
    elif content_type == "series":
        # Either purchased the series itself
        allowed = any(
            (p["itemId"] == content_id and p["itemType"] == "series")
            for p in purchases
        )
    elif content_type == "movie":
        allowed = any(
            p["itemId"] == content_id and p["itemType"] == "movie"
            for p in purchases
        )
    elif content_type == "collectionMovie" and parent_id:
        allowed = any(
            (p["itemId"] == content_id and p["itemType"] == "collectionMovie") or
            (p["itemId"] == parent_id and p["itemType"] == "collection")
            for p in purchases
        )
    elif content_type == "collection":
        allowed = any(
            p["itemId"] == content_id and p["itemType"] == "collection"
            for p in purchases
        )

    if not allowed:
        raise PermissionError(
            f"Access denied to {content_type} {content_id}"
            + (f" (parent {parent_id})" if parent_id else "")
        )
        
# --- B2 CORE HELPERS ---
b2_auth_store = {
    "private": {"expires": datetime.min, "data": None},
    "public":  {"expires": datetime.min, "data": None}
}
# Set the TTLCache to 18 hours (64800 seconds)

def authorize_b2(is_public=False):
    global b2_auth_store
    scope_key = "public" if is_public else "private"
    # Check specific cache for this scope
    if datetime.utcnow() < b2_auth_store[scope_key]["expires"]:
        print(f"DEBUG: Using cached B2 auth for {scope_key}")
        return b2_auth_store[scope_key]["data"]
    print(f"DEBUG: Authorizing B2 for {scope_key.upper()} bucket...")
    
    key_id = B2_PUBLIC_KEY_ID if is_public else B2_PRIVATE_KEY_ID
    app_key = B2_PUBLIC_APP_KEY if is_public else B2_PRIVATE_APP_KEY
    
    if not key_id or not app_key:
        print(f"ERROR: Missing keys for {scope_key} storage")
        raise ValueError(f"B2 Keys not found for {scope_key}")
    r = requests.get(
        "https://api.backblazeb2.com/b2api/v2/b2_authorize_account", 
        auth=(key_id, app_key)
    )
    
    if r.status_code != 200:
        print(f"B2 AUTH FAILED: {r.text}")
        r.raise_for_status()
        
    data = r.json()
    # Save to the specific scope key
    b2_auth_store[scope_key] = {
        "data": data, 
        "expires": datetime.utcnow() + timedelta(hours=23)
    }
    return data

def sign_b2(file_path: str, expires: int) -> str:
    cache_key = f"{B2_PRIVATE_BUCKET_ID}:{file_path}:{expires}"
    if cache_key in signed_url_cache:
        return signed_url_cache[cache_key]
    auth_data = authorize_b2()
    r = requests.post(
        f"{auth_data['apiUrl']}/b2api/v2/b2_get_download_authorization",
        headers={"Authorization": auth_data["authorizationToken"]},
        json={"bucketId": B2_PRIVATE_BUCKET_ID, "fileNamePrefix": file_path, "validDurationInSeconds": expires}
    )
    r.raise_for_status()
    token = r.json()["authorizationToken"]
    url = f"{auth_data['downloadUrl']}/file/{B2_PRIVATE_BUCKET_NAME}/{file_path}?Authorization={token}"
    signed_url_cache[cache_key] = url
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
    """Return B2 files that are not referenced anywhere in Firestore."""
    is_public = request.args.get("isPublic", "false").lower() == "true"
    auth_data = authorize_b2(is_public)
    target_bucket = B2_PUBLIC_BUCKET_ID if is_public else B2_PRIVATE_BUCKET_ID

    all_b2_files = {}
    next_file_name = None

    # Step 1: Paginated B2 Scan
    while True:
        r = requests.post(
            f"{auth_data['apiUrl']}/b2api/v2/b2_list_file_names",
            headers={"Authorization": auth_data["authorizationToken"]},
            json={"bucketId": target_bucket, "maxFileCount": 1000, "startFileName": next_file_name}
        )
        r.raise_for_status()
        data = r.json()
        for f in data.get("files", []):
            all_b2_files[f["fileName"]] = f["fileId"]
        next_file_name = data.get("nextFileName")
        if not next_file_name: break

    # Step 2: Collect all Firestore video paths
    db_paths = set()
    
    # Movies
    for m in db.collection("movies").stream():
        db_paths.add(m.to_dict().get("videoPath"))

    # Series parts
    for s in db.collection("series").stream():
        for part in s.to_dict().get("parts", []):
            db_paths.add(part.get("videoPath"))

    # Collection movies
    for coll in db.collection("collections").stream():
        for item in coll.to_dict().get("movies", []):
            db_paths.add(item.get("videoPath"))

    # Return orphan files
    orphans = [{"path": p, "id": i} for p, i in all_b2_files.items() if p not in db_paths]
    return orphans

# --- API ROUTES ---
def is_free(data: dict) -> bool:
    try:
        return int(data.get("price", 0)) == 0
    except (TypeError, ValueError):
        return False

@app.post("/sign/movie")
def sign_movie():
    uid, is_admin, decoded, err, code = require_auth()
    if err:
        return err, code

    movie_id = request.json["movieId"]
    doc = db.collection("movies").document(movie_id).get()

    if not doc.exists:
        return jsonify({"error": "Not found"}), 404
    
    try:
        assert_entitlement(uid, is_admin, decoded, movie_id, "movie")
    except PermissionError:
        if not is_free(doc.to_dict()):
            return jsonify({"error": "Access denied"}), 403
    
    movie = doc.to_dict()
    
    return jsonify({
        "url": sign_b2(movie["videoPath"], MOVIE_TTL),
        "expiresIn": MOVIE_TTL
    })
@app.post("/sign/series")
def sign_series():
    """Signs all parts in a series (for bulk loading/pre-caching)."""
    uid, is_admin, decoded, err, code = require_auth()
    if err: return err, code

    series_id = request.json.get("seriesId")
    doc = db.collection("series").document(series_id).get()

    if not doc.exists:
        return jsonify({"error": "Series not found"}), 404
    
    series_data = doc.to_dict()
    
    try:
        assert_entitlement(uid, is_admin, decoded, series_id, "series")
    except PermissionError:
        if not is_free(series_data):
            return jsonify({"error": "Access denied"}), 403

    parts = series_data.get("parts", [])
    signed_parts = []

    for p in parts:
        # Using 'videoPath' and 'partName' from your doc example
        signed_parts.append({
            "partId": p.get("partId"),
            "partName": p.get("partName"),
            "url": sign_b2(p["videoPath"], SERIES_TTL),
            "expiresIn": SERIES_TTL
        })

    return jsonify({
        "seriesId": series_id,
        "parts": signed_parts,
        "expiresIn": SERIES_TTL
    })


@app.post("/sign/series/part")
def sign_series_part():
    """Signs a single specific part by searching the parts array."""
    uid, is_admin, decoded, err, code = require_auth()
    if err: return err, code

    data = request.json
    series_id = data.get("seriesId")
    part_id = data.get("partId")

    doc = db.collection("series").document(series_id).get()
    if not doc.exists:
        return jsonify({"error": "Series not found"}), 404

    series_data = doc.to_dict()
    parts = series_data.get("parts", [])
    
    # Find the specific part in the array
    part = next((p for p in parts if p.get("partId") == part_id), None)
    if not part:
        return jsonify({"error": "Part not found"}), 404

    try:
        assert_entitlement(uid, is_admin, decoded, series_id, "series")
    except PermissionError:
        # If series is not free, check if this specific part is free (teaser)
        if not is_free(series_data) and not is_free(part):
            return jsonify({"error": "Access denied"}), 403

    return jsonify({
        "seriesId": series_id,
        "partId": part_id,
        "url": sign_b2(part["videoPath"], SERIES_TTL),
        "expiresIn": SERIES_TTL
    })
    
@app.post("/sign/collection")
def sign_collection():
    uid, is_admin, decoded, err, code = require_auth()
    if err:
        return err, code

    collection_id = request.json["collectionId"]
    coll_ref = db.collection("collections").document(collection_id).get()
    if not coll_ref.exists:
        return jsonify({"error": "Not found"}), 404
        
    try:
        assert_entitlement(uid,is_admin,decoded,collection_id,"collection")
    except PermissionError:
        if not is_free(coll_ref.to_dict()):
            return jsonify({"error": "Access denied"}), 403

    coll = coll_ref.to_dict()
    signed = []

    for m in coll.get("movies", []):
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

        
@app.post("/sign/collection/movie")
def sign_collection_movie():
    uid, is_admin, decoded, err, code = require_auth()
    if err:
        return err, code

    movie_id = request.json["movieId"]
    collection_id = request.json["collectionId"]
    coll_ref = db.collection("collections").document(collection_id).get()
    if not coll_ref.exists:
        return jsonify({"error": "Not found"}), 404

    movie = next(
        (m for m in coll_ref.to_dict().get("movies", [])
         if m["movieId"] == movie_id),
        None
    )
    
    if not movie:
        return jsonify({"error": "Not found"}), 404
        
    try:
        assert_entitlement(uid,is_admin,decoded,movie_id,"collectionMovie",parent_id=collection_id)
    except PermissionError:
        if not is_free(movie):
            return jsonify({"error": "Access denied"}), 403

    return jsonify({
        "movieId": movie_id,
        "url": sign_b2(movie["videoPath"], MOVIE_TTL),
        "expiresIn": MOVIE_TTL
    })

@app.delete("/content/movie/<movie_id>")
def delete_movie(movie_id):
    uid, is_admin, decoded, err, code = require_auth()
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
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin: return jsonify({"error": "Admin only"}), 403
    orphans = get_all_orphans()
    return jsonify({"count": len(orphans), "orphans": orphans})

@app.post("/admin/cleanup/purge-orphans")
def purge_orphans():
    uid, is_admin, decoded, err, code = require_auth()
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
    uid, is_admin, decoded, err, code = require_auth()
    if err: return err, code
    
    try:
        data = request.json or {}
        is_public = data.get("isPublic", False)
        
        # B2 Authorize
        auth_data = authorize_b2(is_public)
        target_bucket = B2_PUBLIC_BUCKET_ID if is_public else B2_PRIVATE_BUCKET_ID
        
        # Get Upload URL for the specific bucket
        r = requests.post(
            f"{auth_data['apiUrl']}/b2api/v2/b2_get_upload_url",
            headers={"Authorization": auth_data["authorizationToken"]},
            json={"bucketId": target_bucket}
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
    uid, is_admin, decoded, err, code = require_auth()
    if err: return err, code

    data = request.json
    print(f"DEBUG: Incoming Flutter Data: {data}")
    
    phone = data["phone"]
    amount = int(data["amount"])  # Lipana expects integer
    item_id = data["item_id"]
    item_name = data["item_name"]
    item_type = data["item_type"]

    # Validate phone format
    if not phone.startswith("254") or len(phone) != 12:
        return jsonify({"error": "Phone must be in format 254XXXXXXXXX"}), 400

    # Prepare Lipana STK Push request
    lipana_payload = {
        "amount": amount,
        "phone_number": phone,
        "account_reference": item_id[:12],  # Max 12 chars
        "transaction_desc": item_name[:20] if item_name else "Payment"  # Max 20 chars
    }

    headers = {
        "Authorization": f"Bearer {LIPANA_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    print(f"DEBUG: Lipana URL: {LIPANA_BASE_URL}/stk-push")
    print(f"DEBUG: Lipana Payload: {lipana_payload}")

    try:
        # Call Lipana STK Push endpoint
        response = requests.post(
            f"{LIPANA_BASE_URL}/stk-push",
            json=lipana_payload,
            headers=headers,
            timeout=30
        )
        
        print(f"DEBUG: Lipana Response Status: {response.status_code}")
        print(f"DEBUG: Lipana Response Body: {response.text}")

        if response.status_code in [200, 201]:
            lipana_data = response.json()
            
            # Lipana response structure
            checkout_id = lipana_data.get("checkout_request_id")
            
            if not checkout_id:
                print(f"ERROR: No checkout_request_id in response: {lipana_data}")
                return jsonify({"error": "Invalid response from payment provider"}), 500
            
            # Save to Firestore
            db.collection("users").document(uid).collection("payments").document(checkout_id).set({
                "itemId": item_id,
                "itemName": item_name,
                "itemType": item_type,
                "planType": data.get("planType", "monthly"),
                "amount": amount,
                "status": "PENDING",
                "createdAt": firestore.SERVER_TIMESTAMP,
                "checkoutRequestId": checkout_id,
                "paymentProvider": "lipana",
                "phoneNumber": phone
            })
            
            # Return in Safaricom format (for Flutter compatibility)
            return jsonify({
                "CheckoutRequestID": checkout_id,
                "CustomerMessage": lipana_data.get("message", "STK Push sent to your phone"),
                "ResponseCode": "0",
                "ResponseDescription": "Success"
            })
        else:
            error_data = response.json() if response.headers.get('content-type') == 'application/json' else {"error": response.text}
            print(f"ERROR: Lipana returned {response.status_code}: {error_data}")
            return jsonify({
                "error": "Payment request failed", 
                "details": error_data
            }), response.status_code
            
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error calling Lipana: {str(e)}")
        return jsonify({"error": f"Payment service unavailable: {str(e)}"}), 500
    except Exception as e:
        print(f"ERROR: Lipana STK Push failed: {str(e)}")
        return jsonify({"error": f"Payment initiation failed: {str(e)}"}), 500


@app.post("/v1/payments/lipana-callback")
def lipana_callback():
    """Handles payment status updates from Lipana"""
    print(f"DEBUG: Lipana Callback Received: {request.json}")

    try:
        data = request.json
        
        # Lipana callback structure
        checkout_id = data.get("checkout_request_id")
        status = data.get("status")  # "success", "failed", "cancelled"
        mpesa_receipt = data.get("receipt_number") or data.get("mpesa_receipt_number")
        amount = data.get("amount")
        phone = data.get("phone_number")

        if not checkout_id:
            print("ERROR: No checkout_request_id in callback")
            return jsonify({"message": "Invalid callback data"}), 400

        # Find the payment document
        payment_query = db.collection_group("payments")\
            .where("checkoutRequestId", "==", checkout_id)\
            .limit(1).get()

        if not payment_query:
            print(f"WARNING: Payment not found for checkout {checkout_id}")
            return jsonify({"message": "Payment not found"}), 404

        payment_doc = payment_query[0]
        pay_data = payment_doc.to_dict()
        uid = payment_doc.reference.parent.parent.id
        
        # Prevent duplicate processing
        if pay_data.get("status") in ["COMPLETED", "FAILED"]:
            print(f"INFO: Payment {checkout_id} already processed as {pay_data.get('status')}")
            return jsonify({"message": "Already processed"}), 200

        # Handle SUCCESS
        if status and status.lower() == "success":
            payment_doc.reference.update({
                "status": "COMPLETED",
                "updatedAt": firestore.SERVER_TIMESTAMP,
                "mpesaReceipt": mpesa_receipt,
                "resultDescription": "Payment successful"
            })

            # Add to purchases
            db.collection("users").document(uid).collection("purchases").add({
                "amount": pay_data.get("amount"),
                "currency": "KES",
                "itemId": pay_data["itemId"],
                "itemType": pay_data["itemType"],
                "paymentMethod": "M-PESA",
                "purchaseDate": firestore.SERVER_TIMESTAMP,
                "purchaseStatus": "complete",
                "receiptData": mpesa_receipt or "LIPANA_" + checkout_id,
            })

            # Handle subscription if applicable
            if pay_data.get("itemType") == "subscription":
                user = auth.get_user(uid)
                current_claims = user.custom_claims or {}
                durations = {"weekly": 7, "monthly": 30, "yearly": 365}
                days = durations.get(pay_data.get("planType"), 30)
                current_expiry = current_claims.get("premiumUntil", 0)
                start_ts = max(time.time(), current_expiry)

                new_expiry = datetime.fromtimestamp(start_ts) + timedelta(days=days)
                new_ts = int(new_expiry.timestamp())

                new_claims = current_claims.copy()
                new_claims['premiumUntil'] = new_ts
                auth.set_custom_user_claims(uid, new_claims)

                db.collection("users").document(uid).update({
                    "premiumUntil": new_ts,
                    "isPremium": True
                })

            print(f"SUCCESS: Payment {checkout_id} completed with receipt {mpesa_receipt}")
            
        # Handle FAILED/CANCELLED
        else:
            failure_reason = data.get("message") or data.get("result_description") or "Payment failed"
            payment_doc.reference.update({
                "status": "FAILED",
                "errorMessage": failure_reason,
                "updatedAt": firestore.SERVER_TIMESTAMP
            })
            print(f"FAILED: Payment {checkout_id} - {failure_reason}")

        return jsonify({"message": "Callback processed"}), 200

    except Exception as e:
        print(f"ERROR: Callback processing failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": "Internal error"}), 500
        
@app.get("/v1/debug/config-check")
def config_check():
    """Checks if Environment Variables are loaded without showing full secrets."""
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin: 
        return jsonify({"error": "Admin only"}), 403

    config_status = {
        "MPESA_CONSUMER_KEY_LOADED": bool(os.getenv("MPESA_CONSUMER_KEY")),
        "MPESA_CONSUMER_SECRET_LOADED": bool(os.getenv("MPESA_CONSUMER_SECRET")),
        "MPESA_PASSKEY_LOADED": bool(os.getenv("MPESA_PASSKEY")),
        "MPESA_STORE_NUMBER": os.getenv("MPESA_STORE_NUMBER"),
        "MPESA_TILL_NUMBER": os.getenv("MPESA_TILL_NUMBER"),
        "FIREBASE_SECRET_FILE_EXISTS": os.path.exists("/etc/secrets/serviceAccountKey.json"),
        "ENV_MODE": "Production" if os.getenv("RENDER") else "Local",
        "LIPANA_SECRET_KEY_LOADED": bool(LIPANA_SECRET_KEY),
        "LIPANA_SECRET_KEY_PREFIX": LIPANA_SECRET_KEY[:15] if LIPANA_SECRET_KEY else None,
        "LIPANA_ENVIRONMENT": LIPANA_ENVIRONMENT,
        "LIPANA_BASE_URL": LIPANA_BASE_URL,
        "LIPANA_CALLBACK_URL": LIPANA_CALLBACK_URL
    }
    
    # Log it to Render console too
    print(f"DEBUG CONFIG CHECK: {config_status}")
    return jsonify(config_status)

# --- TV AUTH CONFIG ---
# We use a short 5-minute window for pairing codes
DEVICE_CODE_TTL_MINUTES = 5

@app.post("/v1/auth/verify-tv-code")
def verify_tv_code():
    """
    Called by the MOBILE app to approve a code shown on the TV.
    """
    print("--- DEBUG: verify_tv_code started ---")
    
    # Use your existing auth helper to ensure the Mobile user is logged in
    uid, is_admin, err, code = require_auth()
    if err:
        print(f"--- DEBUG: auth failed: {err}")
        return err, code

    print(f"--- DEBUG: authenticated user: {uid}")
    try:
        data = request.json
        device_code = data.get("code").upper().strip()
        
        if not device_code:
            return jsonify({"error": "Code is required"}), 400

        # 1. Check if the code exists in Firestore
        code_ref = db.collection('device_auth_requests').document(device_code)
        doc = code_ref.get()
        
        if not doc.exists:
            return jsonify({"error": "Code not found or expired"}), 404
            
        doc_data = doc.to_dict()
        
        # 2. Verify expiry (Safety check)
        created_at = doc_data.get('createdAt')
        if not created_at:
            return jsonify({"error": "Invalid code data"}), 400
            
        # Check if the code is older than 5 minutes
        # Note: server_timestamp returns a datetime object in Python
        now = datetime.utcnow()
        if now > created_at + timedelta(minutes=DEVICE_CODE_TTL_MINUTES):
            code_ref.delete() # Cleanup expired code
            return jsonify({"error": "Code has expired"}), 403

        if doc_data.get('status') != 'pending':
             return jsonify({"error": "Code already used or invalid"}), 400

        # 3. MINT CUSTOM TOKEN
        # Since you are using the Firebase Admin SDK, you CAN create a custom token.
        # This is allowed on the free tier of Firebase as long as you use the Admin SDK 
        # inside your own server (Render).
        custom_token = auth.create_custom_token(uid)
        
        if isinstance(custom_token, bytes):
            custom_token = custom_token.decode('utf-8')

        # 4. Update Firestore to trigger the TV's listener
        code_ref.update({
            'status': 'approved',
            'token': custom_token,
            'approvedBy': uid,
            'approvedAt': firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({"success": True, "message": "TV successfully linked!"})

    except Exception as e:
        print(f"TV Auth Error: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.get("/health")
@app.get("/")
def health():
    return {"status": "ok"}, 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)




