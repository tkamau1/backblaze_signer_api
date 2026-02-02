import os
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Tuple, Optional
import hmac
import hashlib
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

# --- CDN CONFIGURATION (NEW) ---
CDN_DOMAIN = os.getenv("CDN_DOMAIN", "media.djmovieskenya.app")
AUTH_SECRET = os.getenv("AUTH_SECRET")  # MUST MATCH Cloudflare Worker

if not AUTH_SECRET:
    raise ValueError("❌ AUTH_SECRET environment variable not set! This MUST match your Cloudflare Worker.")

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
LIPANA_SECRET_KEY = os.getenv("LIPANA_SECRET_KEY")   # lip_sk_test_...
LIPANA_ENVIRONMENT = os.getenv("LIPANA_ENVIRONMENT", "sandbox")
LIPANA_WEBHOOK_SECRET = os.getenv("LIPANA_WEBHOOK_SECRET")
LIPANA_BASE_URL = "https://api.lipana.dev/v1" 
LIPANA_CALLBACK_URL = "https://backblaze-signer-api.onrender.com/v1/payments/lipana-callback"

# TTLs
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
# Cache user purchases for 1 minute to reduce Firestore reads
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
    except Exception as e:
        print(f"Auth error: {e}")
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

def assert_entitlement(uid: str, is_admin: bool, decoded: dict, content_id: str, 
                       content_type: str, parent_id: str = None, part_id: str = None):
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
    
# ============================================
# CDN URL GENERATION (REPLACES sign_b2)
# ============================================

def generate_cdn_url(file_path: str) -> dict:
    """
    Generate hour-aligned signed URL for Cloudflare CDN.
    Token rotates at top of each hour (9:00, 10:00, 11:00, etc.)
    This MUST match the Worker's validation logic.
    
    Args:
        file_path: Path to file (e.g., "/hls/movie-123/index.m3u8")
    
    Returns:
        dict with 'url' and 'expiresIn' (seconds until token expires)
    """
    # Align to hour boundary (UTC)
    current_hour = int(time.time() // 3600)
    expiry = (current_hour + 1) * 3600
    
    # Ensure path starts with /
    if not file_path.startswith("/"):
        file_path = f"/{file_path}"
    
    # Generate HMAC signature (MUST match Worker's validation)
    data = f"{file_path}{expiry}"
    signature = hmac.new(
        AUTH_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Build CDN URL
    cdn_url = f"https://{CDN_DOMAIN}{file_path}?token={signature}&expires={expiry}"
    
    # Calculate seconds until expiry
    expires_in = expiry - int(time.time())
    
    return {
        "url": cdn_url,
        "expiresIn": expires_in
    }

# ============================================
# B2 CORE HELPERS (For Admin Operations Only)
# ============================================
b2_auth_store = {
    "private": {"expires": datetime.min, "data": None},
    "public":  {"expires": datetime.min, "data": None}
}

def authorize_b2(is_public=False):
    """
    B2 authorization - now only used for:
    - Admin file management
    - Direct uploads
    - Orphan cleanup
    
    NOT used for video playback URLs anymore (CDN handles that)
    """
    global b2_auth_store
    scope_key = "public" if is_public else "private"
    
    # Check specific cache for this scope
    if datetime.utcnow() < b2_auth_store[scope_key]["expires"]:
        return b2_auth_store[scope_key]["data"]
    
    print(f"DEBUG: Authorizing B2 for {scope_key.upper()} bucket...")
    
    key_id = B2_PUBLIC_KEY_ID if is_public else B2_PRIVATE_KEY_ID
    app_key = B2_PUBLIC_APP_KEY if is_public else B2_PRIVATE_APP_KEY
    
    if not key_id or not app_key:
        raise ValueError(f"B2 Keys not found for {scope_key}")
    
    r = requests.get(
        "https://api.backblazeb2.com/b2api/v2/b2_authorize_account", 
        auth=(key_id, app_key)
    )
    
    if r.status_code != 200:
        print(f"B2 AUTH FAILED: {r.text}")
        r.raise_for_status()
        
    data = r.json()
    b2_auth_store[scope_key] = {
        "data": data, 
        "expires": datetime.utcnow() + timedelta(hours=23)
    }
    return data

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
        if not next_file_name: 
            break

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

# ============================================
# API ROUTES - VIDEO PLAYBACK
# ============================================

def is_free(data: dict) -> bool:
    """Check if content is free"""
    try:
        return int(data.get("price", 0)) == 0
    except (TypeError, ValueError):
        return False

@app.post("/sign/movie")
def sign_movie():
    """Generate CDN URL for a movie"""
    uid, is_admin, decoded, err, code = require_auth()
    if err:
        return err, code

    movie_id = request.json.get("movieId")
    if not movie_id:
        return jsonify({"error": "movieId required"}), 400
    
    doc = db.collection("movies").document(movie_id).get()
    if not doc.exists:
        return jsonify({"error": "Movie not found"}), 404
    
    movie = doc.to_dict()
    
    # Check entitlement (skip for free content)
    try:
        assert_entitlement(uid, is_admin, decoded, movie_id, "movie")
    except PermissionError:
        if not is_free(movie):
            return jsonify({"error": "Access denied"}), 403
    
    # Generate CDN URL
    video_path = movie.get("videoPath")
    if not video_path:
        return jsonify({"error": "Video path not found"}), 404
    
    result = generate_cdn_url(video_path)
    return jsonify(result)


@app.post("/sign/series")
def sign_series():
    """Signs all parts in a series (for bulk loading/pre-caching)."""
    uid, is_admin, decoded, err, code = require_auth()
    if err: 
        return err, code

    series_id = request.json.get("seriesId")
    if not series_id:
        return jsonify({"error": "seriesId required"}), 400
    
    doc = db.collection("series").document(series_id).get()
    if not doc.exists:
        return jsonify({"error": "Series not found"}), 404
    
    series_data = doc.to_dict()
    
    # Check entitlement
    try:
        assert_entitlement(uid, is_admin, decoded, series_id, "series")
    except PermissionError:
        if not is_free(series_data):
            return jsonify({"error": "Access denied"}), 403

    parts = series_data.get("parts", [])
    signed_parts = []

    for p in parts:
        video_path = p.get("videoPath")
        if not video_path:
            continue
            
        cdn_data = generate_cdn_url(video_path)
        signed_parts.append({
            "partId": p.get("partId"),
            "partName": p.get("partName"),
            "url": cdn_data["url"],
            "expiresIn": cdn_data["expiresIn"]
        })

    return jsonify({
        "seriesId": series_id,
        "parts": signed_parts,
        "expiresIn": signed_parts[0]["expiresIn"] if signed_parts else 3600
    })


@app.post("/sign/series/part")
def sign_series_part():
    """Signs a single specific part by searching the parts array."""
    uid, is_admin, decoded, err, code = require_auth()
    if err: 
        return err, code

    data = request.json
    series_id = data.get("seriesId")
    part_id = data.get("partId")
    
    if not series_id or not part_id:
        return jsonify({"error": "seriesId and partId required"}), 400

    doc = db.collection("series").document(series_id).get()
    if not doc.exists:
        return jsonify({"error": "Series not found"}), 404

    series_data = doc.to_dict()
    parts = series_data.get("parts", [])
    
    # Find the specific part in the array
    part = next((p for p in parts if p.get("partId") == part_id), None)
    if not part:
        return jsonify({"error": "Part not found"}), 404

    # Check entitlement
    try:
        assert_entitlement(uid, is_admin, decoded, series_id, "series")
    except PermissionError:
        # If series is not free, check if this specific part is free (teaser)
        if not is_free(series_data) and not is_free(part):
            return jsonify({"error": "Access denied"}), 403

    video_path = part.get("videoPath")
    if not video_path:
        return jsonify({"error": "Video path not found"}), 404
    
    cdn_data = generate_cdn_url(video_path)
    
    return jsonify({
        "seriesId": series_id,
        "partId": part_id,
        "url": cdn_data["url"],
        "expiresIn": cdn_data["expiresIn"]
    })


@app.post("/sign/collection")
def sign_collection():
    """Generate CDN URLs for all movies in a collection"""
    uid, is_admin, decoded, err, code = require_auth()
    if err:
        return err, code

    collection_id = request.json.get("collectionId")
    if not collection_id:
        return jsonify({"error": "collectionId required"}), 400
    
    coll_ref = db.collection("collections").document(collection_id).get()
    if not coll_ref.exists:
        return jsonify({"error": "Collection not found"}), 404
    
    coll = coll_ref.to_dict()
    
    # Check entitlement
    try:
        assert_entitlement(uid, is_admin, decoded, collection_id, "collection")
    except PermissionError:
        if not is_free(coll):
            return jsonify({"error": "Access denied"}), 403

    signed = []
    for m in coll.get("movies", []):
        video_path = m.get("videoPath")
        if not video_path:
            continue
            
        cdn_data = generate_cdn_url(video_path)
        signed.append({
            "movieId": m.get("movieId"),
            "url": cdn_data["url"],
            "expiresIn": cdn_data["expiresIn"]
        })

    return jsonify({
        "collectionId": collection_id,
        "movies": signed,
        "expiresIn": signed[0]["expiresIn"] if signed else 3600
    })


@app.post("/sign/collection/movie")
def sign_collection_movie():
    """Generate CDN URL for a specific movie in a collection"""
    uid, is_admin, decoded, err, code = require_auth()
    if err:
        return err, code

    movie_id = request.json.get("movieId")
    collection_id = request.json.get("collectionId")
    
    if not movie_id or not collection_id:
        return jsonify({"error": "movieId and collectionId required"}), 400
    
    coll_ref = db.collection("collections").document(collection_id).get()
    if not coll_ref.exists:
        return jsonify({"error": "Collection not found"}), 404

    movie = next(
        (m for m in coll_ref.to_dict().get("movies", [])
         if m.get("movieId") == movie_id),
        None
    )
    
    if not movie:
        return jsonify({"error": "Movie not found in collection"}), 404
    
    # Check entitlement
    try:
        assert_entitlement(uid, is_admin, decoded, movie_id, "collectionMovie", parent_id=collection_id)
    except PermissionError:
        if not is_free(movie):
            return jsonify({"error": "Access denied"}), 403

    video_path = movie.get("videoPath")
    if not video_path:
        return jsonify({"error": "Video path not found"}), 404
    
    cdn_data = generate_cdn_url(video_path)
    
    return jsonify({
        "movieId": movie_id,
        "url": cdn_data["url"],
        "expiresIn": cdn_data["expiresIn"]
    })

# ============================================
# ADMIN ROUTES
# ============================================

@app.delete("/content/movie/<movie_id>")
def delete_movie(movie_id):
    """Delete a movie (owner or admin only)"""
    uid, is_admin, decoded, err, code = require_auth()
    if err: 
        return err, code
    
    doc_ref = db.collection("movies").document(movie_id)
    doc = doc_ref.get()
    if not doc.exists: 
        return jsonify({"error": "Not found"}), 404
    
    data = doc.to_dict()
    
    # Security: Owner or Admin only
    if not is_admin and data.get("uploaderId") != uid:
        return jsonify({"error": "Unauthorized"}), 403

    b2_success = delete_b2_file(data.get("videoPath"), data.get("fileId"))
    doc_ref.delete()
    
    return jsonify({"success": True, "b2_deleted": b2_success})


@app.get("/admin/cleanup/orphans")
def list_orphans():
    """List all orphaned B2 files (admin only)"""
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin: 
        return jsonify({"error": "Admin only"}), 403
    
    orphans = get_all_orphans()
    return jsonify({"count": len(orphans), "orphans": orphans})


@app.post("/admin/cleanup/purge-orphans")
def purge_orphans():
    """Delete all orphaned B2 files (admin only)"""
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin: 
        return jsonify({"error": "Admin only"}), 403

    dry_run = request.args.get("dry_run", "true").lower() == "true"
    orphans = get_all_orphans()
    
    if dry_run:
        return jsonify({
            "mode": "DRY RUN", 
            "would_delete": len(orphans), 
            "orphans": orphans
        })

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        results = list(ex.map(lambda o: delete_b2_file(o["path"], o["id"]), orphans))
    
    return jsonify({
        "mode": "LIVE PURGE", 
        "deleted": results.count(True), 
        "failed": results.count(False)
    })

# ============================================
# B2 UPLOAD TOKEN (For Direct Uploads)
# ============================================

@app.post("/v1/auth/b2-token")
def get_b2_upload_token():
    """Get B2 upload token for direct uploads from Flutter"""
    uid, is_admin, decoded, err, code = require_auth()
    if err: 
        return err, code
    
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
        
        return jsonify({
            "uploadUrl": data["uploadUrl"],
            "uploadAuthToken": data["authorizationToken"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ============================================
# PAYMENT ROUTES (Lipana Integration)
# ============================================

@app.post("/v1/payments/stk-push")
def mpesa_stk_push():
    """Initiate M-PESA STK push via Lipana"""
    uid, is_admin, decoded, err, code = require_auth()
    if err: 
        return err, code

    data = request.json
    print(f"DEBUG: Incoming Flutter Data: {data}")
    
    phone = data.get("phone")
    amount = int(data.get("amount"))
    item_id = data.get("item_id")
    item_name = data.get("item_name")
    item_type = data.get("item_type")

    # Validate phone format
    if not phone or not phone.startswith("254") or len(phone) != 12:
        return jsonify({"error": "Phone must be in format 254XXXXXXXXX"}), 400

    # Prepare Lipana STK Push request
    lipana_payload = {
        "phone": phone,
        "amount": amount
    }

    headers = {
        "x-api-key": LIPANA_SECRET_KEY,
        "Content-Type": "application/json"
    }

    lipana_url = f"{LIPANA_BASE_URL}/transactions/push-stk"

    try:
        response = requests.post(
            lipana_url,
            json=lipana_payload,
            headers=headers,
            timeout=30
        )
        
        print(f"DEBUG: Lipana Response Status: {response.status_code}")
        print(f"DEBUG: Lipana Response Body: {response.text}")

        if response.status_code in [200, 201]:
            lipana_data = response.json()
            response_data = lipana_data.get("data", {})
            
            transaction_id = response_data.get("transactionId")
            checkout_id = response_data.get("checkoutRequestID") or transaction_id
            
            if not transaction_id:
                print(f"ERROR: No transactionId in response: {lipana_data}")
                return jsonify({"error": "Invalid response from payment provider"}), 500
            
            # Store payment in Firestore
            db.collection("users").document(uid).collection("payments").document(transaction_id).set({
                "itemId": item_id,
                "itemName": item_name,
                "itemType": item_type,
                "planType": data.get("planType", "monthly"),
                "amount": amount,
                "status": "PENDING",
                "createdAt": firestore.SERVER_TIMESTAMP,
                "checkoutRequestId": checkout_id,
                "transactionId": transaction_id,
                "paymentProvider": "lipana",
                "phoneNumber": phone
            })
            
            return jsonify({
                "CheckoutRequestID": transaction_id,
                "CustomerMessage": response_data.get("message", "STK Push sent to your phone"),
                "ResponseCode": "0",
                "ResponseDescription": "Success"
            })
        else:
            error_data = response.json() if 'application/json' in response.headers.get('content-type', '') else {"error": response.text}
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
    
    # Verify webhook signature
    signature = request.headers.get('X-Lipana-Signature') or request.headers.get('x-lipana-signature')
    
    if signature and LIPANA_WEBHOOK_SECRET:
        payload = request.get_data()
        expected_signature = hmac.new(
            LIPANA_WEBHOOK_SECRET.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            print("ERROR: Invalid webhook signature")
            return jsonify({"error": "Unauthorized"}), 401
    
    print(f"DEBUG: Lipana Callback Received: {request.json}")

    try:
        data = request.json
        event = data.get("event")
        event_data = data.get("data", {})
        
        transaction_id = event_data.get("transactionId") or event_data.get("transaction_id")
        status = event_data.get("status")
        mpesa_receipt = event_data.get("mpesaReceiptNumber") or event_data.get("receipt_number")
        amount = event_data.get("amount")
        phone = event_data.get("phone") or event_data.get("phone_number")

        if not transaction_id:
            print("ERROR: No transactionId in callback")
            return jsonify({"message": "Invalid callback data"}), 400

        print(f"DEBUG: Processing callback - TxnID: {transaction_id}, Event: {event}, Status: {status}")

        # Find the payment document
        payment_query = db.collection_group("payments")\
            .where("transactionId", "==", transaction_id)\
            .limit(1).get()

        if not payment_query:
            print(f"WARNING: Payment not found for transaction {transaction_id}")
            return jsonify({"message": "Payment not found"}), 404

        payment_doc = payment_query[0]
        pay_data = payment_doc.to_dict()
        uid = payment_doc.reference.parent.parent.id
        
        # Prevent duplicate processing
        if pay_data.get("status") in ["COMPLETED", "FAILED"]:
            print(f"INFO: Payment {transaction_id} already processed")
            return jsonify({"message": "Already processed"}), 200

        # Handle SUCCESS
        if event in ["transaction.success", "payment.success"] or (status and status.lower() == "success"):
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
                "receiptData": mpesa_receipt or "LIPANA_" + transaction_id,
            })

            # Handle subscription
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

            print(f"SUCCESS: Payment {transaction_id} completed with receipt {mpesa_receipt}")
            
        # Handle FAILED/CANCELLED
        elif event in ["transaction.failed", "transaction.cancelled", "payment.failed"] or (status and status.lower() in ["failed", "cancelled"]):
            failure_reason = event_data.get("message") or event_data.get("result_description") or "Payment failed"
            payment_doc.reference.update({
                "status": "FAILED",
                "errorMessage": failure_reason,
                "updatedAt": firestore.SERVER_TIMESTAMP
            })
            print(f"FAILED: Payment {transaction_id} - {failure_reason}")
        else:
            print(f"WARNING: Unknown event: {event} with status: {status}")

        return jsonify({"message": "Callback processed"}), 200

    except Exception as e:
        print(f"ERROR: Callback processing failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": "Internal error"}), 500


@app.post("/v1/payments/test-complete/<transaction_id>")
def test_complete_payment(transaction_id):
    """Manual endpoint to complete a payment (for testing only)"""
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin:
        return jsonify({"error": "Admin only"}), 403
    
    # Simulate Lipana success callback
    callback_data = {
        "event": "transaction.success",
        "data": {
            "transactionId": transaction_id,
            "status": "success",
            "amount": 10,
            "phone": "254711847919",
            "mpesaReceiptNumber": f"TEST{transaction_id[-8:]}"
        }
    }
    
    try:
        with app.test_request_context(
            '/v1/payments/lipana-callback',
            method='POST',
            json=callback_data
        ):
            response = lipana_callback()
            return jsonify({
                "message": "Test callback processed",
                "result": response
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# TV AUTH
# ============================================

DEVICE_CODE_TTL_MINUTES = 5

@app.post("/v1/auth/verify-tv-code")
def verify_tv_code():
    """Called by mobile app to approve a code shown on TV"""
    uid, is_admin, decoded, err, code = require_auth()
    if err:
        return err, code

    try:
        data = request.json
        device_code = data.get("code", "").upper().strip()
        
        if not device_code:
            return jsonify({"error": "Code is required"}), 400

        code_ref = db.collection('device_auth_requests').document(device_code)
        doc = code_ref.get()
        
        if not doc.exists:
            return jsonify({"error": "Code not found or expired"}), 404
            
        doc_data = doc.to_dict()
        created_at = doc_data.get('createdAt')
        
        if not created_at:
            return jsonify({"error": "Invalid code data"}), 400
            
        # Check expiry
        now = datetime.utcnow()
        if now > created_at + timedelta(minutes=DEVICE_CODE_TTL_MINUTES):
            code_ref.delete()
            return jsonify({"error": "Code has expired"}), 403

        if doc_data.get('status') != 'pending':
            return jsonify({"error": "Code already used or invalid"}), 400

        # Create custom token
        custom_token = auth.create_custom_token(uid)
        
        if isinstance(custom_token, bytes):
            custom_token = custom_token.decode('utf-8')

        # Update Firestore
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

# ============================================
# TITLE LOCK
# ============================================
def build_lock_key(category: str, normalized_title: str, dj_name: str | None = None, dj_names: list[str] | None = None):
    """
    Build a unique lock key:
    - Movies/Series: normalized_title + optional dj_name
    - Collections: normalized_title + sorted list of dj_names
    """
    base = normalized_title.lower().replace(" ", "_")

    if category == "collections" and dj_names:
        dj_slug = "_".join(sorted([dj.lower().replace(" ", "_") for dj in dj_names]))
        return f"{base}__{dj_slug}"
    
    if category in ["movies", "series"] and dj_name:
        return f"{base}__{dj_name.lower().replace(' ', '_')}"

    return base

@app.post("/admin/title-lock/acquire")
def acquire_title_lock():
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin:
        return jsonify({"error": "Admin only"}), 403

    data = request.json or {}
    category = data.get("category")
    normalized_title = data.get("normalizedTitle")
    dj_name = data.get("djName")          # for movies/series
    dj_names = data.get("djNames")        # for collections
    exclude_doc_id = data.get("excludeDocId")

    if not category or not normalized_title:
        return jsonify({"error": "category and normalizedTitle required"}), 400
    if category not in ["movies", "series", "collections"]:
        return jsonify({"error": "Invalid category"}), 400

    lock_key = build_lock_key(category, normalized_title, dj_name, dj_names)
    doc_id = f"{category}__{lock_key}"
    lock_ref = db.collection("title_locks").document(doc_id)

    try:
        def txn(transaction):
            snap = transaction.get(lock_ref)
            if snap.exists:
                existing = snap.to_dict()
                if exclude_doc_id and existing.get("posterId") == exclude_doc_id:
                    return  # editing same document
                raise ValueError("DUPLICATE")

            transaction.set(lock_ref, {
                "category": category,
                "normalizedTitle": normalized_title,
                "djName": dj_name if category in ["movies", "series"] else None,
                "djNames": dj_names if category == "collections" else [],
                "posterId": exclude_doc_id,
                "createdBy": uid,
                "createdAt": firestore.SERVER_TIMESTAMP
            })

        db.transaction()(txn)

        return jsonify({"success": True, "lockKey": lock_key})

    except ValueError:
        return jsonify({
            "success": False,
            "reason": f"A {category[:-1]} with this title and DJ(s) already exists"
        }), 409

@app.post("/admin/title-lock/update")
def update_title_lock():
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin:
        return jsonify({"error": "Admin only"}), 403

    data = request.json or {}
    category = data.get("category")
    lock_key = data.get("lockKey")
    poster_id = data.get("posterId")

    if not category or not lock_key or not poster_id:
        return jsonify({"error": "category, lockKey, posterId required"}), 400

    doc_id = f"{category}__{lock_key}"
    lock_ref = db.collection("title_locks").document(doc_id)
    lock_ref.update({
        "posterId": poster_id,
        "updatedAt": firestore.SERVER_TIMESTAMP
    })

    return jsonify({"success": True})

@app.delete("/admin/title-lock/release")
def release_title_lock():
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin:
        return jsonify({"error": "Admin only"}), 403

    data = request.json or {}
    category = data.get("category")
    lock_key = data.get("lockKey")

    if not category or not lock_key:
        return jsonify({"error": "category and lockKey required"}), 400

    doc_id = f"{category}__{lock_key}"
    db.collection("title_locks").document(doc_id).delete()

    return jsonify({"success": True})

# ============================================
# DEBUG & HEALTH ROUTES
# ============================================

@app.get("/v1/debug/config-check")
def config_check():
    """Check environment configuration (admin only)"""
    uid, is_admin, decoded, err, code = require_auth()
    if err or not is_admin: 
        return jsonify({"error": "Admin only"}), 403

    config_status = {
        "AUTH_SECRET_LOADED": bool(AUTH_SECRET),
        "AUTH_SECRET_LENGTH": len(AUTH_SECRET) if AUTH_SECRET else 0,
        "CDN_DOMAIN": CDN_DOMAIN,
        "B2_PRIVATE_BUCKET": B2_PRIVATE_BUCKET_NAME,
        "B2_PUBLIC_BUCKET": B2_PUBLIC_BUCKET_NAME,
        "MPESA_CONFIGURED": bool(MPESA_CONSUMER_KEY and MPESA_CONSUMER_SECRET),
        "LIPANA_CONFIGURED": bool(LIPANA_SECRET_KEY),
        "LIPANA_ENVIRONMENT": LIPANA_ENVIRONMENT,
        "FIREBASE_SECRET_FILE_EXISTS": os.path.exists("/etc/secrets/serviceAccountKey.json"),
        "ENV_MODE": "Production" if os.getenv("RENDER") else "Local",
    }
    
    print(f"DEBUG CONFIG CHECK: {config_status}")
    return jsonify(config_status)


@app.get("/health")
@app.get("/")
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "cdn_enabled": bool(AUTH_SECRET),
        "cdn_domain": CDN_DOMAIN
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"\n🚀 Starting server on port {port}")
    print(f"📡 CDN Domain: {CDN_DOMAIN}")
    print(f"🔐 Auth Secret: {'✅ Configured' if AUTH_SECRET else '❌ MISSING'}")
    app.run(host="0.0.0.0", port=port)


