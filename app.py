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

# --- BACKBLAZE CONFIG ---
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")
B2_BUCKET_ID = os.getenv("B2_BUCKET_ID")

# --- SIGNED URL TTLs ---
MOVIE_TTL = 14400        # 4 hours 
SERIES_TTL = 86400       # 24 hours 
COLLECTION_TTL = 86400   # 24 hours 

MAX_THREADS = 10
# TTL is 10 minutes (600s), ensuring it's far less than any B2 URL expiry (min 4h)
PER_USER_RESPONSE_TTL = 600 

LONGEST_TTL = max(MOVIE_TTL, SERIES_TTL, COLLECTION_TTL) 

# Initialize Firebase
try:
    cred = credentials.Certificate("/etc/secrets/serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
except Exception:
    print("Warning: Failed to load service account key. Using default credentials.")
    firebase_admin.initialize_app()
    
db = firestore.client()
app = Flask(__name__)
CORS(app)

# --- CACHING LAYERS ---
b2_auth_cache: Dict[str, Any] = {
    "expires": datetime.min,
    "data": None
}
signed_url_cache = TTLCache(maxsize=5000, ttl=LONGEST_TTL) 
per_user_response_cache = TTLCache(maxsize=1000, ttl=PER_USER_RESPONSE_TTL)


# --- AUTHENTICATION & ENTITLEMENT (Updated) ---

def require_auth() -> Tuple[Optional[str], Optional[Response], Optional[int]]:
    """Verifies Firebase ID token and returns UID."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None, jsonify({"error": "Missing token"}), 401
    try:
        token = header.split(" ", 1)[1]
        decoded = auth.verify_id_token(token)
        uid = decoded["uid"] 
        request.uid = uid 
        return uid, None, None
    except auth.InvalidIdToken:
        return None, jsonify({"error": "Invalid token"}), 401
    except Exception:
        return None, jsonify({"error": "Authentication failed"}), 401


def assert_entitlement(uid: str, content_id: str, content_type: str, series_id: Optional[str] = None, movie_id: Optional[str] = None) -> None:
    """
    Checks if the user is entitled to content.
    content_id is the primary ID (Movie ID, Series ID, Collection ID).
    movie_id and series_id/season_id are used for complex entitlement checks.
    """
    
    # Base query for user purchases
    purchases_ref = db.collection("users").document(uid).collection("purchases")\
        .where("purchaseStatus", "==", "complete")

    if content_type == "season":
        # content_id here is the season's document ID (e.g., 's01', 's02'), and series_id is required
        if not series_id:
            raise ValueError("Series ID is required for season entitlement check.")
            
        snaps = purchases_ref\
            .where("itemType", "in", ["series", "season"])\
            .get()
            
        # Entitled if user bought the whole series OR the specific season
        is_entitled = any(s.to_dict()["itemId"] == series_id and s.to_dict()["itemType"] == "series"
                          or s.to_dict()["itemId"] == content_id and s.to_dict()["itemType"] == "season"
                          for s in snaps)
                          
        if not is_entitled:
            raise PermissionError(f"Not entitled to season {content_id} in series {series_id}")

    elif content_type == "collectionMovie":
        # content_id is the Collection ID, movie_id is the specific Movie ID
        if not movie_id:
            raise ValueError("movie_id is required for collectionMovie entitlement check.")

        snaps = purchases_ref.where("itemType", "in", ["collection", "collectionMovie"]).get()

        # Entitled if user bought the collection (itemId=Collection ID) OR the single movie (itemId=Movie ID)
        is_entitled = any(
            (s.to_dict()["itemId"] == content_id and s.to_dict()["itemType"] == "collection") or
            (s.to_dict()["itemId"] == movie_id and s.to_dict()["itemType"] == "collectionMovie")
            for s in snaps
        )

        if not is_entitled:
            raise PermissionError(f"Not entitled to movie {movie_id} (collection ID {content_id})")

    else:
        # Standard check for: movie, series, collection
        snap = purchases_ref\
            .where("itemId", "==", content_id)\
            .where("itemType", "==", content_type)\
            .limit(1).get()
        if not snap:
            raise PermissionError(f"Not purchased: {content_type} ID {content_id}")

# --- BACKBLAZE B2 AUTH & SIGNING (Unchanged) ---
def authorize_b2() -> Dict[str, Any]:
    global b2_auth_cache
    if datetime.utcnow() < b2_auth_cache["expires"]:
        return b2_auth_cache["data"]

    r = requests.get(
        "https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
        auth=(B2_KEY_ID, B2_APP_KEY),
        timeout=30 
    )
    r.raise_for_status()
    data = r.json()

    b2_auth_cache["data"] = data
    b2_auth_cache["expires"] = datetime.utcnow() + timedelta(hours=23)
    return data

def sign_b2(file_path: str, expires: int) -> str:
    if file_path in signed_url_cache:
        return signed_url_cache[file_path]
    try:
        auth_data = authorize_b2()
        r = requests.post(
            f"{auth_data['apiUrl']}/b2api/v2/b2_get_download_authorization",
            headers={"Authorization": auth_data["authorizationToken"]},
            json={
                "bucketId": B2_BUCKET_ID,
                "fileNamePrefix": file_path,
                "validDurationInSeconds": expires
            },
            timeout=10
        )
        r.raise_for_status()
        token = r.json()["authorizationToken"]
        url = f"{auth_data['downloadUrl']}/file/{B2_BUCKET_NAME}/{file_path}?Authorization={token}"
        signed_url_cache[file_path] = url
        return url
    except requests.RequestException as e:
        print(f"B2 signing failed for {file_path}: {e}")
        raise

# --- FIRESTORE HELPERS (Unchanged) ---

def get_movie(movie_id: str) -> Dict[str, Any]:
    doc = db.collection("movies").document(movie_id).get()
    if not doc.exists:
        raise FileNotFoundError(f"Movie with ID {movie_id} not found.")
    return doc.to_dict()

def get_collection_movies(collection_id: str) -> List[Dict[str, Any]]:
    doc = db.collection("collections").document(collection_id).get()
    if not doc.exists:
        raise FileNotFoundError(f"Collection with ID {collection_id} not found.")
    
    return doc.to_dict().get("movies", [])

def get_episodes(series_id: str, season_doc_id: str) -> List[Dict[str, Any]]:
    snaps = (
        db.collection("series")
        .document(series_id)
        .collection("seasons")
        .document(season_doc_id)
        .collection("episodes")
        .where("status", "==", "public")
        .get()
    )
    return [s.to_dict() for s in snaps]


# --- API ENDPOINTS (Updated for new assert_entitlement signature) ---

@app.post("/sign/movie")
def sign_movie():
    uid, err, code = require_auth()
    if err: return err, code

    try:
        movie_id = request.json["movieId"]
        
        cache_key = f"movie_{uid}_{movie_id}"
        if cache_key in per_user_response_cache:
            return per_user_response_cache[cache_key]

        # Check Entitlement
        assert_entitlement(uid, movie_id, "movie")
        movie = get_movie(movie_id)
        
        response_data = {
            "url": sign_b2(movie["videoPath"], MOVIE_TTL),
            "expiresIn": MOVIE_TTL
        }
        
        response = jsonify(response_data)
        per_user_response_cache[cache_key] = response
        return response

    except KeyError:
        return jsonify({"error": "Missing 'movieId' in request body"}), 400
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception:
        return jsonify({"error": "Internal server error during movie signing"}), 500


@app.post("/sign/series")
def sign_series():
    """Signs all episode files for a given season, accepting separate IDs."""
    uid, err, code = require_auth()
    if err: return err, code

    try:
        series_id = request.json["seriesId"]
        season_doc_id = request.json["seasonId"] 
        
        cache_key = f"series_{uid}_{series_id}_{season_doc_id}"
        if cache_key in per_user_response_cache:
            return per_user_response_cache[cache_key]

        # Check Entitlement (season_doc_id is the content_id for season checks)
        assert_entitlement(uid, season_doc_id, "season", series_id=series_id)

        episodes = get_episodes(series_id, season_doc_id)
        if not episodes:
             return jsonify({"error": "No public episodes found for this season."}), 404

        with ThreadPoolExecutor(MAX_THREADS) as ex:
            data = list(ex.map(
                lambda ep: {
                    "title": ep.get("title", "Episode"),
                    "episodeId": ep.get("episodeId", "N/A"),
                    "url": sign_b2(ep["videoPath"], SERIES_TTL)
                },
                episodes
            ))

        response_data = {
            "seriesId": series_id,
            "seasonId": season_doc_id,
            "episodes": data,
            "expiresIn": SERIES_TTL
        }
        
        response = jsonify(response_data)
        per_user_response_cache[cache_key] = response
        return response
        
    except KeyError:
        return jsonify({"error": "Missing 'seriesId' or 'seasonId' in request body"}), 400
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Internal server error during series signing"}), 500


@app.post("/sign/collection")
def sign_collection():
    """Signs all movie files in a collection with per-user caching."""
    uid, err, code = require_auth()
    if err: return err, code

    try:
        collection_id = request.json["collectionId"]
        
        cache_key = f"collection_{uid}_{collection_id}"
        if cache_key in per_user_response_cache:
            return per_user_response_cache[cache_key]

        # Check Entitlement
        assert_entitlement(uid, collection_id, "collection")

        movies = get_collection_movies(collection_id)
        if not movies:
             return jsonify({"error": "Collection found, but contains no movies."}), 404

        with ThreadPoolExecutor(MAX_THREADS) as ex:
            data = list(ex.map(
                lambda m: {
                    "movieId": m.get("movieId", "N/A"),
                    "url": sign_b2(m["videoPath"], COLLECTION_TTL)
                },
                movies
            ))

        response_data = {
            "collectionId": collection_id,
            "movies": data,
            "expiresIn": COLLECTION_TTL
        }
        
        response = jsonify(response_data)
        per_user_response_cache[cache_key] = response
        return response
        
    except KeyError:
        return jsonify({"error": "Missing 'collectionId' in request body"}), 400
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception:
        return jsonify({"error": "Internal server error during collection signing"}), 500


@app.post("/sign/collection/movie")
def sign_collection_movie():
    """Signs a single movie file, checking entitlement via collection OR single movie purchase."""
    uid, err, code = require_auth()
    if err: return err, code

    try:
        movie_id = request.json["movieId"]
        collection_id = request.json.get("collectionId")

        if not collection_id:
             return jsonify({"error": "Missing 'collectionId' in request body"}), 400

        cache_key = f"collmovie_{uid}_{movie_id}_{collection_id}"
        if cache_key in per_user_response_cache:
            return per_user_response_cache[cache_key]

        # Check Entitlement (collection_id is the primary content_id, movie_id is the secondary check)
        assert_entitlement(uid, collection_id, "collectionMovie", movie_id=movie_id) 

        movie_data = get_movie(movie_id) 

        response_data = {
            "url": sign_b2(movie_data["videoPath"], MOVIE_TTL),
            "expiresIn": MOVIE_TTL
        }
        
        response = jsonify(response_data)
        per_user_response_cache[cache_key] = response
        return response
        
    except KeyError as e:
        return jsonify({"error": f"Missing required field: {e}"}), 400
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception:
        return jsonify({"error": "Internal server error during collection movie signing"}), 500


@app.get("/")
def health():
    """Health check endpoint."""
    return {"status": "ok"}
