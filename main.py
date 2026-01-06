import asyncio
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional, Tuple

import httpx
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from PIL import Image
from pymongo import ASCENDING, DESCENDING

APP_NAME = os.getenv("APP_NAME", "MikuMiku Image Host")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
MAX_BYTES = int(os.getenv("MAX_BYTES", str(10 * 1024 * 1024)))
TTL_DAYS = int(os.getenv("TTL_DAYS", "30"))
UPLOADS_PER_MINUTE = int(os.getenv("UPLOADS_PER_MINUTE", "30"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "600"))

MONGO_URL = os.getenv("MONGO_URL", "").strip()
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "mikumiku_image_host").strip()

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "").strip()
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "1").strip() not in ("0", "false", "False", "")

PBKDF2_ITERATIONS = int(os.getenv("APIKEY_PBKDF2_ITERS", "210000"))
PBKDF2_SALT_BYTES = int(os.getenv("APIKEY_SALT_BYTES", "16"))

ALLOWED_ORIGINS = [
    "https://mikumiku.dev",
    "https://www.mikumiku.dev",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:8000",
]

MIME_TO_EXT = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
}
EXT_TO_MIME = {v: k for k, v in MIME_TO_EXT.items()}
EXT_TO_MIME["jpg"] = "image/jpeg"
EXT_TO_MIME["jpeg"] = "image/jpeg"

SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9\.\-]+$")
ID_RE = re.compile(r"^[a-f0-9]{12}$", re.IGNORECASE)
KEY_RE = re.compile(r"^mk_([A-Za-z0-9]{12})_([A-Za-z0-9\-_]{32,})$")

def ts_utc() -> int:
    return int(time.time())

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def make_id12() -> str:
    return uuid.uuid4().hex[:12]

def compute_etag(size_bytes: int, sha256: str) -> str:
    return f'W/"{size_bytes}-{sha256[:16]}"'

def build_urls(img_id: str, ext: str):
    direct = f"{BASE_URL}/i/{img_id}.{ext}"
    page = f"{BASE_URL}/v/{img_id}"
    return direct, page

def ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False

def resolve_public_ips(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    found_any = False
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ip = sockaddr[0]
        elif family == socket.AF_INET6:
            ip = sockaddr[0]
        else:
            continue
        found_any = True
        if not ip_is_public(ip):
            return False
    return found_any

def validate_remote_url(raw: str) -> Tuple[str, str]:
    raw = raw.strip()
    if len(raw) > 2048:
        raise HTTPException(status_code=400, detail="URL too long")
    parsed = httpx.URL(raw)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only http/https allowed")
    host = parsed.host or ""
    if not host or not SAFE_HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="Invalid host")
    if not resolve_public_ips(host):
        raise HTTPException(status_code=400, detail="Host not allowed")
    return raw, host

def choose_ext_from_mime(mime: str) -> str:
    if mime in MIME_TO_EXT:
        return MIME_TO_EXT[mime]
    raise HTTPException(status_code=400, detail="Unsupported image type")

def ext_from_filename(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    if "." not in name:
        return None
    ext = name.rsplit(".", 1)[-1].lower().strip()
    if ext == "jpeg":
        ext = "jpg"
    if ext in ("jpg", "png", "gif", "webp"):
        return ext
    return None

def normalize_ext_for_mime(uploaded_ext: Optional[str], detected_mime: str) -> str:
    detected_ext = choose_ext_from_mime(detected_mime)
    if not uploaded_ext:
        return detected_ext
    if EXT_TO_MIME.get(uploaded_ext) == detected_mime:
        return uploaded_ext
    return detected_ext

def sniff_mime_and_verify_bytes(data: bytes) -> str:
    try:
        with Image.open(BytesIO(data)) as im:
            im.verify()
            fmt = (im.format or "").upper()
        if fmt == "JPEG":
            return "image/jpeg"
        if fmt == "PNG":
            return "image/png"
        if fmt == "GIF":
            return "image/gif"
        if fmt == "WEBP":
            return "image/webp"
        raise ValueError("Unsupported")
    except Exception:
        raise HTTPException(status_code=400, detail="Unsupported or invalid image")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def pbkdf2_hash(secret: str, salt: bytes, iters: int) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iters, dklen=32)
    return b64url(dk)

def parse_bearer(req: Request) -> str:
    auth = (req.headers.get("authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing API key")
    key = auth.split(" ", 1)[1].strip()
    if not key:
        raise HTTPException(status_code=401, detail="Missing API key")
    return key

def parse_key(raw: str) -> Tuple[str, str]:
    m = KEY_RE.match(raw.strip())
    if not m:
        raise HTTPException(status_code=401, detail="Invalid API key format")
    return m.group(1), m.group(2)

def generate_key() -> Tuple[str, str, str]:
    key_id = make_id12()
    secret = secrets.token_urlsafe(32)
    raw = f"mk_{key_id}_{secret}"
    return raw, key_id, secret

class SlidingWindowLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.buckets: dict[str, list[int]] = {}

    def allow(self, key: str) -> bool:
        t = ts_utc()
        window_start = t - 60
        arr = self.buckets.get(key, [])
        arr = [x for x in arr if x >= window_start]
        if len(arr) >= self.per_minute:
            self.buckets[key] = arr
            return False
        arr.append(t)
        self.buckets[key] = arr
        return True

limiter_ip = SlidingWindowLimiter(UPLOADS_PER_MINUTE)

mongo_client: Optional[AsyncIOMotorClient] = None
db = None
fs: Optional[AsyncIOMotorGridFSBucket] = None
cleanup_task: Optional[asyncio.Task] = None

async def ensure_indexes():
    await db.images.create_index([("expires_at", ASCENDING)])
    await db.images.create_index([("created_at", ASCENDING)])

    await db.api_keys.create_index(
        [("key_id", ASCENDING)],
        unique=True,
        partialFilterExpression={"key_id": {"$type": "string"}},
        name="key_id_unique_string",
    )
    await db.api_keys.create_index([("revoked", ASCENDING)])
    await db.api_keys.create_index([("created_at", DESCENDING)])
    await db.api_keys.create_index([("last_used_at", DESCENDING)])
    await db.api_keys.create_index([("expires_at", ASCENDING)])


async def cleanup_once():
    cutoff = ts_utc()
    cursor = db.images.find({"expires_at": {"$lte": cutoff}}, {"_id": 1, "file_id": 1})
    doomed = await cursor.to_list(length=2000)
    if not doomed:
        return
    for d in doomed:
        try:
            await fs.delete(d["file_id"])
        except Exception:
            pass
        await db.images.delete_one({"_id": d["_id"]})

async def cleanup_loop():
    while True:
        try:
            await cleanup_once()
        except Exception:
            pass
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    global mongo_client, db, fs, cleanup_task
    if not MONGO_URL:
        raise RuntimeError("MONGO_URL is not set")
    mongo_client = AsyncIOMotorClient(MONGO_URL)
    db = mongo_client[MONGO_DB_NAME]
    fs = AsyncIOMotorGridFSBucket(db)
    await ensure_indexes()
    cleanup_task = asyncio.create_task(cleanup_loop())
    try:
        yield
    finally:
        if cleanup_task:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except Exception:
                pass
        if mongo_client:
            mongo_client.close()

app = FastAPI(title=APP_NAME, lifespan=lifespan)

APP_VERSION = os.getenv("APP_VERSION", "dev")

@app.get("/debug/version")
async def debug_version():
    return JSONResponse({"version": APP_VERSION})


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

def client_ip(req: Request) -> str:
    ip = (req.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    return ip or (req.client.host if req.client else "unknown")

async def read_uploadfile_limited(file: UploadFile) -> bytes:
    total = 0
    chunks = []
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Image too large (max {MAX_BYTES} bytes)")
        chunks.append(chunk)
    return b"".join(chunks)

async def download_limited(url: str) -> bytes:
    size = 0
    buf = bytearray()
    timeout = httpx.Timeout(25.0, connect=10.0)
    headers = {"User-Agent": f"{APP_NAME}/1.0"}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        async with client.stream("GET", url) as r:
            r.raise_for_status()
            async for chunk in r.aiter_bytes():
                if not chunk:
                    continue
                size += len(chunk)
                if size > MAX_BYTES:
                    raise HTTPException(status_code=413, detail=f"Image too large (max {MAX_BYTES} bytes)")
                buf.extend(chunk)
    return bytes(buf)

async def store_image_bytes(data: bytes, uploaded_ext: Optional[str]) -> dict:
    detected_mime = sniff_mime_and_verify_bytes(data)
    ext = normalize_ext_for_mime(uploaded_ext, detected_mime)
    size = len(data)
    sha = sha256_bytes(data)
    img_id = make_id12()
    expires_at = int((now_utc() + timedelta(days=TTL_DAYS)).timestamp())

    file_id = await fs.upload_from_stream(
        filename=f"{img_id}.{ext}",
        source=BytesIO(data),
        metadata={"id": img_id, "ext": ext, "mime": detected_mime, "sha256": sha, "size_bytes": size},
    )

    await db.images.insert_one(
        {
            "_id": img_id,
            "file_id": file_id,
            "ext": ext,
            "mime": detected_mime,
            "size_bytes": size,
            "sha256": sha,
            "created_at": ts_utc(),
            "expires_at": expires_at,
        }
    )

    direct, page = build_urls(img_id, ext)
    return {"id": img_id, "direct_url": direct, "page_url": page, "mime": detected_mime, "size_bytes": size}

async def require_admin(req: Request):
    if not ADMIN_SECRET:
        raise HTTPException(status_code=500, detail="Admin not configured")
    supplied = (req.headers.get("x-admin-secret") or "").strip()
    if not supplied or supplied != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

async def verify_api_key(req: Request):
    if not REQUIRE_API_KEY:
        return {"key_id": None, "scopes": ["upload", "fetch"], "rate_per_minute": UPLOADS_PER_MINUTE}

    raw = parse_bearer(req)
    key_id, secret = parse_key(raw)

    doc = await db.api_keys.find_one({"key_id": key_id})
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if doc.get("revoked"):
        raise HTTPException(status_code=401, detail="API key revoked")

    expires_at = doc.get("expires_at")
    if expires_at is not None and isinstance(expires_at, int) and ts_utc() >= expires_at:
        raise HTTPException(status_code=401, detail="API key expired")

    salt_b64 = doc.get("salt_b64")
    iters = int(doc.get("iters") or PBKDF2_ITERATIONS)
    stored_hash = doc.get("hash_b64")
    if not salt_b64 or not stored_hash:
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid API key")

    computed = pbkdf2_hash(secret, salt, iters)
    if not hmac.compare_digest(computed, stored_hash):
        raise HTTPException(status_code=401, detail="Invalid API key")

    scopes = doc.get("scopes") or ["upload", "fetch"]
    rate_per_minute = int(doc.get("rate_per_minute") or UPLOADS_PER_MINUTE)

    ip = client_ip(req)
    if rate_per_minute > 0:
        k = f"key:{key_id}"
        limiter_key = SlidingWindowLimiter(rate_per_minute)
        if not limiter_key.allow(k):
            raise HTTPException(status_code=429, detail="Too many requests for this API key")

    await db.api_keys.update_one(
        {"key_id": key_id},
        {"$set": {"last_used_at": ts_utc(), "last_used_ip": ip}},
    )

    return {"key_id": key_id, "scopes": scopes, "rate_per_minute": rate_per_minute}

def require_scope(scopes: list[str], needed: str):
    if needed not in scopes:
        raise HTTPException(status_code=403, detail="Insufficient scope")

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse("<h3>MikuMiku Image Host running</h3><p>Try /docs</p>")

@app.post("/upload")
async def upload(req: Request, file: UploadFile = File(...), k=Depends(verify_api_key)):
    ip = client_ip(req)
    if not limiter_ip.allow(ip):
        raise HTTPException(status_code=429, detail="Too many uploads, try again later")
    require_scope(k["scopes"], "upload")
    data = await read_uploadfile_limited(file)
    uploaded_ext = ext_from_filename(file.filename)
    out = await store_image_bytes(data, uploaded_ext)
    return JSONResponse(out)

@app.post("/fetch")
async def fetch(req: Request, url: str = Form(...), k=Depends(verify_api_key)):
    ip = client_ip(req)
    if not limiter_ip.allow(ip):
        raise HTTPException(status_code=429, detail="Too many uploads, try again later")
    require_scope(k["scopes"], "fetch")
    url, _h = validate_remote_url(url)
    data = await download_limited(url)
    out = await store_image_bytes(data, None)
    return JSONResponse(out)

@app.get("/v/{img_id}", response_class=HTMLResponse)
async def view(img_id: str):
    if not ID_RE.match(img_id):
        raise HTTPException(status_code=404, detail="Not found")
    row = await db.images.find_one({"_id": img_id})
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    direct, _ = build_urls(img_id, row["ext"])
    html = f"""
    <!doctype html>
    <html><head><meta charset="utf-8"><title>{APP_NAME} - {img_id}</title></head>
    <body style="font-family: system-ui; max-width: 900px; margin: 32px auto; padding: 0 16px;">
      <h2>{APP_NAME}</h2>
      <p><a href="{direct}">{direct}</a></p>
      <img src="{direct}" style="max-width:100%; height:auto; border-radius: 12px;">
    </body></html>
    """
    return HTMLResponse(html)

@app.get("/i/{img_file}")
async def image(img_file: str, req: Request):
    m = re.fullmatch(r"([a-f0-9]{12})\.(jpg|png|gif|webp)", img_file.lower())
    if not m:
        raise HTTPException(status_code=404, detail="Not found")
    img_id = m.group(1)
    row = await db.images.find_one({"_id": img_id})
    if not row:
        raise HTTPException(status_code=404, detail="Not found")

    etag = compute_etag(row["size_bytes"], row["sha256"])
    if req.headers.get("if-none-match") == etag:
        return JSONResponse(status_code=304)

    grid_out = await fs.open_download_stream(row["file_id"])

    async def gen():
        while True:
            chunk = await grid_out.readchunk()
            if not chunk:
                break
            yield chunk

    headers = {
        "ETag": etag,
        "Cache-Control": "public, max-age=31536000, immutable",
        "Content-Length": str(row["size_bytes"]),
    }
    return StreamingResponse(gen(), media_type=row["mime"], headers=headers)

@app.post("/admin/keys/create")
async def admin_create_key(req: Request, name: str = Form("sharex"), _=Depends(require_admin)):
    try:
        if db is None:
            raise RuntimeError("db is None (Mongo not initialized)")
        raw = "mk_" + secrets.token_urlsafe(32)
        key_hash = sha256_hex(raw)
        doc = {
            "key_hash": key_hash,
            "name": (name or "key")[:64],
            "revoked": False,
            "created_at": ts_utc(),
        }
        await db.api_keys.insert_one(doc)
        return JSONResponse({"api_key": raw})
    except Exception as e:
        return JSONResponse(
            {"error": type(e).__name__, "message": str(e)},
            status_code=500,
        )


@app.get("/admin/keys/list")
async def admin_list_keys(req: Request, limit: int = 100, _=Depends(require_admin)):
    limit = max(1, min(int(limit or 100), 500))
    cursor = db.api_keys.find({}, {"_id": 0, "salt_b64": 0, "hash_b64": 0}).sort("created_at", DESCENDING).limit(limit)
    items = await cursor.to_list(length=limit)
    return JSONResponse({"keys": items})

@app.post("/admin/keys/revoke")
async def admin_revoke_key(req: Request, key_id: str = Form(...), _=Depends(require_admin)):
    key_id = (key_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{12}", key_id):
        raise HTTPException(status_code=400, detail="Invalid key_id")
    r = await db.api_keys.update_one({"key_id": key_id}, {"$set": {"revoked": True, "revoked_at": ts_utc()}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Key not found")
    return JSONResponse({"revoked": True, "key_id": key_id})

@app.post("/admin/keys/revoke-raw")
async def admin_revoke_raw(req: Request, api_key: str = Form(...), _=Depends(require_admin)):
    raw = (api_key or "").strip()
    key_id, _secret = parse_key(raw)
    r = await db.api_keys.update_one({"key_id": key_id}, {"$set": {"revoked": True, "revoked_at": ts_utc()}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Key not found")
    return JSONResponse({"revoked": True, "key_id": key_id})

@app.get("/debug/headers")
async def debug_headers(req: Request):
    return JSONResponse({
        "auth": req.headers.get("authorization"),
        "admin": req.headers.get("x-admin-secret"),
        "origin": req.headers.get("origin"),
        "host": req.headers.get("host"),
    })
