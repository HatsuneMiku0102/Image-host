import asyncio
import hashlib
import ipaddress
import os
import re
import socket
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from PIL import Image
from pymongo import ASCENDING

APP_NAME = os.getenv("APP_NAME", "MikuMiku Image Host")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
MAX_BYTES = int(os.getenv("MAX_BYTES", str(10 * 1024 * 1024)))
TTL_DAYS = int(os.getenv("TTL_DAYS", "30"))
UPLOADS_PER_MINUTE = int(os.getenv("UPLOADS_PER_MINUTE", "30"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "600"))

MONGO_URL = os.getenv("MONGO_URL", "").strip()
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "mikumiku_image_host").strip()

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

def ts_utc() -> int:
    return int(time.time())

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def make_id() -> str:
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
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only http/https allowed")
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")
    host = parsed.hostname or ""
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

class RateLimiter:
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

limiter = RateLimiter(UPLOADS_PER_MINUTE)

mongo_client: Optional[AsyncIOMotorClient] = None
db = None
fs: Optional[AsyncIOMotorGridFSBucket] = None
cleanup_task: Optional[asyncio.Task] = None

async def ensure_indexes():
    await db.images.create_index([("expires_at", ASCENDING)])
    await db.images.create_index([("created_at", ASCENDING)])

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

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

def client_ip(req: Request) -> str:
    ip = (req.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    return ip or (req.client.host if req.client else "unknown")

async def store_image_bytes(data: bytes, uploaded_ext: Optional[str]) -> dict:
    detected_mime = sniff_mime_and_verify_bytes(data)
    ext = normalize_ext_for_mime(uploaded_ext, detected_mime)
    size = len(data)
    sha = sha256_bytes(data)
    img_id = make_id()
    expires_at = int((now_utc() + timedelta(days=TTL_DAYS)).timestamp())
    file_id = await fs.upload_from_stream(
        filename=f"{img_id}.{ext}",
        source=BytesIO(data),
        metadata={"id": img_id, "ext": ext, "mime": detected_mime, "sha256": sha, "size_bytes": size},
    )
    doc = {
        "_id": img_id,
        "file_id": file_id,
        "ext": ext,
        "mime": detected_mime,
        "size_bytes": size,
        "sha256": sha,
        "created_at": ts_utc(),
        "expires_at": expires_at,
    }
    await db.images.insert_one(doc)
    direct, page = build_urls(img_id, ext)
    return {"id": img_id, "direct_url": direct, "page_url": page, "mime": detected_mime, "size_bytes": size}

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse("<h3>MikuMiku Image Host running</h3><p>Try /docs</p>")

@app.post("/upload")
async def upload(req: Request, file: UploadFile = File(...)):
    ip = client_ip(req)
    if not limiter.allow(ip):
        raise HTTPException(status_code=429, detail="Too many uploads, try again later")
    data = await read_uploadfile_limited(file)
    uploaded_ext = ext_from_filename(file.filename)
    out = await store_image_bytes(data, uploaded_ext)
    return JSONResponse(out)

@app.post("/fetch")
async def fetch(req: Request, url: str = Form(...)):
    ip = client_ip(req)
    if not limiter.allow(ip):
        raise HTTPException(status_code=429, detail="Too many uploads, try again later")
    url, _ = validate_remote_url(url)
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
