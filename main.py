import asyncio
import hashlib
import ipaddress
import os
import re
import socket
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

import aiofiles
import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from PIL import Image

APP_NAME = os.getenv("APP_NAME", "MikuMiku Image Host")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
STORAGE_DIR = os.getenv("STORAGE_DIR", "/tmp/mikumiku").rstrip("/")
DB_PATH = os.getenv("DB_PATH", "/tmp/mikumiku/db.sqlite").strip()
MAX_BYTES = int(os.getenv("MAX_BYTES", str(10 * 1024 * 1024)))
TTL_DAYS = int(os.getenv("TTL_DAYS", "30"))
UPLOADS_PER_MINUTE = int(os.getenv("UPLOADS_PER_MINUTE", "30"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "600"))

ALLOWED_ORIGINS = [
    "https://mikumiku.dev",
    "https://www.mikumiku.dev",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:8000",
]

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

MIME_TO_EXT = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
}
EXT_TO_MIME = {v: k for k, v in MIME_TO_EXT.items()}
EXT_TO_MIME["jpg"] = "image/jpeg"

SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9\.\-]+$")

def ts_utc() -> int:
    return int(time.time())

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS images (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            mime TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_images_expires ON images(expires_at)")
    con.commit()
    con.close()

def db_connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

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

async def sniff_mime_and_verify(path: str) -> str:
    def _verify() -> str:
        with Image.open(path) as im:
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
        raise ValueError("Unsupported image type")
    try:
        return await asyncio.to_thread(_verify)
    except Exception:
        raise HTTPException(status_code=400, detail="Unsupported or invalid image")

async def hash_file_sha256(path: str) -> str:
    def _hash() -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    return await asyncio.to_thread(_hash)

def make_id() -> str:
    return uuid.uuid4().hex[:12]

def storage_path(filename: str) -> str:
    return os.path.join(STORAGE_DIR, filename)

def compute_etag(size_bytes: int, sha256: str) -> str:
    return f'W/"{size_bytes}-{sha256[:16]}"'

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
cleanup_task: Optional[asyncio.Task] = None

async def cleanup_once():
    cutoff = ts_utc()
    con = db_connect()
    rows = con.execute("SELECT id, filename FROM images WHERE expires_at <= ?", (cutoff,)).fetchall()
    con.close()
    if not rows:
        return
    for r in rows:
        path = storage_path(r["filename"])
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
        con2 = db_connect()
        con2.execute("DELETE FROM images WHERE id = ?", (r["id"],))
        con2.commit()
        con2.close()

async def cleanup_loop():
    while True:
        try:
            await cleanup_once()
        except Exception:
            pass
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    global cleanup_task
    init_db()
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

app = FastAPI(title=APP_NAME, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

def choose_ext_from_mime(mime: str) -> str:
    if mime in MIME_TO_EXT:
        return MIME_TO_EXT[mime]
    raise HTTPException(status_code=400, detail="Unsupported image type")

def build_urls(img_id: str, ext: str):
    direct = f"{BASE_URL}/i/{img_id}.{ext}"
    page = f"{BASE_URL}/v/{img_id}"
    return direct, page

def insert_image_record(img_id: str, filename: str, mime: str, size_bytes: int, sha256: str, expires_at: int):
    con = db_connect()
    con.execute(
        "INSERT INTO images (id, filename, mime, size_bytes, sha256, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (img_id, filename, mime, size_bytes, sha256, ts_utc(), expires_at),
    )
    con.commit()
    con.close()

def get_image_record(img_id: str):
    con = db_connect()
    row = con.execute("SELECT * FROM images WHERE id = ?", (img_id,)).fetchone()
    con.close()
    return row

async def stream_download_to_file(url: str, out_path: str) -> int:
    size = 0
    timeout = httpx.Timeout(25.0, connect=10.0)
    headers = {"User-Agent": f"{APP_NAME}/1.0"}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        async with client.stream("GET", url) as r:
            r.raise_for_status()
            async with aiofiles.open(out_path, "wb") as f:
                async for chunk in r.aiter_bytes():
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise HTTPException(status_code=413, detail=f"Image too large (max {MAX_BYTES} bytes)")
                    await f.write(chunk)
    return size

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse("<h3>MikuMiku Image Host running</h3><p>Try /docs</p>")

@app.post("/upload")
async def upload(req: Request, file: UploadFile = File(...)):
    ip = (req.headers.get("x-forwarded-for") or "").split(",")[0].strip() or (req.client.host if req.client else "unknown")
    if not limiter.allow(ip):
        raise HTTPException(status_code=429, detail="Too many uploads, try again later")

    temp_path = storage_path(f"tmp_{uuid.uuid4().hex}")
    size = 0
    async with aiofiles.open(temp_path, "wb") as f:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
                raise HTTPException(status_code=413, detail=f"Image too large (max {MAX_BYTES} bytes)")
            await f.write(chunk)

    mime = await sniff_mime_and_verify(temp_path)
    ext = choose_ext_from_mime(mime)
    sha256 = await hash_file_sha256(temp_path)

    img_id = make_id()
    final_name = f"{img_id}.{ext}"
    os.replace(temp_path, storage_path(final_name))

    expires_at = int((now_utc() + timedelta(days=TTL_DAYS)).timestamp())
    insert_image_record(img_id, final_name, mime, size, sha256, expires_at)

    direct, page = build_urls(img_id, ext)
    return JSONResponse({"id": img_id, "direct_url": direct, "page_url": page, "mime": mime, "size_bytes": size})

@app.post("/fetch")
async def fetch(req: Request, url: str = Form(...)):
    ip = (req.headers.get("x-forwarded-for") or "").split(",")[0].strip() or (req.client.host if req.client else "unknown")
    if not limiter.allow(ip):
        raise HTTPException(status_code=429, detail="Too many uploads, try again later")

    url, _ = validate_remote_url(url)
    temp_path = storage_path(f"tmp_{uuid.uuid4().hex}")

    try:
        size = await stream_download_to_file(url, temp_path)
        mime = await sniff_mime_and_verify(temp_path)
        ext = choose_ext_from_mime(mime)
        sha256 = await hash_file_sha256(temp_path)

        img_id = make_id()
        final_name = f"{img_id}.{ext}"
        os.replace(temp_path, storage_path(final_name))

        expires_at = int((now_utc() + timedelta(days=TTL_DAYS)).timestamp())
        insert_image_record(img_id, final_name, mime, size, sha256, expires_at)

        direct, page = build_urls(img_id, ext)
        return JSONResponse({"id": img_id, "direct_url": direct, "page_url": page, "mime": mime, "size_bytes": size})
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass

@app.get("/v/{img_id}", response_class=HTMLResponse)
async def view(img_id: str):
    row = get_image_record(img_id)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    ext = row["filename"].split(".")[-1].lower()
    direct, _ = build_urls(img_id, ext)
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
    row = get_image_record(img_id)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")

    path = storage_path(row["filename"])
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Not found")

    etag
