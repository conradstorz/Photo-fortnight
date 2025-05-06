
# -*- coding: utf-8 -*-
import os
import json
import uuid
import time
import base64
import shutil
import hashlib
import openai
import datetime
import secrets
from pathlib import Path
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image, ExifTags
from loguru import logger
import clamd
import bcrypt
import io

# Setup logs directory and logger
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
logger.add(LOG_DIR / "server.log", rotation="500 KB", retention="7 days", level="DEBUG")

app = FastAPI()

# Directories
UPLOAD_DIR = Path("uploads")
THUMBNAIL_DIR = UPLOAD_DIR / "thumbnails"
STAGING_DIR = Path("staging")
UPLOAD_DIR.mkdir(exist_ok=True)
THUMBNAIL_DIR.mkdir(exist_ok=True)
STAGING_DIR.mkdir(exist_ok=True)

# Files
LOG_FILE = Path("upload_log.jsonl")
DECISIONS_LOG = Path("upload_decisions.jsonl")
USER_DB = Path("users.json")

# Mount static
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Configuration
COOKIE_NAME = "visitor_id"
SESSION_COOKIE = "session_id"
SESSIONS = {}
ALLOWED_FORMATS = {"jpeg", "png"}
MAX_UPLOAD_SIZE = 10 * 1024 * 1024
UPLOAD_COOLDOWN_SECONDS = 60
BLACKLIST_DURATION_SECONDS = 30 * 24 * 60 * 60

# Globals
last_upload_times = {}
blacklisted_ips = {}
clamd_client = clamd.ClamdUnixSocket()
openai.api_key = os.getenv("OPENAI_API_KEY")

# Admin passcode
admin_passcode = None
if not USER_DB.exists():
    admin_passcode = ''.join(secrets.choice("0123456789") for _ in range(6))
    logger.info(f"[Admin Setup] Passcode: {admin_passcode}")

# ----------- Utilities -----------
def extract_exif(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        return {ExifTags.TAGS.get(k, k): v for k, v in exif_data.items()} if exif_data else {}
    except Exception:
        return {}

def strip_exif(image_path):
    try:
        image = Image.open(image_path)
        data = list(image.getdata())
        clean = Image.new(image.mode, image.size)
        clean.putdata(data)
        clean.save(image_path)
    except Exception:
        pass

def create_thumbnail(image_path, thumbnail_path, size=(300, 300)):
    try:
        image = Image.open(image_path)
        image.thumbnail(size)
        image.save(thumbnail_path)
    except Exception:
        pass

def calculate_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def is_valid_image_type(file_bytes):
    try:
        img = Image.open(io.BytesIO(file_bytes))
        return img.format.lower() in ALLOWED_FORMATS
    except Exception:
        return False

def load_users():
    return json.loads(USER_DB.read_text()) if USER_DB.exists() else []

def save_users(users):
    USER_DB.write_text(json.dumps(users, indent=2))

def find_user(username):
    return next((u for u in load_users() if u["username"] == username), None)

def any_admin_exists():
    return any(u["role"] == "admin" for u in load_users())

def current_user(request: Request):
    sid = request.cookies.get(SESSION_COOKIE)
    return SESSIONS.get(sid)

def create_session(username):
    sid = str(uuid.uuid4())
    SESSIONS[sid] = username
    return sid

def save_staging_metadata(filename, client_ip, visitor_id):
    meta = {
        "client_ip": client_ip,
        "visitor_id": visitor_id,
        "upload_timestamp": datetime.datetime.utcnow().isoformat()
    }
    (STAGING_DIR / f"{filename}.meta.json").write_text(json.dumps(meta))

def load_staging_metadata(filename):
    meta_path = STAGING_DIR / f"{filename}.meta.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text())
    return {"client_ip": "unknown", "visitor_id": "unknown"}

def analyze_image(image_path):
    try:
        img_bytes = Path(image_path).read_bytes()
        base64_img = base64.b64encode(img_bytes).decode("utf-8")
        prompt = (
            "You are an expert automotive image classifier."
            " Given a car photo, respond ONLY with JSON like this:\n"
            "{\n"
            "  \"is_pornographic\": false,\n"
            "  \"car_make\": \"Toyota\",\n"
            "  \"car_model\": \"Corolla\",\n"
            "  \"car_color\": \"Red\"\n"
            "}"
        )
        response = openai.chat.completions.create(
            model="gpt-4-vision-preview",
            messages=[
                {"role": "user", "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_img}"}}
                ]}
            ],
            max_tokens=300
        )
        return json.loads(response.choices[0].message.content.strip())
    except Exception as e:
        logger.exception("[AI ERROR] Failed to analyze image")
        return {
            "is_pornographic": False,
            "car_make": None,
            "car_model": None,
            "car_color": None
        }


from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_302_FOUND

templates = Jinja2Templates(directory="templates")
TEMPLATES_DIR = Path("templates")
TEMPLATES_DIR.mkdir(exist_ok=True)

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    user = current_user(request)
    if not user or find_user(user)["role"] != "admin":
        raise HTTPException(status_code=403)
    return templates.TemplateResponse("admin_dashboard.html", {"request": request, "user": user})

@app.get("/admin/staging", response_class=HTMLResponse)
def view_staging(request: Request):
    user = current_user(request)
    if not user or find_user(user)["role"] != "admin":
        raise HTTPException(status_code=403)

    staged_files = []
    for file in STAGING_DIR.glob("*.jpg"):
        meta = load_staging_metadata(file.name)
        staged_files.append({
            "filename": file.name,
            "metadata": meta
        })

    return templates.TemplateResponse("staging_review.html", {
        "request": request,
        "files": staged_files,
        "user": user
    })

@app.post("/admin/approve")
async def approve_file(request: Request, filename: str = Form(...), note: str = Form("")):
    user = current_user(request)
    if not user or find_user(user)["role"] != "admin":
        raise HTTPException(status_code=403)

    src_path = STAGING_DIR / filename
    meta = load_staging_metadata(filename)
    hash_before = calculate_sha256(src_path)
    dest_path = UPLOAD_DIR / filename
    shutil.move(str(src_path), str(dest_path))

    hash_after = calculate_sha256(dest_path)
    if hash_before != hash_after:
        logger.error(f"Hash mismatch on move for {filename}")
        return RedirectResponse("/admin/staging", status_code=HTTP_302_FOUND)

    strip_exif(dest_path)
    create_thumbnail(dest_path, THUMBNAIL_DIR / filename)

    with DECISIONS_LOG.open("a") as logf:
        logf.write(json.dumps({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "client_ip": meta.get("client_ip"),
            "visitor_id": meta.get("visitor_id"),
            "filename": filename,
            "action": "approved",
            "admin": user,
            "sha256": hash_after,
            "mod_note": note
        }) + "\n")

    return RedirectResponse("/admin/staging", status_code=HTTP_302_FOUND)

@app.post("/admin/reject")
async def reject_file(request: Request, filename: str = Form(...), note: str = Form("")):
    user = current_user(request)
    if not user or find_user(user)["role"] != "admin":
        raise HTTPException(status_code=403)

    src_path = STAGING_DIR / filename
    meta = load_staging_metadata(filename)
    hash_before = calculate_sha256(src_path)

    src_path.unlink(missing_ok=True)

    with DECISIONS_LOG.open("a") as logf:
        logf.write(json.dumps({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "client_ip": meta.get("client_ip"),
            "visitor_id": meta.get("visitor_id"),
            "filename": filename,
            "action": "rejected",
            "admin": user,
            "sha256": hash_before,
            "mod_note": note
        }) + "\n")

    return RedirectResponse("/admin/staging", status_code=HTTP_302_FOUND)

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request,
        "admin_passcode_required": not any_admin_exists()
    })

@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...), admin_passcode: str = Form(None)):
    users = load_users()
    if find_user(username):
        raise HTTPException(status_code=400, detail="User already exists")
    role = "admin" if not any_admin_exists() and admin_passcode == admin_passcode else "user"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users.append({"username": username, "password_hash": password_hash, "role": role})
    save_users(users)
    session_id = create_session(username)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = find_user(username)
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=403, detail="Invalid credentials")
    session_id = create_session(username)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True)
    return response

@app.get("/logout")
def logout(request: Request):
    sid = request.cookies.get(SESSION_COOKIE)
    SESSIONS.pop(sid, None)
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response

@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request})

@app.post("/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    client_ip = request.client.host
    visitor_id = request.cookies.get(COOKIE_NAME, str(uuid.uuid4()))
    now = time.time()

    if client_ip in blacklisted_ips and blacklisted_ips[client_ip] > now:
        raise HTTPException(status_code=403, detail="You are blacklisted")

    last_time = last_upload_times.get(client_ip, 0)
    if now - last_time < UPLOAD_COOLDOWN_SECONDS:
        raise HTTPException(status_code=429, detail="Please wait before uploading again")

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_SIZE or not is_valid_image_type(contents):
        raise HTTPException(status_code=400, detail="Invalid file")

    temp_path = STAGING_DIR / file.filename
    temp_path.write_bytes(contents)

    # Virus scan
    try:
        if clamd_client.ping():
            result = clamd_client.instream(temp_path.open("rb"))
            if result and result["stream"][0] == "FOUND":
                temp_path.unlink()
                raise HTTPException(status_code=400, detail="Virus detected")
    except Exception as e:
        logger.warning("ClamAV scan failed: {}", e)

    # AI analysis
    analysis = analyze_image(temp_path)
    if analysis["is_pornographic"]:
        blacklisted_ips[client_ip] = now + BLACKLIST_DURATION_SECONDS
        temp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Inappropriate content")

    save_staging_metadata(file.filename, client_ip, visitor_id)
    last_upload_times[client_ip] = now

    return RedirectResponse("/", status_code=302)
