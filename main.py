
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
    '''
    Sends image to OpenAI Vision API and expects a JSON response.
    Returns dict with:
    - is_pornographic: bool
    - car_make: str
    - car_model: str
    - car_color: str
    '''
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
