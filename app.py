from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import string
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

import requests
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DATABASE = DATA_DIR / "db.sqlite3"
ENDPOINTS_FILE = DATA_DIR / "endpoints.json"
BOTS_FILE = BASE_DIR / "bots.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sf-change-me")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)

RANDOM_ALPHABET = string.ascii_lowercase + string.digits


def load_bot_patterns() -> tuple[re.Pattern, dict]:
    with open(BOTS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    bot_patterns = []
    bot_categories = {}

    for category, patterns in data.items():
        for pattern in patterns:
            bot_patterns.append(pattern)
            bot_categories[pattern] = category

    combined_pattern = "|".join(bot_patterns)
    return re.compile(combined_pattern, re.I), bot_categories


BOT_UA_RE, BOT_CATEGORIES = load_bot_patterns()

ALLOWED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
}

ALLOWED_BEHAVIORS = {
    "image",
    "redirect",
    "alert",
}

ALLOWED_BOT_BEHAVIORS = {
    "image",
    "redirect",
    "nothing",
    "meta",
    "mimic",
}

ALLOWED_PER_PAGE = {
    10,
    20,
    50,
    100,
    200,
    500,
    1000,
}

LICENSE_PREFIX = "SF-"


def random_token(length: int = 8) -> str:
    return "".join(secrets.choice(RANDOM_ALPHABET) for _ in range(length))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_license_key(value: str) -> str:
    return (value or "").strip().upper()


def normalize_query_string(value: str | None) -> str:
    value = (value or "").strip()
    return value[1:] if value.startswith("?") else value


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_http_url(value: str) -> bool:
    if not value:
        return False

    try:
        parsed = urlparse(value)
    except ValueError:
        return False

    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def validate_image_url(value: str) -> bool:
    return validate_http_url(value)


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT NOT NULL UNIQUE,
    license_key TEXT NOT NULL UNIQUE,
    tracking_key TEXT NOT NULL UNIQUE,
    created_at_utc TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id TEXT NOT NULL,
    visited_at_utc TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    accept TEXT,
    accept_language TEXT,
    accept_encoding TEXT,
    host TEXT,
    method TEXT,
    path TEXT,
    query_string TEXT,
    scheme TEXT,
    remote_port INTEGER,
    is_bot INTEGER NOT NULL,
    route TEXT,
    browser TEXT,
    browser_version TEXT,
    os TEXT,
    device TEXT,
    headers_json TEXT,
    bot_category TEXT
);

CREATE INDEX IF NOT EXISTS idx_visits_endpoint
ON visits(endpoint_id);

CREATE INDEX IF NOT EXISTS idx_visits_time
ON visits(visited_at_utc);

CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_id INTEGER NOT NULL UNIQUE,
    fingerprint_hash TEXT,
    canvas_hash TEXT,
    webgl_hash TEXT,
    audio_hash TEXT,
    fonts_hash TEXT,
    navigator_json TEXT,
    screen_json TEXT,
    timezone_json TEXT,
    features_json TEXT,
    webgl_json TEXT,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY (visit_id)
        REFERENCES visits(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fingerprints_hash
ON fingerprints(fingerprint_hash);

CREATE INDEX IF NOT EXISTS idx_fingerprints_visit
ON fingerprints(visit_id);

CREATE TABLE IF NOT EXISTS endpoint_history (
    endpoint_id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    tracking_key TEXT NOT NULL,
    deleted_at_utc TEXT NOT NULL,
    FOREIGN KEY (owner_id)
        REFERENCES users(id)
);
"""


def init_db() -> None:
    with db() as connection:
        connection.executescript(SCHEMA)


def generate_tracking_key() -> str:
    return Fernet.generate_key().decode("ascii")


def create_tracking_cipher(tracking_key: str) -> Fernet | None:
    if not tracking_key:
        return None

    try:
        return Fernet(tracking_key.encode("ascii"))
    except Exception:
        return None


def encrypt_tracking_value(value: str, tracking_key: str) -> str:
    value = (value or "").strip()

    if not value:
        return ""

    cipher = create_tracking_cipher(tracking_key)

    if cipher is None:
        raise RuntimeError("User tracking key is invalid.")

    return cipher.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_tracking_value(value: str, tracking_key: str) -> str | None:
    if not value:
        return None

    cipher = create_tracking_cipher(tracking_key)

    if cipher is None:
        return None

    try:
        return cipher.decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError, TypeError):
        return None


def generate_license_key() -> str:
    return LICENSE_PREFIX + secrets.token_hex(20).upper()


def create_license(nickname: str) -> str:
    nickname = (nickname or "").strip()

    if not nickname:
        raise ValueError("Nickname cannot be empty.")

    if len(nickname) > 64:
        raise ValueError("Nickname cannot be longer than 64 characters.")

    license_key = generate_license_key()
    tracking_key = generate_tracking_key()

    with db() as connection:
        connection.execute(
            """
            INSERT INTO users (
                nickname,
                license_key,
                tracking_key,
                created_at_utc,
                active
            )
            VALUES (?, ?, ?, ?, 1)
            """,
            (nickname, license_key, tracking_key, utc_now()),
        )

    return license_key


def authenticate_license(license_key: str) -> sqlite3.Row | None:
    normalized = normalize_license_key(license_key)

    if not normalized:
        return None

    with db() as connection:
        return connection.execute(
            """
            SELECT
                id,
                nickname,
                license_key,
                tracking_key,
                created_at_utc,
                active
            FROM users
            WHERE license_key = ?
              AND active = 1
            """,
            (normalized,),
        ).fetchone()


def get_logged_in_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")

    if not user_id:
        return None

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        session.clear()
        return None

    with db() as connection:
        user = connection.execute(
            """
            SELECT
                id,
                nickname,
                license_key,
                tracking_key,
                created_at_utc,
                active
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    if not user or not user["active"]:
        session.clear()
        return None

    return user


def account_required() -> bool:
    return get_logged_in_user() is not None


@app.template_filter("friendly_datetime")
def friendly_datetime(value):
    try:
        dt = datetime.fromisoformat(value)

        if dt.tzinfo is None:
            return dt.strftime("%d %b %Y, %H:%M:%S")

        return dt.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")
    except (TypeError, ValueError):
        return value


def load_endpoints() -> dict:
    if not ENDPOINTS_FILE.exists():
        return {}

    try:
        data = json.loads(ENDPOINTS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    return data if isinstance(data, dict) else {}


def save_endpoints(data: dict) -> None:
    temporary = ENDPOINTS_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary.replace(ENDPOINTS_FILE)


def endpoint_token() -> str:
    return random_token(8)


def prepare_endpoint_ids(endpoints: dict) -> dict:
    used_ids = set()

    for endpoint in endpoints.values():
        try:
            endpoint_id = int(endpoint.get("id"))
        except (TypeError, ValueError):
            continue

        if endpoint_id > 0:
            used_ids.add(endpoint_id)

    next_id = max(used_ids, default=0) + 1
    changed = False

    for endpoint in endpoints.values():
        try:
            endpoint_id = int(endpoint.get("id"))

            if endpoint_id > 0:
                endpoint["id"] = endpoint_id
                continue

        except (TypeError, ValueError):
            pass

        endpoint["id"] = next_id
        used_ids.add(next_id)
        next_id += 1
        changed = True

    if changed:
        save_endpoints(endpoints)

    return endpoints


def sort_endpoints_newest_first(endpoints: dict) -> OrderedDict:
    return OrderedDict(
        sorted(
            endpoints.items(),
            key=lambda item: item[1].get("created_at", ""),
            reverse=True,
        )
    )


def endpoint_belongs_to_user(endpoint: dict, user_id: int) -> bool:
    try:
        return int(endpoint.get("owner_id")) == int(user_id)
    except (TypeError, ValueError):
        return False


def get_endpoint_owner(endpoint: dict) -> sqlite3.Row | None:
    try:
        owner_id = int(endpoint.get("owner_id"))
    except (TypeError, ValueError):
        return None

    with db() as connection:
        return connection.execute(
            """
            SELECT
                id,
                nickname,
                tracking_key,
                active
            FROM users
            WHERE id = ?
              AND active = 1
            """,
            (owner_id,),
        ).fetchone()


def get_deleted_endpoint_history(endpoint_id: str, user_id: int) -> sqlite3.Row | None:
    with db() as connection:
        return connection.execute(
            """
            SELECT
                endpoint_id,
                owner_id,
                tracking_key,
                deleted_at_utc
            FROM endpoint_history
            WHERE endpoint_id = ?
              AND owner_id = ?
            """,
            (endpoint_id, user_id),
        ).fetchone()


def get_owned_historical_endpoint_ids(user_id: int) -> list[str]:
    with db() as connection:
        rows = connection.execute(
            """
            SELECT endpoint_id
            FROM endpoint_history
            WHERE owner_id = ?
            """,
            (user_id,),
        ).fetchall()

    return [row["endpoint_id"] for row in rows]


def get_tracking_key_for_visit(endpoint_id: str, user_id: int, active_endpoints: dict) -> str:
    endpoint = active_endpoints.get(endpoint_id)

    if endpoint and endpoint_belongs_to_user(endpoint, user_id):
        return endpoint.get("_tracking_key", "") or ""

    history = get_deleted_endpoint_history(endpoint_id, user_id)

    if history:
        return history["tracking_key"] or ""

    return ""


def build_endpoint_url(endpoint_id: str) -> str:
    return url_for("image_endpoint", endpoint_id=endpoint_id, _external=True)


def client_ip() -> str:
    candidates = [
        request.headers.get("CF-Connecting-IP", "").strip(),
        request.headers.get("X-Real-IP", "").strip(),
    ]

    forwarded = request.headers.get("X-Forwarded-For", "")

    if forwarded:
        candidates.append(forwarded.split(",", 1)[0].strip())

    candidates.append((request.remote_addr or "").strip())

    return next((value for value in candidates if valid_ip(value)), "")


def get_bot_category(ua: str) -> str:
    for pattern, category in BOT_CATEGORIES.items():
        if re.search(pattern, ua, re.I):
            return category
    return ""


def parse_ua(ua: str) -> dict:
    value = ua or ""
    lower = value.lower()

    browser = "Other"
    browser_version = ""

    if BOT_UA_RE.search(value):
        browser = "Bot"
        browser_version = ""
        return {
            "browser": browser,
            "browser_version": browser_version,
            "os": "Other",
            "device": "Desktop",
        }

    browser_patterns = (
        ("Edge", r"edg/([\d.]+)", "edg/"),
        ("Chrome", r"chrome/([\d.]+)", "chrome/"),
        ("Firefox", r"firefox/([\d.]+)", "firefox/"),
        ("Safari", r"version/([\d.]+)", "safari/"),
    )

    for name, pattern, marker in browser_patterns:
        if marker not in lower:
            continue

        if name == "Safari" and "chrome/" in lower:
            continue

        browser = name

        match = re.search(pattern, value, re.I)

        if match:
            browser_version = match.group(1)

        break

    if "windows" in lower:
        os_name = "Windows"
    elif "android" in lower:
        os_name = "Android"
    elif "iphone" in lower or "ipad" in lower:
        os_name = "iOS"
    elif "mac os x" in lower:
        os_name = "macOS"
    elif "linux" in lower:
        os_name = "Linux"
    else:
        os_name = "Other"

    if "iphone" in lower or ("android" in lower and "mobile" in lower):
        device = "Mobile"
    elif "ipad" in lower or "android" in lower:
        device = "Tablet"
    else:
        device = "Desktop"

    return {
        "browser": browser,
        "browser_version": browser_version,
        "os": os_name,
        "device": device,
    }


def log_visit(endpoint_id: str, route: str) -> int:
    ua = request.headers.get("User-Agent", "")
    is_bot = bool(BOT_UA_RE.search(ua))
    bot_category = get_bot_category(ua) if is_bot else ""
    info = parse_ua(ua)
    query_string = request.query_string.decode("utf-8", "replace")

    values = (
        endpoint_id,
        utc_now(),
        client_ip(),
        ua,
        request.headers.get("Accept", ""),
        request.headers.get("Accept-Language", ""),
        request.headers.get("Accept-Encoding", ""),
        request.host,
        request.method,
        request.path,
        query_string,
        request.scheme,
        request.environ.get("REMOTE_PORT"),
        int(is_bot),
        route,
        info["browser"],
        info["browser_version"],
        info["os"],
        info["device"],
        json.dumps(dict(request.headers), ensure_ascii=False, sort_keys=True),
        bot_category,
    )

    with db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO visits (
                endpoint_id,
                visited_at_utc,
                ip_address,
                user_agent,
                accept,
                accept_language,
                accept_encoding,
                host,
                method,
                path,
                query_string,
                scheme,
                remote_port,
                is_bot,
                route,
                browser,
                browser_version,
                os,
                device,
                headers_json,
                bot_category
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?
            )
            """,
            values,
        )

        return cursor.lastrowid


def store_uploaded(file):
    if not file or not file.filename:
        return None

    filename = secure_filename(file.filename)

    if not filename:
        raise ValueError("Invalid upload filename.")

    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("Only PNG, JPEG, GIF and WebP uploads are supported.")

    name = f"{uuid.uuid4().hex}{extension}"
    path = UPLOAD_DIR / name

    file.save(path)

    return f"/media/{name}"


def delete_uploaded(source: str) -> None:
    if not source.startswith("/media/"):
        return

    filename = secure_filename(Path(source).name)

    if not filename:
        return

    try:
        (UPLOAD_DIR / filename).unlink(missing_ok=True)
    except OSError:
        pass


def resolve_image(source: str):
    if source.startswith("/media/"):
        filename = secure_filename(Path(source).name)
        path = UPLOAD_DIR / filename

        if not path.is_file():
            abort(404)

        return send_file(path)

    if not validate_image_url(source):
        abort(404)

    try:
        response = requests.get(
            source,
            timeout=8,
            headers={"User-Agent": "ImageFingerprinter/1.0"},
        )
        response.raise_for_status()
    except requests.RequestException:
        abort(502)

    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()

    if not content_type.startswith("image/"):
        abort(415)

    return send_file(BytesIO(response.content), mimetype=content_type)


@app.before_request
def require_auth():
    endpoint = request.endpoint

    public_routes = [
        "login",
        "logout",
        "image_endpoint",
        "endpoint_image",
        "fingerprint",
        "media",
        "static",
    ]

    if endpoint and endpoint not in public_routes and not endpoint.startswith("fingerprint"):
        if not account_required():
            return redirect(url_for("login"))


@app.route("/")
def index():
    if account_required():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("50 per hour")
def login():
    if account_required():
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        license_key = request.form.get("license_key", "")
        user = authenticate_license(license_key)

        if user:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        error = "Invalid license key."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@limiter.limit("30 per minute")
def dashboard():
    user = get_logged_in_user()

    if not user:
        return redirect(url_for("login"))

    user_id = int(user["id"])

    active_endpoints = sort_endpoints_newest_first(prepare_endpoint_ids(load_endpoints()))

    active_endpoints = OrderedDict(
        (
            endpoint_id,
            endpoint,
        )
        for endpoint_id, endpoint in active_endpoints.items()
        if endpoint_belongs_to_user(endpoint, user_id)
    )

    for endpoint in active_endpoints.values():
        endpoint["_tracking_key"] = user["tracking_key"]

    deleted_endpoint_ids = get_owned_historical_endpoint_ids(user_id)

    all_endpoint_ids = list(active_endpoints)

    for endpoint_id in deleted_endpoint_ids:
        if endpoint_id not in all_endpoint_ids:
            all_endpoint_ids.append(endpoint_id)

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    try:
        per_page = int(request.args.get("per_page", 20))
    except (TypeError, ValueError):
        per_page = 20

    if per_page not in ALLOWED_PER_PAGE:
        per_page = 20

    hide_bots = request.args.get("hide_bots") == "1"
    regex_filter = request.args.get("regex_filter", "").strip()

    with db() as connection:
        if all_endpoint_ids:
            placeholders = ",".join("?" for _ in all_endpoint_ids)

            stats = connection.execute(
                f"""
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(is_bot = 1), 0) AS bots,
                    COALESCE(SUM(is_bot = 0), 0) AS normal
                FROM visits
                WHERE endpoint_id IN ({placeholders})
                """,
                all_endpoint_ids,
            ).fetchone()

            endpoint_stats_rows = connection.execute(
                f"""
                SELECT
                    endpoint_id,
                    COALESCE(SUM(is_bot = 1), 0) AS bot_clicks,
                    COALESCE(SUM(is_bot = 0), 0) AS user_clicks
                FROM visits
                WHERE endpoint_id IN ({placeholders})
                GROUP BY endpoint_id
                """,
                all_endpoint_ids,
            ).fetchall()

            visit_where = f"WHERE v.endpoint_id IN ({placeholders})"
            query_parameters = list(all_endpoint_ids)

            if hide_bots:
                visit_where += " AND v.is_bot = 0"

            count_row = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM visits v
                {visit_where}
                """,
                query_parameters,
            ).fetchone()

            total_visits = count_row[0]

        else:
            stats = {
                "total": 0,
                "bots": 0,
                "normal": 0,
            }
            endpoint_stats_rows = []
            total_visits = 0
            visit_where = ""
            query_parameters = []

        total_pages = max(1, (total_visits + per_page - 1) // per_page)
        page = min(page, total_pages)
        offset = (page - 1) * per_page

        if all_endpoint_ids:
            placeholders = ",".join("?" for _ in all_endpoint_ids)
            visits_where = f"WHERE v.endpoint_id IN ({placeholders})"
            visit_parameters = list(all_endpoint_ids)

            if hide_bots:
                visits_where += " AND v.is_bot = 0"

            visits = connection.execute(
                f"""
                SELECT
                    v.*,
                    f.fingerprint_hash,
                    f.canvas_hash,
                    f.webgl_hash,
                    f.audio_hash,
                    f.fonts_hash,
                    f.navigator_json,
                    f.screen_json,
                    f.timezone_json,
                    f.features_json,
                    f.webgl_json,
                    f.created_at_utc AS fingerprint_created_at
                FROM visits v
                LEFT JOIN fingerprints f ON f.visit_id = v.id
                {visits_where}
                ORDER BY v.id DESC
                LIMIT ? OFFSET ?
                """,
                (*visit_parameters, per_page, offset),
            ).fetchall()

        else:
            visits = []

    endpoint_stats = {
        row["endpoint_id"]: {
            "bot_clicks": row["bot_clicks"],
            "user_clicks": row["user_clicks"],
        }
        for row in endpoint_stats_rows
    }

    decoded_visits = []

    for row in visits:
        visit = dict(row)
        visit["is_bot"] = bool(visit.get("is_bot", 0))

        endpoint = active_endpoints.get(visit.get("endpoint_id"))
        tracking_alias = ""

        if endpoint:
            tracking_alias = endpoint.get("tracking_alias", "") or ""

        visit["tracking_alias"] = tracking_alias
        visit["endpoint_deleted"] = endpoint is None

        decoded_visits.append(visit)

    if regex_filter:
        try:
            pattern = re.compile(regex_filter, re.IGNORECASE)
            decoded_visits = [
                v for v in decoded_visits
                if pattern.search(json.dumps(v, default=str))
            ]
        except re.error:
            pass

    endpoint_urls = {
        token: build_endpoint_url(token)
        for token, endpoint in active_endpoints.items()
    }

    return render_template(
        "dashboard.html",
        user=user,
        endpoints=active_endpoints,
        endpoint_urls=endpoint_urls,
        endpoint_stats=endpoint_stats,
        stats=stats,
        visits=decoded_visits,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_visits=total_visits,
        regex_filter=regex_filter,
    )


@app.route("/delete_visits", methods=["POST"])
def delete_visits():
    user = get_logged_in_user()

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = int(user["id"])
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid request"}), 400

    visit_ids = data.get("visit_ids", [])

    if not visit_ids:
        return jsonify({"error": "No visit IDs provided"}), 400

    with db() as connection:
        for visit_id in visit_ids:
            try:
                visit_id = int(visit_id)
            except (TypeError, ValueError):
                continue

            visit = connection.execute(
                """
                SELECT id, endpoint_id
                FROM visits
                WHERE id = ?
                """,
                (visit_id,),
            ).fetchone()

            if not visit:
                continue

            endpoint = load_endpoints().get(visit["endpoint_id"])
            authorized = False

            if endpoint:
                authorized = endpoint_belongs_to_user(endpoint, user_id)
            else:
                history = get_deleted_endpoint_history(visit["endpoint_id"], user_id)
                authorized = history is not None

            if not authorized:
                continue

            connection.execute(
                """
                DELETE FROM visits
                WHERE id = ?
                """,
                (visit_id,),
            )

    return jsonify({"ok": True})


@app.route("/create", methods=["POST"])
def create_endpoint():
    user = get_logged_in_user()

    if not user:
        return redirect(url_for("login"))

    user_id = int(user["id"])
    tracking_key = user["tracking_key"]

    created_files = []

    try:
        behavior = request.form.get("behavior", "image").strip().lower()

        if behavior not in ALLOWED_BEHAVIORS:
            raise ValueError("Invalid visitor behavior.")

        bot_behavior = request.form.get("bot_behavior", "image").strip().lower()

        if bot_behavior not in ALLOWED_BOT_BEHAVIORS:
            raise ValueError("Invalid bot behavior.")

        bot_image = ""
        if bot_behavior == "image":
            bot_image = store_uploaded(request.files.get("bot_image"))

            if bot_image:
                created_files.append(bot_image)
            else:
                bot_image = request.form.get("bot_image_url", "").strip()

            if not bot_image:
                raise ValueError("Bot image is required when bot behavior is 'image'.")

            if bot_image.startswith(("http://", "https://")) and not validate_image_url(bot_image):
                raise ValueError("Bot image URL is invalid.")

        bot_meta_tags = ""
        if bot_behavior == "meta":
            bot_meta_tags = request.form.get("meta_tags", "")

            if not bot_meta_tags.strip():
                raise ValueError("Meta tags are required when bot behavior is 'meta'.")

            if len(bot_meta_tags) > 5000:
                raise ValueError("Meta tags are too long.")

        bot_redirect_url = ""
        if bot_behavior == "redirect":
            bot_redirect_url = request.form.get("bot_redirect_url", "").strip()

            if bot_redirect_url and not validate_http_url(bot_redirect_url):
                raise ValueError("Bot redirect URL is invalid.")

        bot_mimic_url = ""
        bot_mimic_meta_tags = ""
        if bot_behavior == "mimic":
            bot_mimic_url = request.form.get("bot_mimic_url", "").strip()

            if not bot_mimic_url:
                raise ValueError("Target URL is required for 'Mimic website' behavior.")

            if not validate_http_url(bot_mimic_url):
                raise ValueError("Invalid target URL for 'Mimic website'.")

            try:
                response = requests.get(
                    bot_mimic_url,
                    timeout=30,
                    headers={
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"
                        )
                    },
                    allow_redirects=True,
                )
                response.raise_for_status()

                html_content = response.text
                meta_tags = []

                meta_pattern = re.compile(r'<meta[^>]*>', re.IGNORECASE | re.DOTALL)
                meta_tags.extend(meta_pattern.findall(html_content))

                title_pattern = re.compile(r'<title[^>]*>.*?</title>', re.IGNORECASE | re.DOTALL)
                meta_tags.extend(title_pattern.findall(html_content))

                link_pattern = re.compile(
                    r'<link[^>]*rel=["\']([^"\']*)["\'][^>]*>',
                    re.IGNORECASE | re.DOTALL,
                )
                for match in link_pattern.finditer(html_content):
                    meta_tags.append(match.group(0))

                meta_tags = list(dict.fromkeys(meta_tags))

                if len(meta_tags) > 100:
                    meta_tags = meta_tags[:100]

                bot_mimic_meta_tags = "\n".join(meta_tags) if meta_tags else ""

            except requests.exceptions.RequestException as e:
                raise ValueError(f"Failed to fetch page: {str(e)}")
            except Exception as e:
                raise ValueError(f"Error processing page: {str(e)}")

        normal_image = ""
        if behavior == "image":
            normal_image = store_uploaded(request.files.get("image2"))

            if normal_image:
                created_files.append(normal_image)
            else:
                normal_image = request.form.get("image2_url", "").strip()

            if not normal_image:
                raise ValueError("Normal visitor image is required.")

            if normal_image.startswith(("http://", "https://")) and not validate_image_url(normal_image):
                raise ValueError("Normal image URL is invalid.")

        redirect_url = ""
        if behavior == "redirect":
            redirect_url = request.form.get("redirect_url", "").strip()

            if redirect_url and not validate_http_url(redirect_url):
                raise ValueError("Redirect URL is invalid.")

        alert_message = ""
        if behavior == "alert":
            alert_message = request.form.get("alert_message", "")

            if not alert_message.strip():
                raise ValueError("Alert message is required.")

            if len(alert_message) > 5000:
                raise ValueError("Alert message is too long.")

        tracking_aliases = request.form.get("tracking_aliases", "").strip()

        if len(tracking_aliases) > 10000:
            raise ValueError("Tracking aliases are too long.")

        tracking_aliases = [v.strip() for v in tracking_aliases.split(",") if v.strip()]

        if not tracking_aliases:
            tracking_aliases = [""]

        endpoints = prepare_endpoint_ids(load_endpoints())

        existing_ids = []

        for endpoint in endpoints.values():
            try:
                value = int(endpoint.get("id"))
            except (TypeError, ValueError):
                continue

            if value > 0:
                existing_ids.append(value)

        next_id = max(existing_ids, default=0) + 1

        for tracking_alias in tracking_aliases:
            if len(tracking_alias) > 1000:
                raise ValueError(f"Tracking alias '{tracking_alias}' is too long.")

            token = endpoint_token()

            while token in endpoints:
                token = endpoint_token()

            endpoints[token] = {
                "id": next_id,
                "owner_id": user_id,
                "bot_behavior": bot_behavior,
                "bot_image": bot_image,
                "bot_meta_tags": bot_meta_tags,
                "bot_redirect_url": bot_redirect_url,
                "bot_mimic_url": bot_mimic_url,
                "bot_mimic_meta_tags": bot_mimic_meta_tags,
                "image_normal": normal_image,
                "behavior": behavior,
                "redirect_url": redirect_url,
                "alert_message": alert_message,
                "tracking_alias": tracking_alias,
                "created_at": utc_now(),
            }

            next_id += 1

        save_endpoints(endpoints)

    except ValueError as exc:
        for source in created_files:
            delete_uploaded(source)

        return render_template("error.html", message=str(exc)), 400

    return redirect(url_for("dashboard"))


@app.route("/delete/<endpoint_id>", methods=["POST"])
def delete_endpoint(endpoint_id):
    user = get_logged_in_user()

    if not user:
        return redirect(url_for("login"))

    user_id = int(user["id"])
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid request"}), 400

    delete_visits = data.get("delete_visits", False)
    endpoints = load_endpoints()
    item = endpoints.get(endpoint_id)

    if not item:
        return jsonify({"error": "Endpoint not found"}), 404

    if not endpoint_belongs_to_user(item, user_id):
        return jsonify({"error": "Endpoint not found"}), 404

    if delete_visits:
        with db() as connection:
            connection.execute(
                """
                DELETE FROM visits
                WHERE endpoint_id = ?
                """,
                (endpoint_id,),
            )

    tracking_key = user["tracking_key"]

    with db() as connection:
        connection.execute(
            """
            INSERT INTO endpoint_history (
                endpoint_id,
                owner_id,
                tracking_key,
                deleted_at_utc
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(endpoint_id)
            DO UPDATE SET
                owner_id = excluded.owner_id,
                tracking_key = excluded.tracking_key,
                deleted_at_utc = excluded.deleted_at_utc
            """,
            (endpoint_id, user_id, tracking_key, utc_now()),
        )

    delete_uploaded(item.get("bot_image", ""))
    delete_uploaded(item.get("image_normal", ""))

    del endpoints[endpoint_id]

    save_endpoints(endpoints)

    return jsonify({"ok": True})


@app.route("/delete_visit/<int:visit_id>", methods=["POST"])
def delete_visit(visit_id):
    user = get_logged_in_user()

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = int(user["id"])

    with db() as connection:
        visit = connection.execute(
            """
            SELECT id, endpoint_id
            FROM visits
            WHERE id = ?
            """,
            (visit_id,),
        ).fetchone()

        if not visit:
            return jsonify({"error": "Visit not found"}), 404

        endpoint = load_endpoints().get(visit["endpoint_id"])
        authorized = False

        if endpoint:
            authorized = endpoint_belongs_to_user(endpoint, user_id)
        else:
            history = get_deleted_endpoint_history(visit["endpoint_id"], user_id)
            authorized = history is not None

        if not authorized:
            return jsonify({"error": "Unauthorized"}), 401

        connection.execute(
            """
            DELETE FROM visits
            WHERE id = ?
            """,
            (visit_id,),
        )

    return jsonify({"ok": True})


@app.route("/media/<name>")
def media(name):
    filename = secure_filename(name)
    path = UPLOAD_DIR / filename

    if not path.is_file():
        abort(404)

    return send_file(path)


@app.route("/i/<endpoint_id>/image")
@limiter.limit("30 per minute")
def endpoint_image(endpoint_id):
    item = load_endpoints().get(endpoint_id)

    if not item:
        abort(404)

    image = item.get("image_normal", "")

    if not image:
        abort(404)

    return resolve_image(image)


@app.route("/i/<endpoint_id>")
@limiter.limit("30 per minute")
def image_endpoint(endpoint_id):
    item = load_endpoints().get(endpoint_id)

    if not item:
        abort(404)

    ua = request.headers.get("User-Agent", "")
    bot = bool(BOT_UA_RE.search(ua))

    if bot:
        bot_behavior = item.get("bot_behavior", "image")

        if bot_behavior not in ALLOWED_BOT_BEHAVIORS:
            bot_behavior = "image"

        if bot_behavior == "nothing":
            bot = False
        else:
            route = f"bot_{bot_behavior}"
            visit_id = log_visit(endpoint_id, route)

            if bot_behavior == "image":
                image = item.get("bot_image", item.get("image_normal", ""))

                if not image:
                    abort(404)

                return resolve_image(image)

            if bot_behavior == "redirect":
                target = (item.get("bot_redirect_url", "") or "").strip()

                if target and not validate_http_url(target):
                    target = ""

                return render_template(
                    "visitor_action.html",
                    endpoint_id=endpoint_id,
                    visit_id=visit_id,
                    action="redirect",
                    target=target,
                    alert_message="",
                )

            if bot_behavior == "meta":
                return render_template(
                    "visitor_meta.html",
                    endpoint_id=endpoint_id,
                    visit_id=visit_id,
                    meta_tags=item.get("bot_meta_tags", ""),
                )

            if bot_behavior == "mimic":
                return render_template(
                    "visitor_mimic.html",
                    endpoint_id=endpoint_id,
                    visit_id=visit_id,
                    meta_tags=item.get("bot_mimic_meta_tags", ""),
                )

            image = item.get("bot_image", item.get("image_normal", ""))

            if image:
                return resolve_image(image)

            abort(404)

    visit_id = log_visit(endpoint_id, "normal")
    behavior = item.get("behavior", "image")

    if behavior not in ALLOWED_BEHAVIORS:
        behavior = "image"

    if behavior == "image":
        return render_template(
            "visitor_image.html",
            endpoint_id=endpoint_id,
            visit_id=visit_id,
            image_url=url_for("endpoint_image", endpoint_id=endpoint_id),
        )

    if behavior == "redirect":
        target = (item.get("redirect_url", "") or "").strip()

        if target and not validate_http_url(target):
            target = ""

        return render_template(
            "visitor_action.html",
            endpoint_id=endpoint_id,
            visit_id=visit_id,
            action="redirect",
            target=target,
            alert_message="",
        )

    if behavior == "alert":
        return render_template(
            "visitor_action.html",
            endpoint_id=endpoint_id,
            visit_id=visit_id,
            action="alert",
            target="",
            alert_message=item.get("alert_message", "") or "",
        )

    return render_template(
        "visitor_image.html",
        endpoint_id=endpoint_id,
        visit_id=visit_id,
        image_url=url_for("endpoint_image", endpoint_id=endpoint_id),
    )


@app.route("/view/<int:visit_id>")
def get_fingerprint(visit_id):
    user = get_logged_in_user()

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = int(user["id"])

    with db() as connection:
        visit = connection.execute(
            """
            SELECT id, endpoint_id
            FROM visits
            WHERE id = ?
            """,
            (visit_id,),
        ).fetchone()

        if not visit:
            return jsonify({"ready": False})

        endpoint = load_endpoints().get(visit["endpoint_id"])
        authorized = False

        if endpoint:
            authorized = endpoint_belongs_to_user(endpoint, user_id)
        else:
            history = get_deleted_endpoint_history(visit["endpoint_id"], user_id)
            authorized = history is not None

        if not authorized:
            return jsonify({"error": "Unauthorized"}), 401

        row = connection.execute(
            """
            SELECT
                f.fingerprint_hash,
                f.canvas_hash,
                f.webgl_hash,
                f.audio_hash,
                f.fonts_hash,
                f.navigator_json,
                f.screen_json,
                f.timezone_json,
                f.features_json,
                f.webgl_json,
                f.created_at_utc AS fingerprint_created_at
            FROM fingerprints f
            WHERE f.visit_id = ?
            """,
            (visit_id,),
        ).fetchone()

    if not row:
        return jsonify({"ready": False})

    return jsonify({
        "ready": True,
        "fingerprint_hash": row["fingerprint_hash"],
        "canvas_hash": row["canvas_hash"],
        "webgl_hash": row["webgl_hash"],
        "audio_hash": row["audio_hash"],
        "fonts_hash": row["fonts_hash"],
        "navigator_json": row["navigator_json"],
        "screen_json": row["screen_json"],
        "timezone_json": row["timezone_json"],
        "features_json": row["features_json"],
        "webgl_json": row["webgl_json"],
        "fingerprint_created_at": row["fingerprint_created_at"],
    })


@app.route("/view/<endpoint_id>", methods=["POST"])
def fingerprint(endpoint_id):
    endpoints = load_endpoints()

    if endpoint_id not in endpoints:
        abort(404)

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        visit_id = int(payload.get("visit_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid visit_id"}), 400

    with db() as connection:
        visit = connection.execute(
            """
            SELECT id, endpoint_id, is_bot
            FROM visits
            WHERE id = ?
            """,
            (visit_id,),
        ).fetchone()

        if not visit or visit["endpoint_id"] != endpoint_id:
            return jsonify({"error": "Invalid visit"}), 400

        if visit["is_bot"]:
            return jsonify({"error": "Bot visits cannot submit fingerprints"}), 400

        def normalized_value(name):
            value = payload.get(name, {})

            if value is None:
                return None

            if isinstance(value, (dict, list, str, int, float, bool)):
                return value

            return str(value)

        def canonical_json(value):
            return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

        def value_hash(value):
            return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()

        fingerprint_source = {
            key: value
            for key, value in payload.items()
            if key != "visit_id"
        }

        fingerprint_hash = hashlib.sha256(
            canonical_json(fingerprint_source).encode("utf-8")
        ).hexdigest()

        values = {
            name: normalized_value(name)
            for name in ("navigator", "screen", "timezone", "features", "webgl", "canvas", "audio", "fonts")
        }

        connection.execute(
            """
            INSERT INTO fingerprints (
                visit_id,
                fingerprint_hash,
                canvas_hash,
                webgl_hash,
                audio_hash,
                fonts_hash,
                navigator_json,
                screen_json,
                timezone_json,
                features_json,
                webgl_json,
                created_at_utc
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            ON CONFLICT(visit_id)
            DO UPDATE SET
                fingerprint_hash = excluded.fingerprint_hash,
                canvas_hash = excluded.canvas_hash,
                webgl_hash = excluded.webgl_hash,
                audio_hash = excluded.audio_hash,
                fonts_hash = excluded.fonts_hash,
                navigator_json = excluded.navigator_json,
                screen_json = excluded.screen_json,
                timezone_json = excluded.timezone_json,
                features_json = excluded.features_json,
                webgl_json = excluded.webgl_json,
                created_at_utc = excluded.created_at_utc
            """,
            (
                visit_id,
                fingerprint_hash,
                value_hash(values["canvas"]),
                value_hash(values["webgl"]),
                value_hash(values["audio"]),
                value_hash(values["fonts"]),
                canonical_json(values["navigator"]),
                canonical_json(values["screen"]),
                canonical_json(values["timezone"]),
                canonical_json(values["features"]),
                canonical_json(values["webgl"]),
                utc_now(),
            ),
        )

    return jsonify({"ok": True})


def cli_create_license(nickname: str) -> None:
    try:
        license_key = create_license(nickname)
    except sqlite3.IntegrityError:
        print(f"Error: nickname '{nickname}' already exists.")
        raise SystemExit(1)

    print()
    print("License created successfully.")
    print(f"Nickname: {nickname}")
    print(f"License:  {license_key}")
    print()


def cli_list_users() -> None:
    with db() as connection:
        users = connection.execute(
            """
            SELECT id, nickname, created_at_utc, active
            FROM users
            ORDER BY id ASC
            """
        ).fetchall()

    if not users:
        print("No users.")
        return

    for user in users:
        status = "active" if user["active"] else "disabled"
        print(f"#{user['id']} {user['nickname']} [{status}] {user['created_at_utc']}")


def cli_disable_user(nickname: str) -> None:
    with db() as connection:
        cursor = connection.execute(
            """
            UPDATE users
            SET active = 0
            WHERE nickname = ?
            """,
            (nickname,),
        )

    if cursor.rowcount == 0:
        print(f"User not found: {nickname}")
        raise SystemExit(1)

    print(f"Disabled user: {nickname}")


def cli_enable_user(nickname: str) -> None:
    with db() as connection:
        cursor = connection.execute(
            """
            UPDATE users
            SET active = 1
            WHERE nickname = ?
            """,
            (nickname,),
        )

    if cursor.rowcount == 0:
        print(f"User not found: {nickname}")
        raise SystemExit(1)

    print(f"Enabled user: {nickname}")


def run_cli() -> bool:
    parser = argparse.ArgumentParser(description="Stealth Fingerprinter")

    subparsers = parser.add_subparsers(dest="command")

    create_parser = subparsers.add_parser("create-license", help="Create a new user license.")
    create_parser.add_argument("nickname", help="Nickname for the user.")

    subparsers.add_parser("list-users", help="List users.")

    disable_parser = subparsers.add_parser("disable-user", help="Disable a user.")
    disable_parser.add_argument("nickname")

    enable_parser = subparsers.add_parser("enable-user", help="Enable a user.")
    enable_parser.add_argument("nickname")

    args = parser.parse_args()

    if not args.command:
        return False

    commands = {
        "create-license": lambda: cli_create_license(args.nickname),
        "list-users": cli_list_users,
        "disable-user": lambda: cli_disable_user(args.nickname),
        "enable-user": lambda: cli_enable_user(args.nickname),
    }

    command = commands.get(args.command)

    if command is None:
        return False

    command()

    return True


init_db()

if __name__ == "__main__":
    if run_cli():
        raise SystemExit(0)

    app.run(host="0.0.0.0", port=5000, debug=False)
