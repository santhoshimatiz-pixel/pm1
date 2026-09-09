import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import smtplib
import socket
import sys
import threading
import traceback
import time
import zipfile
import xml.etree.ElementTree as ET
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import urllib.request
from urllib.request import Request

ROOT = os.path.dirname(os.path.abspath(__file__))


# =====================================================================
# CONFIGURATION — loaded from environment variables (and an optional
# .env file next to server.py for local development). Nothing secret is
# hard-coded any more: copy .env.example to .env and fill in real values.
# =====================================================================
def _load_dotenv():
    """Best-effort .env loader (no external dependency). Real environment
    variables (e.g. set by the hosting platform) always win over .env."""
    path = os.path.join(ROOT, ".env")
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except OSError:
        pass


_load_dotenv()


def _env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env(name, default=""):
    return os.environ.get(name, default)


# ----- runtime/production configuration -----
APP_ENV = _env("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV in ("production", "prod")
DEBUG = _env_bool("DEBUG", False) and not IS_PRODUCTION   # never enable in production
PORT = int(_env("PORT", "8000"))
HOST = _env("HOST", "0.0.0.0")
COOKIE_SECURE = _env_bool("COOKIE_SECURE", IS_PRODUCTION)
FORCE_HTTPS = _env_bool("FORCE_HTTPS", IS_PRODUCTION)
TRUST_PROXY = _env_bool("TRUST_PROXY", IS_PRODUCTION)
SESSION_TTL_HOURS = float(_env("SESSION_TTL_HOURS", "12"))
SESSION_MAX_HOURS = float(_env("SESSION_MAX_HOURS", "168"))
MIN_PASSWORD_LENGTH = max(8, int(_env("MIN_PASSWORD_LENGTH", "8")))
MAX_UPLOAD_BYTES = int(_env("MAX_UPLOAD_BYTES", str(6 * 1024 * 1024)))
MAX_ATTACHMENT_BYTES = int(_env("MAX_ATTACHMENT_BYTES", str(5 * 1024 * 1024)))
MAX_BODY_BYTES = int(_env("MAX_BODY_BYTES", str(12 * 1024 * 1024)))
MAX_PASSWORD_LENGTH = 200
APP_BASE_URL = _env("APP_BASE_URL", "").strip().rstrip("/")
INITIAL_ADMIN_PASSWORD = _env("INITIAL_ADMIN_PASSWORD", "").strip()
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _env("ALLOWED_ORIGINS", "").split(",") if o.strip()]

# ----- Gmail credentials (used only for the optional "send email now" handoff
#       feature). Leave blank to disable that feature; never hard-code these. -----
GMAIL_USER = _env("GMAIL_USER", "")
GMAIL_APP_PASSWORD = _env("GMAIL_APP_PASSWORD", "")
DEFAULT_FROM_EMAIL = _env("DEFAULT_FROM_EMAIL", "")
DEFAULT_TO_EMAIL = _env("DEFAULT_TO_EMAIL", "")

# ----- session-signing secret. Auto-generated on first run and persisted to a
#       local, git-ignored file so sessions survive restarts. Set SECRET_KEY in
#       the environment for multi-instance / production deployments instead. -----
SECRET_KEY = _env("SECRET_KEY", "")
if IS_PRODUCTION and len(SECRET_KEY) < 32:
    raise SystemExit(
        "FATAL: APP_ENV=production requires SECRET_KEY to be set to 32+ random characters.\n"
        "Generate one with:  python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
if not SECRET_KEY:
    _secret_path = os.path.join(ROOT, ".session_secret")
    try:
        if os.path.exists(_secret_path):
            with open(_secret_path, "r", encoding="utf-8") as f:
                SECRET_KEY = f.read().strip()
        if not SECRET_KEY:
            SECRET_KEY = secrets.token_hex(32)
            with open(_secret_path, "w", encoding="utf-8") as f:
                f.write(SECRET_KEY)
    except OSError:
        SECRET_KEY = secrets.token_hex(32)  # in-memory fallback (sessions won't survive a restart)

COOKIE_NAME = "matiz_session"
CSRF_COOKIE_NAME = "matiz_csrf"

# Basic RFC-ish address check, used to validate mail recipients.
EMAIL_RE = re.compile(r"^[^@\s,;:<>\\\"]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}$")


# =====================================================================
# PASSWORD HASHING — PBKDF2-HMAC-SHA256 with a per-password random salt.
# Replaces the previous plain-text password storage/comparison.
# =====================================================================
_PBKDF2_ITERATIONS = 260000
_PBKDF2_PREFIX = "pbkdf2_sha256"


def hash_password(raw_password):
    raw_password = raw_password or ""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", raw_password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_PREFIX}${_PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def is_hashed_password(value):
    return isinstance(value, str) and value.startswith(_PBKDF2_PREFIX + "$")


def verify_password(raw_password, stored):
    """Constant-time verification. Returns False for any malformed/missing hash."""
    if not stored or not is_hashed_password(stored):
        return False
    try:
        _, iterations, salt, hexhash = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", (raw_password or "").encode("utf-8"),
                                  bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(dk.hex(), hexhash)
    except (ValueError, TypeError):
        return False


# SECURITY: file-upload hygiene. Files are stored as base64 blobs in SQLite (never written
# to disk under a user-controlled name), which already rules out path traversal — but the
# filename and declared MIME type are still attacker-controlled strings that get echoed back
# to other users (e.g. inside a data: URI download link in index.html), so they're sanitized
# before storage.
_SAFE_FILETYPE_RE = re.compile(r"^[a-zA-Z0-9.+/-]{1,100}$")


# Extensions that must never be handed back to a browser under their original
# name/type: executables, scripts, and the markup formats that run script when
# opened (html/svg). These are stored, but renamed so a colleague clicking the
# download link cannot be tricked into executing them.
_BLOCKED_UPLOAD_EXTS = {
    "exe", "msi", "bat", "cmd", "com", "scr", "pif", "cpl", "dll", "sys",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "sh", "bash",
    "apk", "jar", "hta", "html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml",
    "url", "lnk", "reg", "iso", "img", "dmg", "app", "scpt", "jnlp", "gadget",
}


def sanitize_upload_filename(name):
    name = (name or "").strip()
    if not name:
        return ""
    name = name.replace("\\", "/").split("/")[-1]   # strip any path component
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)      # strip control characters
    name = name.strip(". ")
    if not name:
        name = "file"
    # Neutralise dangerous extensions, including double extensions like
    # "report.pdf.exe" — the last one is what the OS acts on.
    parts = name.split(".")
    if len(parts) > 1 and parts[-1].lower() in _BLOCKED_UPLOAD_EXTS:
        name = name + ".txt"
    return name[:180]


def check_base64_payload(data, max_decoded_bytes, label="file"):
    """Validate an uploaded base64 blob and enforce a *decoded* size limit.

    The old code only measured the encoded string, so the real limit was ~25%
    higher than advertised, and a malformed blob was stored happily and only
    blew up later in the browser.
    """
    if not data:
        return ""
    raw = str(data)
    if "," in raw[:200] and raw[:5].lower() == "data:":
        raw = raw.split(",", 1)[1]        # strip a data: URI prefix if present
    if len(raw) > max_decoded_bytes * 4 // 3 + 1024:
        raise ApiError("That %s is too large (max %d MB)."
                       % (label, max_decoded_bytes // (1024 * 1024)))
    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception:
        raise ApiError("That %s could not be read. Please try uploading it again." % label)
    if len(decoded) > max_decoded_bytes:
        raise ApiError("That %s is too large (max %d MB)."
                       % (label, max_decoded_bytes // (1024 * 1024)))
    return raw


_DANGEROUS_MIME = ("text/html", "application/xhtml", "image/svg", "text/xsl",
                    "application/javascript", "text/javascript", "application/x-javascript")


def sanitize_upload_filetype(mime):
    mime = (mime or "").strip()
    if not mime or not _SAFE_FILETYPE_RE.match(mime):
        return "application/octet-stream"
    low = mime.lower()
    # These render/execute in the browser when opened from a data: link.
    if any(low.startswith(x) for x in _DANGEROUS_MIME):
        return "application/octet-stream"
    return mime


# =====================================================================
# LIGHTWEIGHT IN-MEMORY RATE LIMITING (per client IP). Good enough to slow
# down brute-force / abusive scripting against a single-process app like
# this one; a reverse proxy / WAF should still front any internet-facing
# deployment for stronger protection.
# =====================================================================
_RATE_LOCK = threading.Lock()
_RATE_BUCKETS = {}   # (ip, bucket) -> list[timestamps]


def _rate_limited(ip, bucket, limit, window_seconds):
    now = time.time()
    key = (ip, bucket)
    with _RATE_LOCK:
        hits = [t for t in _RATE_BUCKETS.get(key, []) if now - t < window_seconds]
        if len(hits) >= limit:
            # Already over the limit: do NOT record this attempt. Counting rejected
            # attempts kept pushing the window forward, so a locked-out user who
            # kept retrying could never drain it and stayed locked out indefinitely.
            _RATE_BUCKETS[key] = hits
            return True
        hits.append(now)
        _RATE_BUCKETS[key] = hits
        # Opportunistic cleanup so the dict can't grow without bound.
        if len(_RATE_BUCKETS) > 5000:
            for k in [k for k, v in _RATE_BUCKETS.items() if not v or now - max(v) > 3600]:
                _RATE_BUCKETS.pop(k, None)
        return False


# =====================================================================
# SERVER-SIDE SESSIONS. Replaces the old design where every request simply
# trusted a "role" / "empId" / "clientId" field sent by the browser. A
# session is created only after a password has been verified in
# handle_action("login", ...); the HTTP layer then binds every subsequent
# request's real identity to the session token in an HttpOnly cookie,
# overriding anything the client claims about itself in the JSON body.
# =====================================================================
# =====================================================================
# AUTHORIZATION MATRIX
# ---------------------------------------------------------------------
# Deny-by-default. Every action must appear in exactly one bucket below;
# an action that is not listed is rejected outright, so adding a new
# handler without deciding who may call it fails closed rather than open.
#
# The session layer has already replaced the caller's claimed "role" with
# the one stored server-side, so these checks act on a trusted identity.
# =====================================================================

# Reachable with no session at all.
PUBLIC_ACTIONS = {"login", "logout", "session",
                  "set_client_password", "request_client_password_reset"}

# The only actions a client-portal session may reach. Everything else is
# staff-only, including the destructive pipeline actions.
CLIENT_ALLOWED_ACTIONS = {
    "bootstrap", "change_password",
    "get_thread", "send_message", "chat_typing",
    "get_client_document",
    "add_query",
    "client_approve_proposal", "client_approve_paper", "client_approve_implementation",
    "client_request_correction_proposal", "client_request_correction_paper",
    "client_request_correction_implementation",
}

_R_ADMIN = ("md_admin", "super_admin")
_R_MARKETING = ("telecaller", "marketing_tl", "marketing_manager") + _R_ADMIN
_R_MKT_MGMT = ("marketing_tl", "marketing_manager") + _R_ADMIN
_R_ACCOUNTS = ("account_team",) + _R_ADMIN
_R_TECH = ("technical_manager", "technical_tl", "content_coordinator") + _R_ADMIN
_R_TECH_MGMT = ("technical_manager", "technical_tl") + _R_ADMIN
_R_TECH_MGR = ("technical_manager",) + _R_ADMIN
_R_JOURNAL = ("journal_manager", "journal_tl") + _R_ADMIN
_R_MANAGERS = ("marketing_manager", "technical_manager", "journal_manager") + _R_ADMIN
_R_STAFF_MGMT = ("technical_manager", "technical_tl", "marketing_tl", "marketing_manager",
                 "journal_manager", "journal_tl") + _R_ADMIN

# Every logged-in staff principal, including individually-added employees
# (who log in with role "employee").
_R_ALL_STAFF = ("employee", "telecaller", "marketing_tl", "marketing_manager",
                "account_team", "technical_manager", "technical_tl",
                "content_coordinator", "journal_manager", "journal_tl") + _R_ADMIN

ACTION_ROLES = {
    # ---- shared, any authenticated staff member ----
    "bootstrap": _R_ALL_STAFF,
    "change_password": _R_ALL_STAFF,
    "get_thread": _R_ALL_STAFF,
    "send_message": _R_ALL_STAFF,
    "chat_typing": _R_ALL_STAFF,
    "get_client_document": _R_ALL_STAFF,
    "dm_directory": _R_ALL_STAFF,
    "dm_send": _R_ALL_STAFF,
    "dm_thread": _R_ALL_STAFF,
    "dm_typing": _R_ALL_STAFF,
    "dm_inbox": _R_ALL_STAFF,
    "add_work_update": _R_ALL_STAFF,
    "add_task_comment": _R_ALL_STAFF,
    "add_calendar_event": _R_ALL_STAFF,
    "delete_calendar_event": _R_ALL_STAFF,
    "request_hold": _R_ALL_STAFF,
    "request_deadline_extension": _R_ALL_STAFF,

    # ---- marketing / intake ----
    "add_client": _R_MARKETING,
    "update_client": _R_MARKETING + ("account_team", "technical_manager", "technical_tl",
                                     "content_coordinator", "journal_manager", "journal_tl"),
    "add_call": _R_MARKETING,
    "add_query": _R_ALL_STAFF,
    "update_query": _R_ALL_STAFF,
    "delete_query": _R_MKT_MGMT + ("technical_manager", "journal_manager"),
    "add_client_note": _R_ALL_STAFF,
    "delete_client_note": _R_MKT_MGMT,
    "add_client_referral": _R_MARKETING,
    "delete_client_referral": _R_MKT_MGMT,
    "add_client_document": _R_ALL_STAFF,
    "delete_client_document": _R_MKT_MGMT + ("technical_manager", "journal_manager"),
    "add_service_item": _R_MARKETING,
    "delete_service_item": _R_MARKETING,
    "schedule_demo": _R_MARKETING + ("technical_manager", "technical_tl"),
    "postpone_demo_schedule": _R_MARKETING + ("technical_manager", "technical_tl"),
    "cancel_demo_schedule": _R_MARKETING + ("technical_manager", "technical_tl"),
    "complete_demo_schedule": _R_MARKETING + ("technical_manager", "technical_tl"),
    "mark_demo_given": _R_MARKETING + ("technical_manager", "technical_tl"),
    "reject_client": _R_MKT_MGMT,
    "unreject_client": _R_MKT_MGMT,
    # BUGFIX: widened from _R_MKT_MGMT. Telecallers can already add a client one at a
    # time (add_client uses _R_MARKETING), but the bulk-import panel shown on their own
    # dashboard was still gated to Marketing TL/Manager only, so a Telecaller clicking
    # "Import file" there got a silent 403. Matches add_client's roles.
    "import_clients": _R_MARKETING,
    "import_clients_from_url": _R_MARKETING,
    "bulk_import": _R_MARKETING,
    "bulk_import_from_url": _R_MARKETING,
    "assign_proposal_writer": _R_MARKETING + ("technical_manager", "technical_tl"),
    "send_to_client": _R_MARKETING,
    "send_to_tl": _R_MARKETING + ("technical_manager", "technical_tl"),

    # ---- client portal administration (invitations / portal passwords) ----
    "send_client_invite": ("telecaller", "marketing_tl", "marketing_manager") + _R_ADMIN,
    "create_invite_link": ("telecaller", "marketing_tl", "marketing_manager") + _R_ADMIN,
    "admin_reset_client_password": ("telecaller", "marketing_tl", "marketing_manager") + _R_ADMIN,

    # ---- accounts / money ----
    "mark_paid": _R_ACCOUNTS,
    "mark_installment_paid": _R_ACCOUNTS,
    # BUGFIX: widened from _R_ACCOUNTS. The handler itself (see MARKETING_ROLES inside the
    # add_client_installments/delete_client_installment actions below) has always allowed
    # Telecaller/Marketing TL/Marketing Manager/Admin to manage the installment split-up,
    # but this authorization gate ran first and silently rejected them with a 403 before
    # the handler's own (correct) check ever ran.
    "add_client_installments": _R_MARKETING,
    "delete_client_installment": _R_MARKETING,
    "account_approve": _R_ACCOUNTS,
    "approve_writing_fee": _R_ACCOUNTS,
    "manager_approve": _R_MANAGERS,
    "manager_fasttrack": _R_MANAGERS,

    # ---- technical pipeline ----
    "add_task": _R_TECH + ("journal_manager", "journal_tl", "marketing_manager"),
    "update_task": _R_ALL_STAFF,
    "delete_task": _R_TECH_MGMT + ("journal_manager", "journal_tl"),
    "assign_programmers": _R_TECH,
    "assign_writers": _R_TECH,
    "assign_formatters": _R_TECH + ("journal_manager", "journal_tl"),
    "assign_proofreaders": _R_TECH + ("journal_manager", "journal_tl"),
    "assign_format_coordinator": _R_TECH_MGMT + ("journal_manager", "journal_tl"),
    "assign_proofread_coordinator": _R_TECH_MGMT + ("journal_manager", "journal_tl"),
    "coordinator_take_proposal": _R_ALL_STAFF,
    "coordinator_take_implementation": _R_ALL_STAFF,
    "coordinator_take_writing": _R_ALL_STAFF,
    "coordinator_assign_proposal_writer": _R_ALL_STAFF,
    "coordinator_assign_implementation_team": _R_ALL_STAFF,
    "coordinator_assign_writing_team": _R_ALL_STAFF,
    "coordinator_decision": _R_ALL_STAFF,
    "techtl_decision": _R_TECH_MGMT,
    "techmgr_decision": _R_TECH_MGR,
    "tl_verify": _R_TECH_MGMT,
    "verify_proposal": _R_TECH_MGMT,
    "submit_proposal": _R_ALL_STAFF,
    "deliver_proposal": _R_TECH_MGMT,
    "complete_implementation": _R_ALL_STAFF,
    "send_implementation_to_client": _R_TECH_MGMT,
    "approve_demo": _R_TECH_MGMT,
    "submit_writing_demo": _R_ALL_STAFF,
    "mark_writing_demo_given": _R_TECH_MGMT + ("marketing_manager", "marketing_tl"),
    "writer_resubmit": _R_ALL_STAFF,
    "writer_resubmit_proofread": _R_ALL_STAFF,
    "complete_formatting": _R_ALL_STAFF,
    "format_decision": _R_ALL_STAFF,
    "format_manager_decision": _R_TECH_MGMT + ("journal_manager", "journal_tl"),
    "proofread_decision": _R_ALL_STAFF,
    "proofread_request_correction": _R_ALL_STAFF,
    "resolve_hold": _R_MANAGERS + ("technical_tl", "journal_tl"),
    "resolve_deadline_extension": _R_MANAGERS + ("technical_tl", "journal_tl"),
    "reject_deadline_extension": _R_MANAGERS + ("technical_tl", "journal_tl"),

    # ---- staff overrides of a client approval (audited) ----
    "override_client_approval_proposal": _R_MANAGERS,
    "override_client_approval_implementation": _R_MANAGERS,
    "override_client_approval_paper": _R_MANAGERS,

    # ---- journal ----
    "add_target_journal": _R_JOURNAL,
    "delete_target_journal": _R_JOURNAL,
    "update_target_journal_status": _R_JOURNAL,
    "select_journal": _R_JOURNAL,
    "set_journal_name": _R_JOURNAL,
    "submit_to_journal": _R_JOURNAL,
    "update_journal_status": _R_JOURNAL,

    # ---- team / employee management ----
    "employee_create": _R_STAFF_MGMT,
    "employee_update": _R_STAFF_MGMT,
    "employee_update_team": _R_STAFF_MGMT,
    "employee_delete": _R_STAFF_MGMT,
    "employee_restore": _R_STAFF_MGMT,
    "employee_reset_password": _R_STAFF_MGMT,
    "set_employee_active": _R_STAFF_MGMT,
    "list_deleted_employees": _R_STAFF_MGMT,

    # ---- admin only ----
    "admin_directory": _R_ADMIN,
    "admin_change_password": _R_ADMIN,
    "set_role_access": _R_ADMIN,
    "delete_client": _R_ADMIN,
    "save_settings": _R_ADMIN,
    "send_email": _R_ADMIN + ("marketing_manager", "marketing_tl"),

    # ---- client-portal actions (staff may also drive them where the UI allows) ----
    "client_approve_proposal": _R_ALL_STAFF,
    "client_approve_paper": _R_ALL_STAFF,
    "client_approve_implementation": _R_ALL_STAFF,
    "client_request_correction_proposal": _R_ALL_STAFF,
    "client_request_correction_paper": _R_ALL_STAFF,
    "client_request_correction_implementation": _R_ALL_STAFF,
}


# =====================================================================
# PER-REQUEST PRINCIPAL
# ---------------------------------------------------------------------
# The server is threaded, so the caller's session is stashed in a
# thread-local for the duration of the request. This lets get_client()
# enforce object-level ownership centrally instead of requiring every one
# of the ~125 handlers to remember to check.
# =====================================================================
_CURRENT = threading.local()


def set_principal(session):
    _CURRENT.session = session


def get_principal():
    return getattr(_CURRENT, "session", None)


def client_family_ids(con, client_id):
    """All client rows belonging to the same CL-ID family (the app's
    "same client, another service" grouping, keyed on display_id)."""
    row = con.execute("SELECT id, display_id FROM clients WHERE id=?", (client_id or "",)).fetchone()
    if not row:
        return set()
    did = row["display_id"] or row["id"]
    return {r["id"] for r in con.execute(
        "SELECT id FROM clients WHERE COALESCE(NULLIF(display_id,''), id)=?", (did,))}


def client_visible_to(con, client_id, session=None):
    """True if the current principal is allowed to see/act on this client."""
    session = session if session is not None else get_principal()
    if not session:
        return False
    if session["kind"] != "client":
        return True          # staff share the client list by product design
    return client_id in client_family_ids(con, session["client_id"])


def session_identity(session):
    """The caller's canonical DM key and display label, derived only from the
    server-side session.

    Key format matches what the frontend and dm_directory already use:
    "EMP:<employee id>" for individually-added employees, "ROLE:<role>" for
    shared department logins.
    """
    if not session:
        return {"key": "", "label": ""}
    if session["kind"] == "employee":
        return {"key": "EMP:%s" % session["emp_id"],
                "label": session["emp_name"] or "Employee"}
    if session["kind"] == "client":
        return {"key": "", "label": "Client"}
    role = session["role"] or ""
    return {"key": "ROLE:%s" % role,
            "label": STAFF_ROLE_LABELS.get(role, role.replace("_", " ").title())}


def authorize(action, session):
    """Deny-by-default gate. Raises ApiError; returns nothing on success.

    Runs after the HTTP layer has bound the caller's real identity to the
    session, so `session["role"]` cannot be influenced by the request body.
    """
    if action in PUBLIC_ACTIONS:
        return
    if not session:
        raise ApiError("Your session has expired. Please log in again.", 401)

    kind = session["kind"]

    if kind == "client":
        if action not in CLIENT_ALLOWED_ACTIONS:
            raise ApiError("Not allowed.", 403)
        return

    allowed = ACTION_ROLES.get(action)
    if allowed is None:
        # Unknown/unmapped action — fail closed.
        raise ApiError("Unknown action.", 404)

    role = session["role"] or ""
    if role in ("super_admin", "md_admin"):
        return
    if role in allowed:
        return
    raise ApiError("You don't have permission to do that.", 403)



def hash_session_token(token):
    """SECURITY: only the HMAC of a session token is stored. The raw token lives
    solely in the user's cookie, so a database leak (or a stray pg_dump backup)
    does not hand the attacker a set of live, ready-to-use sessions."""
    return hmac.new(SECRET_KEY.encode("utf-8"), (token or "").encode("utf-8"),
                    hashlib.sha256).hexdigest()


def create_session(con, kind, role, ip="", emp_id=None, emp_uid=None, emp_name=None,
                    emp_role=None, emp_team_type=None, client_id=None):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    con.execute("""INSERT INTO sessions (token, kind, role, emp_id, emp_uid, emp_name,
                       emp_role, emp_team_type, client_id, ip, csrf)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (hash_session_token(token), kind, role, emp_id, emp_uid, emp_name,
                 emp_role, emp_team_type, client_id, ip, csrf))
    con.commit()
    return {"token": token, "csrf": csrf}


def get_session(con, token):
    if not token:
        return None
    hashed = hash_session_token(token)
    row = con.execute("SELECT * FROM sessions WHERE token=?", (hashed,)).fetchone()
    if not row:
        return None

    def _parse(v):
        try:
            return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return datetime.now()

    # Idle timeout ...
    if _parse(row["last_seen"]) < datetime.now() - timedelta(hours=SESSION_TTL_HOURS):
        con.execute("DELETE FROM sessions WHERE token=?", (hashed,))
        con.commit()
        return None
    # ... and an absolute cap, so a session that is kept warm by a polling tab
    # cannot live forever.
    if _parse(row["created_at"]) < datetime.now() - timedelta(hours=SESSION_MAX_HOURS):
        con.execute("DELETE FROM sessions WHERE token=?", (hashed,))
        con.commit()
        return None

    # SECURITY: re-validate the principal on every request, so disabling a role,
    # deactivating an employee or deleting a client ends live sessions immediately
    # rather than at their next login.
    if row["kind"] == "dept":
        u = con.execute("SELECT enabled FROM users WHERE role=?", (row["role"],)).fetchone()
        if not u or not u["enabled"]:
            con.execute("DELETE FROM sessions WHERE token=?", (hashed,))
            con.commit()
            return None
    elif row["kind"] == "employee":
        e = con.execute("SELECT active, deleted_at FROM employees WHERE id=?",
                        (row["emp_id"],)).fetchone()
        if not e or not e["active"] or e["deleted_at"]:
            con.execute("DELETE FROM sessions WHERE token=?", (hashed,))
            con.commit()
            return None
    elif row["kind"] == "client":
        c = con.execute("SELECT id FROM clients WHERE id=?", (row["client_id"],)).fetchone()
        if not c:
            con.execute("DELETE FROM sessions WHERE token=?", (hashed,))
            con.commit()
            return None

    # Throttle the last_seen write to once a minute (this runs on every request).
    if _parse(row["last_seen"]) < datetime.now() - timedelta(minutes=1):
        con.execute("UPDATE sessions SET last_seen=to_char(now(), 'YYYY-MM-DD HH24:MI:SS') WHERE token=?",
                    (hashed,))
        con.commit()
    return row


def delete_session(con, token):
    if token:
        con.execute("DELETE FROM sessions WHERE token=?", (hash_session_token(token),))
        con.commit()


# Every task_type the "tasks" table is allowed to store. PROPOSAL/IMPLEMENTATION/
# PAPER_WRITING are Technical-team work; PROOFREADING/FORMATTING/SUBMISSION are
# Journal-team work (jmOpenAddTask on the front end). "" means a general/other task
# with no specific type. Any value outside this set is silently reset to "" — that used
# to only include the Technical-team types, which meant every task the Journal Manager
# created via "Add Task" had its type silently wiped, so it could never appear in the
# Journal team's (type-filtered) task lists. Keep this in sync with JOURNAL_TASK_TYPES /
# TECH_TASK_TYPES in index.html.
VALID_TASK_TYPES = ("PROPOSAL", "IMPLEMENTATION", "PAPER_WRITING",
                     "PROOFREADING", "FORMATTING", "SUBMISSION", "")
# Roles allowed to approve a task all the way to COMPLETED. Technical roles for
# Technical-team tasks, Journal roles for Journal-team tasks, Admin for anything.
TASK_COMPLETION_ROLES = ("technical_manager", "technical_tl", "journal_manager", "journal_tl",
                          "md_admin", "super_admin")

# ----- "is typing..." indicators (client<->staff chat + internal DMs) -----
# Deliberately kept in memory, not in the database: it's a fast-expiring signal
# ("someone is typing right now"), not data anyone needs to keep or query later,
# so a lightweight in-process store (with a lock, since requests run on separate
# threads) is the right amount of machinery for it.
_TYPING_LOCK = threading.Lock()
_TYPING_CHAT = {}   # (client_id, thread_with, side) -> last keystroke timestamp; side is "client" or "staff"
_TYPING_DM = {}     # (pair_p1, pair_p2, sender_key) -> last keystroke timestamp
_TYPING_TTL = 6      # seconds a "typing" signal stays valid after the last keystroke ping


def _typing_touch(store, key):
    with _TYPING_LOCK:
        store[key] = time.time()


def _typing_is_active(store, key):
    with _TYPING_LOCK:
        ts = store.get(key)
    return bool(ts) and (time.time() - ts) < _TYPING_TTL


STAGES = [
    "NEW", "TL_REVIEW", "MANAGER_REVIEW", "ACCOUNT_REVIEW", "TECH_ASSIGNED",
    "PROPOSAL_ASSIGNED", "PROPOSAL_SUBMITTED",
    "PROPOSAL_VERIFIED", "PROPOSAL_CLIENT_REVIEW", "PROPOSAL_APPROVED",
    "IMPLEMENTATION_ASSIGNED", "IMPLEMENTATION_COMPLETE",
    "IMPLEMENTATION_CLIENT_REVIEW", "IMPLEMENTATION_APPROVED",
    "PAPERWRITER_ASSIGNED", "COORDINATOR_REVIEW", "WRITER_FIXING", "TECHTL_REVIEW",
    "TECHMGR_REVIEW", "WRITING_COMPLETE", "CLIENT_REVIEW", "CLIENT_ACCEPTED",
    "JOURNAL_MANAGER_REVIEW", "PROOFREAD_COORD_ASSIGNED", "PROOFREADING",
    "PROOFREAD_CORRECTION", "PROOFREAD_RECHECK", "JOURNAL_MANAGER_FORMATTING",
    "FORMATTING_ASSIGNED", "FORMATTING_IN_PROGRESS", "FORMATTING_MANAGER_REVIEW", "SUBMISSION",
    "JOURNAL_SUBMITTED", "COMPLETED",
]
PAY_KEYS = ["reg", "start", "code", "writing", "paper"]
REVIEW_LEVELS = ["COORDINATOR", "TECHTL", "TECHMGR"]
JOURNAL_STATUSES = ["SUBMITTED", "UNDER_REVIEW", "REVISION_REQUESTED", "ACCEPTED", "PUBLISHED", "REJECTED"]


SERVICES = {
    "SCI": {
        "label": "SCI (with implementation)",
        "hasImplementation": True,
        "requiresWritingFee": True,
        "amounts": {"reg": 25000, "start": 25000, "code": 40000, "writing": 20000, "paper": 10000},
    },
    "SCOPUS_PAID": {
        "label": "Scopus paid (with implementation)",
        "hasImplementation": True,
        "requiresWritingFee": False,
        "amounts": {"reg": 20000, "start": 15000, "code": 25000, "paper": 10000},
    },
    "SCOPUS_NO_IMPL": {
        "label": "Scopus (without implementation)",
        "hasImplementation": False,
        "requiresWritingFee": False,
        "amounts": {"reg": 20000, "paper": 15000},
    },
    "SYNOPSIS": {
        "label": "Synopsis",
        "hasImplementation": False,
        "requiresWritingFee": False,
        "amounts": {"reg": 15000, "paper": 10000},
    },
    "SURVEY_SYNOPSIS": {
        "label": "Survey Synopsis",
        "hasImplementation": False,
        "requiresWritingFee": False,
        "amounts": {"reg": 15000, "paper": 10000},
    },
    "THESIS_100": {
        "label": "100 Page Thesis",
        "hasImplementation": False,
        "requiresWritingFee": False,
        "amounts": {"reg": 30000, "paper": 70000},
    },
}
DEFAULT_SERVICE = "SCI"

# Roles allowed to send/resend a client's portal invitation, generate a shareable
# invite link, or reset a client's portal password on their behalf. "employee" is
# included because individually-added Telecallers log in with role="employee".
# SECURITY: "employee" was removed from this list. It was there so individually-added
# Telecallers (who log in with role="employee") could invite clients, but it also let
# every programmer/writer reset any client's portal password. Individually-added
# Telecallers are now allowed through by their employee role instead (see
# _employee_may_invite), not by the blanket "employee" login role.
INVITE_ROLES = ("telecaller", "marketing_tl", "marketing_manager", "md_admin", "super_admin")
# SECURITY: roles allowed to create/manage team members (Team tab on their dashboards).
STAFF_MGMT_ROLES = ("technical_manager", "technical_tl", "marketing_tl", "marketing_manager",
                     "journal_manager", "journal_tl", "md_admin", "super_admin")
# SECURITY: roles allowed to administer logins/employees system-wide (Team & Access screen).
ADMIN_ROLES = ("md_admin", "super_admin")
# FEATURE: roles allowed to change a client's SERVICE and TOTAL AMOUNT after the client has
# already been registered — a tighter set than "who can edit a client at all" (update_client
# below), since the service drives the whole payment schedule.
SERVICE_EDIT_ROLES = ("telecaller", "marketing_tl", "marketing_manager", "md_admin", "super_admin")


def service_conf(key):
    return SERVICES.get(key) or SERVICES[DEFAULT_SERVICE]


def stageIdxServer(stage):
    """Index of a stage within the STAGES pipeline order, for comparing whether one
    stage is chronologically ahead of another (e.g. 'has this client already moved on
    past the point a given task type cares about'). Unknown stages sort last so they
    never get treated as 'earlier'."""
    try:
        return STAGES.index(stage)
    except ValueError:
        return len(STAGES)


def portal_link(display_id, token, origin=None):
    """Direct one-click link that opens the portal straight into the
    'create your password' screen with the Client ID and setup code
    already filled in.

    Prefer `origin` (the address actually in the staff member's browser bar,
    e.g. https://your-real-domain.com or http://192.168.1.5:8000 — sent by
    the frontend as window.location.origin) since that's guaranteed to be an
    address other devices can actually reach. Only fall back to guessing
    this machine's LAN IP when no origin was supplied (e.g. a direct API
    call) - that guess can be wrong (multiple network adapters, VPNs) and
    literally never works if it falls back to localhost, since 'localhost'
    on the CLIENT's own phone/laptop just points back to their own device,
    not this server."""
    if origin:
        return f"{origin.rstrip('/')}/?setup={display_id}:{token}"
    ip = lan_ip()
    host = f"{ip}:{PORT}" if ip and ip != "127.0.0.1" else f"localhost:{PORT}"
    return f"http://{host}/?setup={display_id}:{token}"


def invite_email_html(name, display_id, token, link):
    """An attractive, card-style HTML invitation email (matches the visual
    style of the in-app invitation card)."""
    safe_name = (name or "there")
    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:32px 16px;background:#f4efe6;font-family:Segoe UI,Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" style="max-width:520px;margin:0 auto;border-collapse:collapse;">
    <tr><td style="padding-bottom:18px;">
      <span style="font-size:20px;font-weight:800;color:#1a1a1a;letter-spacing:.3px;">MATIZ&nbsp;TECHNOLOGY</span>
    </td></tr>
    <tr><td style="background:#ffffff;border-radius:16px;padding:36px 32px;box-shadow:0 1px 3px rgba(0,0,0,.06);">
      <h1 style="margin:0 0 18px;font-size:25px;line-height:1.3;color:#1a1a1a;">Your client portal is ready, {esc_html(safe_name)}</h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.6;color:#3a3a3a;">
        You can now track your project, chat with your team, and view updates any time — right from your own iMatiz portal.
      </p>
      <table role="presentation" style="width:100%;background:#faf6ee;border:1px solid #ecdfc4;border-radius:12px;
             margin:0 0 26px;border-collapse:collapse;">
        <tr>
          <td style="padding:16px 20px;border-bottom:1px solid #ecdfc4;">
            <div style="font-size:12px;color:#8a7a4e;letter-spacing:.4px;text-transform:uppercase;">Your Client ID</div>
            <div style="font-size:19px;font-weight:800;color:#1a1a1a;margin-top:3px;">{esc_html(display_id)}</div>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 20px;">
            <div style="font-size:12px;color:#8a7a4e;letter-spacing:.4px;text-transform:uppercase;">One-time setup code</div>
            <div style="font-size:19px;font-weight:800;color:#1a1a1a;margin-top:3px;letter-spacing:1px;">{esc_html(token)}</div>
          </td>
        </tr>
      </table>
      <table role="presentation" style="width:100%;border-collapse:collapse;margin:0 0 24px;">
        <tr><td align="center">
          <a href="{esc_html(link)}"
             style="display:inline-block;background:#1a1a1a;color:#ffffff;text-decoration:none;
                    font-weight:700;font-size:15px;padding:14px 34px;border-radius:9px;">
            Set up my password
          </a>
        </td></tr>
      </table>
      <p style="margin:0 0 6px;font-size:12.5px;line-height:1.6;color:#8a8a8a;">
        Prefer to do it manually? Open the iMatiz portal, choose <b>Client</b>, then
        <b>First time? Set your password</b>, and enter your Client ID and setup code above.
      </p>
      <p style="margin:18px 0 0;font-size:12.5px;line-height:1.6;color:#8a8a8a;">
        Keep your Client ID and password safe — you'll use them every time you log in.
      </p>
    </td></tr>
    <tr><td style="padding:22px 6px 0;font-size:13px;color:#8a8a8a;">
      Happy building,<br>The iMatiz Technology Team
    </td></tr>
  </table>
</body>
</html>"""


def esc_html(s):
    return (str(s or "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code



# =====================================================================
# DATABASE LAYER — PostgreSQL (psycopg2), behind a thin sqlite3-shaped shim.
#
# The rest of this file was written against sqlite3's connection/cursor API
# (con.execute(sql, params).fetchone()/.fetchall(), dict-like row access by
# column name, cur.lastrowid, con.commit()/.close()). Rather than touch the
# ~300 call sites, PGConnection/PGCursor below reproduce that exact surface
# on top of psycopg2, so every existing call site works unchanged:
#   - '?' positional placeholders are rewritten to psycopg2's '%s' before
#     each execute(). This app's SQL text never contains a literal '?'
#     inside a string literal (verified by inspection — the only '%'
#     wildcards for LIKE are applied to bind values in Python, never
#     written into the SQL text), so a plain string replace is safe.
#   - rows come back as psycopg2 RealDictRow, which supports row["col"]
#     exactly like sqlite3.Row.
#   - INSERTs into tables with a SERIAL id column automatically get
#     "RETURNING id" appended so cur.lastrowid keeps working.
# =====================================================================
import psycopg2
import psycopg2.extras
import psycopg2.pool

DATABASE_URL = _env("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise SystemExit(
        "FATAL: DATABASE_URL is not set. This app stores its data in PostgreSQL — "
        "set DATABASE_URL to a postgres connection string.\n"
        "  Render: add a PostgreSQL database to this service and it is provided "
        "automatically (see render.yaml).\n"
        "  Local development: run a Postgres instance and set DATABASE_URL in .env, "
        "e.g. postgresql://matiz:matiz@localhost:5432/matiz")
# Render (and several other hosts) hand out "postgres://" URLs; psycopg2 wants
# "postgresql://". Accept either.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

# Keeps both sides of every "is this session/link still fresh?" comparison on
# the same clock: Postgres sessions from this pool report time in APP_TZ, and
# Python's own datetime.now() follows the OS TZ setting — set the TZ
# environment variable (e.g. TZ=Asia/Kolkata) to move both together. Left
# unset, everything is UTC, which matches how this app behaves out of the box
# on Render today.
APP_TZ = _env("TZ", "UTC").strip() or "UTC"

try:
    _PG_POOL = psycopg2.pool.ThreadedConnectionPool(
        1, 20, DATABASE_URL, options=f"-c timezone={APP_TZ}")
except psycopg2.OperationalError as e:
    raise SystemExit(f"FATAL: could not connect to PostgreSQL using DATABASE_URL: {e}")

# SQL expression used everywhere the old code said datetime('now','localtime') —
# a plain 'YYYY-MM-DD HH:MM:SS' string in the session timezone above, with no
# fractional seconds, matching the exact format get_session() parses with
# datetime.strptime(v, "%Y-%m-%d %H:%M:%S").
_NOW_SQL = "to_char(now(), 'YYYY-MM-DD HH24:MI:SS')"

_INSERT_TABLE_RE = re.compile(r"(?is)^\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)")

# Tables with a SERIAL id column whose INSERTs rely on cur.lastrowid.
_SERIAL_ID_TABLES = {
    "employees", "calls", "payments", "history", "work_updates", "service_items",
    "client_installments", "journal_targets", "messages", "thread_reads",
    "dm_messages", "dm_reads", "calendar_events", "client_queries", "tasks",
    "task_comments", "client_documents", "client_notes_v2", "client_referrals",
}


def _qmark_to_pyformat(sql):
    return sql.replace("?", "%s")


class PGCursor:
    """Shim over a psycopg2 cursor matching the handful of sqlite3.Cursor
    features this app relies on: .fetchone()/.fetchall()/.lastrowid/iteration."""

    def __init__(self, cur):
        self._cur = cur
        self.lastrowid = None

    def _run(self, sql, params):
        sql = _qmark_to_pyformat(sql)
        m = _INSERT_TABLE_RE.match(sql)
        wants_id = bool(m and m.group(1).lower() in _SERIAL_ID_TABLES
                        and "returning" not in sql.lower())
        if wants_id:
            sql = sql.rstrip().rstrip(";") + " RETURNING id"
        self._cur.execute(sql, params or None)
        if wants_id:
            row = self._cur.fetchone()
            self.lastrowid = row["id"] if row else None
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __iter__(self):
        return iter(self._cur)


class PGConnection:
    """Shim over a pooled psycopg2 connection matching the sqlite3.Connection
    surface this app relies on: .execute()/.executescript()/.commit()/
    .rollback()/.close(), with rows addressable by column name."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return PGCursor(cur)._run(sql, params)

    def executescript(self, script):
        # psycopg2 sends the whole string as one query, and Postgres's simple
        # query protocol runs every ';'-separated statement in it — enough for
        # the schema-creation scripts below (no bind parameters needed there).
        cur = self._conn.cursor()
        cur.execute(script)
        return self

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            _PG_POOL.putconn(self._conn)
        except Exception:
            try:
                self._conn.close()
            except Exception:
                pass


def db():
    conn = _PG_POOL.getconn()
    conn.autocommit = False
    return PGConnection(conn)


def init_db():
    con = db()
    con.executescript(f"""
    CREATE TABLE IF NOT EXISTS users (
        role TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS employees (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT DEFAULT '',
        domain TEXT DEFAULT '',
        address TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        reg_date TEXT NOT NULL,
        deadline_date TEXT NOT NULL,
        stage TEXT NOT NULL DEFAULT 'NEW',
        proposal_verified_by TEXT DEFAULT '',
        assigned_programmers TEXT DEFAULT '',
        implementation_deadline TEXT,
        assigned_writers TEXT DEFAULT '',
        next_follow_up TEXT,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS calls (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        call_type TEXT NOT NULL,
        note TEXT DEFAULT '',
        next_date TEXT,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        pay_key TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        amount REAL,
        pay_date TEXT,
        UNIQUE (client_id, pay_key)
    );
    CREATE TABLE IF NOT EXISTS history (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        stage TEXT NOT NULL,
        actor TEXT NOT NULL,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        from_email TEXT NOT NULL,
        to_email TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS work_updates (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        emp_name TEXT NOT NULL,
        milestone TEXT NOT NULL,
        note TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS service_items (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        pay_key TEXT NOT NULL,
        name TEXT NOT NULL,
        amount REAL NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS client_installments (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        amount REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        paid_date TEXT,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS journal_targets (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT '',
        added_by TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        thread_with TEXT NOT NULL,
        sender_type TEXT NOT NULL CHECK (sender_type IN ('client','staff')),
        sender_name TEXT NOT NULL,
        body TEXT DEFAULT '',
        file_name TEXT DEFAULT '',
        file_type TEXT DEFAULT '',
        file_data TEXT DEFAULT '',
        read_by_client INTEGER NOT NULL DEFAULT 0,
        read_by_staff INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS thread_reads (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        thread_with TEXT NOT NULL,
        viewer_key TEXT NOT NULL,
        last_read_id INTEGER NOT NULL DEFAULT 0,
        UNIQUE(client_id, thread_with, viewer_key)
    );
    CREATE TABLE IF NOT EXISTS dm_messages (
        id SERIAL PRIMARY KEY,
        p1 TEXT NOT NULL,
        p2 TEXT NOT NULL,
        sender_key TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        body TEXT DEFAULT '',
        file_name TEXT DEFAULT '',
        file_type TEXT DEFAULT '',
        file_data TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS dm_reads (
        id SERIAL PRIMARY KEY,
        p1 TEXT NOT NULL,
        p2 TEXT NOT NULL,
        viewer_key TEXT NOT NULL,
        last_read_at TEXT,
        UNIQUE(p1, p2, viewer_key)
    );
    CREATE TABLE IF NOT EXISTS calendar_events (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        event_date TEXT NOT NULL,
        note TEXT DEFAULT '',
        color TEXT DEFAULT 'gold',
        created_by TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS client_queries (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        query_text TEXT NOT NULL,
        query_date TEXT NOT NULL,
        assigned_to TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'OPEN',
        resolved_on TEXT,
        reply_text TEXT DEFAULT '',
        replied_on TEXT,
        created_by TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        client_id TEXT REFERENCES clients(id) ON DELETE CASCADE,
        priority TEXT NOT NULL DEFAULT 'MEDIUM',
        start_date TEXT,
        finish_date TEXT,
        status TEXT NOT NULL DEFAULT 'OPEN',
        assigned_to TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS task_comments (
        id SERIAL PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        author TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS client_documents (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        file_name TEXT NOT NULL,
        file_type TEXT DEFAULT '',
        file_data TEXT NOT NULL,
        uploaded_by TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS client_notes_v2 (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS client_referrals (
        id SERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        designation TEXT DEFAULT '',
        name TEXT NOT NULL,
        email TEXT DEFAULT '',
        mobile TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL})
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        role TEXT NOT NULL,
        emp_id INTEGER,
        emp_uid TEXT,
        emp_name TEXT,
        emp_role TEXT,
        emp_team_type TEXT,
        client_id TEXT,
        ip TEXT DEFAULT '',
        csrf TEXT DEFAULT '',
        created_at TEXT DEFAULT ({_NOW_SQL}),
        last_seen TEXT DEFAULT ({_NOW_SQL})
    );
    """)
    con.commit()

    # ----- idempotent "add column if missing" migrations. Postgres supports
    #       ADD COLUMN IF NOT EXISTS directly, so (unlike the old sqlite version)
    #       there is no need to first list existing columns via PRAGMA table_info. -----
    for col, decl in [("alt_mobile", "TEXT DEFAULT ''"), ("institutional_email", "TEXT DEFAULT ''"),
                       ("department", "TEXT DEFAULT ''"), ("referred_by", "TEXT DEFAULT ''"),
                       ("client_password", "TEXT DEFAULT ''"), ("invite_token", "TEXT DEFAULT ''"),
                       ("invite_sent_at", "TEXT DEFAULT ''"), ("last_login_at", "TEXT DEFAULT ''"),
                       ("password_reset_requested", "INTEGER NOT NULL DEFAULT 0"),
                       ("password_reset_requested_at", "TEXT DEFAULT ''")]:
        con.execute(f"ALTER TABLE clients ADD COLUMN IF NOT EXISTS {col} {decl}")
    for col, decl in [("event_time", "TEXT DEFAULT ''"), ("visibility", "TEXT DEFAULT 'everyone'"),
                       ("created_by_id", "TEXT DEFAULT ''")]:
        con.execute(f"ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS {col} {decl}")
    con.commit()

    users = [
        ("super_admin", "Super Admin"), ("md_admin", "MD / Admin"),
        ("telecaller", "Telecaller"), ("marketing_tl", "Marketing TL"),
        ("marketing_manager", "Marketing Manager"), ("account_team", "Accounts Team"),
        ("technical_manager", "Technical Manager"), ("technical_tl", "Technical TL"),
        ("content_coordinator", "Content Coordinator"),
        ("journal_manager", "Journal Manager"), ("journal_tl", "Journal TL"),
        ("employee", "Team Member"), ("client", "Client"),
    ]
    # SECURITY: no shared default password. Previously every department login was
    # seeded with "0803", a value printed in the README, so anyone who could reach
    # the URL could sign in as Super Admin. Admin logins now take their password
    # from INITIAL_ADMIN_PASSWORD on first run; the rest are created disabled and
    # must have a password set by the Super Admin under Team & Access.
    _existing_users = {r["role"] for r in con.execute("SELECT role FROM users")}
    _admin_hash = ""
    if INITIAL_ADMIN_PASSWORD:
        if len(INITIAL_ADMIN_PASSWORD) < MIN_PASSWORD_LENGTH:
            raise SystemExit("FATAL: INITIAL_ADMIN_PASSWORD must be at least %d characters."
                             % MIN_PASSWORD_LENGTH)
        _admin_hash = hash_password(INITIAL_ADMIN_PASSWORD)
    elif not _existing_users:
        if IS_PRODUCTION:
            raise SystemExit(
                "FATAL: this is a brand-new database and APP_ENV=production, so there is no\n"
                "admin account yet. Set INITIAL_ADMIN_PASSWORD (8+ characters) and start again.\n"
                "Remove it from the environment once you have signed in.")
        _generated = secrets.token_urlsafe(12)
        _admin_hash = hash_password(_generated)
        print("=" * 60)
        print("  FIRST RUN — a Super Admin / MD Admin password has been generated:")
        print("      %s" % _generated)
        print("  This is shown once. Sign in and change it under Team & Access.")
        print("=" * 60)

    for role, label in users:
        if role in _existing_users:
            continue
        if role in ("super_admin", "md_admin") and _admin_hash:
            con.execute("""INSERT INTO users (role, display_name, password) VALUES (?,?,?)
                           ON CONFLICT (role) DO NOTHING""", (role, label, _admin_hash))
        else:
            # No usable password: created empty. verify_password() rejects an empty
            # stored hash, so these cannot be logged into until one is set.
            con.execute("""INSERT INTO users (role, display_name, password) VALUES (?,?,'')
                           ON CONFLICT (role) DO NOTHING""", (role, label))
    con.commit()

    con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS enabled INTEGER NOT NULL DEFAULT 1")
    con.commit()

    con.execute("ALTER TABLE clients ADD COLUMN IF NOT EXISTS service_key TEXT DEFAULT '%s'" % DEFAULT_SERVICE)
    con.execute("ALTER TABLE clients ADD COLUMN IF NOT EXISTS writing_approved_at TEXT")

    for col, decl in [
        ("team_type", "TEXT DEFAULT ''"), ("emp_uid", "TEXT"),
        # SECURITY: no default password for employees either (was '0803').
        ("password", "TEXT DEFAULT ''"), ("email", "TEXT DEFAULT ''"),
        ("is_coordinator", "INTEGER NOT NULL DEFAULT 0"), ("coordinator_id", "INTEGER"),
        ("deleted_at", "TEXT"), ("joining_date", "TEXT DEFAULT ''"),
        ("date_of_birth", "TEXT DEFAULT ''"), ("branch", "TEXT DEFAULT ''"),
        ("department", "TEXT DEFAULT ''"), ("phone", "TEXT DEFAULT ''"),
        ("designation", "TEXT DEFAULT ''"),
    ]:
        con.execute(f"ALTER TABLE employees ADD COLUMN IF NOT EXISTS {col} {decl}")
    con.commit()

    con.execute("UPDATE employees SET role='PAPER_WRITER', is_coordinator=1 WHERE role='COORDINATOR'")
    con.commit()

    if con.execute("SELECT COUNT(*) c FROM employees").fetchone()["c"] == 0:
        for n in ("Janani", "Aishwarya", "Satish"):
            con.execute("INSERT INTO employees (name, role) VALUES (?, 'PROGRAMMER')", (n,))
        for n in ("Kavikeerthana", "Dhanpriya"):
            con.execute("INSERT INTO employees (name, role) VALUES (?, 'PAPER_WRITER')", (n,))
    con.commit()

    missing = con.execute("SELECT id FROM employees WHERE emp_uid IS NULL OR emp_uid=''").fetchall()
    if missing:
        n = 1001
        for r in con.execute("SELECT emp_uid FROM employees WHERE emp_uid IS NOT NULL AND emp_uid<>''"):
            m = re.match(r"^EMP-(\d+)$", r["emp_uid"] or "")
            if m:
                n = max(n, int(m.group(1)) + 1)
        for r in missing:
            con.execute("UPDATE employees SET emp_uid=? WHERE id=?",
                        (f"EMP-{n}", r["id"]))
            n += 1
        con.commit()

    for col, decl in [("rejected", "INTEGER NOT NULL DEFAULT 0"), ("reject_reason", "TEXT DEFAULT ''"),
                       ("rejected_at", "TEXT")]:
        con.execute(f"ALTER TABLE clients ADD COLUMN IF NOT EXISTS {col} {decl}")
    con.commit()

    extra_cols = {
        "writing_deadline": "TEXT",
        "demo_completed_date": "TEXT",
        "review_level": "TEXT DEFAULT ''",
        "coordinator_name": "TEXT DEFAULT ''",
        "coordinator_rounds": "INTEGER NOT NULL DEFAULT 0",
        "techtl_rounds": "INTEGER NOT NULL DEFAULT 0",
        "techmgr_rounds": "INTEGER NOT NULL DEFAULT 0",
        "client_approved_at": "TEXT",
        "journal_name": "TEXT DEFAULT ''",
        "proofread_coordinator": "TEXT DEFAULT ''",
        "assigned_proofreaders": "TEXT DEFAULT ''",
        "proofread_rounds": "INTEGER NOT NULL DEFAULT 0",
        "format_coordinator": "TEXT DEFAULT ''",
        "assigned_formatters": "TEXT DEFAULT ''",
        "format_rounds": "INTEGER NOT NULL DEFAULT 0",
        "submission_person": "TEXT DEFAULT ''",
        "journal_status": "TEXT DEFAULT ''",
        "proposal_writer": "TEXT DEFAULT ''",
        "proposal_deadline": "TEXT",
        "proposal_submitted_at": "TEXT",
        "on_hold": "INTEGER NOT NULL DEFAULT 0",
        "hold_reason": "TEXT DEFAULT ''",
        "hold_requested_by": "TEXT DEFAULT ''",
        "requested_deadline": "TEXT",
        "ext_requested": "INTEGER NOT NULL DEFAULT 0",
        "ext_reason": "TEXT DEFAULT ''",
        "ext_requested_by": "TEXT DEFAULT ''",
        "ext_amount": "TEXT DEFAULT ''",
        "ext_target": "TEXT DEFAULT ''",
        "proposal_coordinator": "TEXT DEFAULT ''",
        "proposal_awaiting_team_pick": "INTEGER NOT NULL DEFAULT 0",
        "writing_awaiting_team_pick": "INTEGER NOT NULL DEFAULT 0",
        "impl_coordinator": "TEXT DEFAULT ''",
        "impl_awaiting_team_pick": "INTEGER NOT NULL DEFAULT 0",
        "project_id": "TEXT",
        "designation": "TEXT DEFAULT ''",
        "institution": "TEXT DEFAULT ''",
        "topic": "TEXT DEFAULT ''",
        "technical_person": "TEXT DEFAULT ''",
        "base_paper_provided": "INTEGER NOT NULL DEFAULT 0",
        "bdc": "TEXT DEFAULT ''",
        "total_amount": "REAL DEFAULT 0",
        "demo_given_date": "TEXT",
        "demo_satisfied": "TEXT DEFAULT ''",
        "demo_approved_at": "TEXT",
        "demo_approved_by": "TEXT DEFAULT ''",
        # ----- pre-assignment: Technical Manager/TL can pick the implementation team and/or
        #       paper writer(s) up front, at the same time as the proposal writer, instead of
        #       coming back later. These are held here and applied automatically (auto-assigned,
        #       no extra click needed) the moment the client reaches the stage where that work
        #       would normally become assignable.
        "pre_impl_programmers": "TEXT DEFAULT ''",
        "pre_impl_deadline": "TEXT DEFAULT ''",
        "pre_impl_by": "TEXT DEFAULT ''",
        "pre_write_writers": "TEXT DEFAULT ''",
        "pre_write_deadline": "TEXT DEFAULT ''",
        "pre_write_by": "TEXT DEFAULT ''",
        "installment_plan_name": "TEXT DEFAULT ''",
        # ----- demo scheduling: Marketing TL/Manager schedule an upcoming demo (paper or
        #       code) for a client. This is separate from demo_given_date/demo_completed_date
        #       above, which record that a demo already happened - these fields record one
        #       that is coming up, so Technical Manager/TL and the specific employee doing the
        #       work (and their calendar) can see it ahead of time.
        "demo_scheduled_type": "TEXT DEFAULT ''",     # 'code' or 'paper'
        "demo_scheduled_date": "TEXT DEFAULT ''",
        "demo_scheduled_time": "TEXT DEFAULT ''",
        "demo_scheduled_note": "TEXT DEFAULT ''",
        "demo_scheduled_emp": "TEXT DEFAULT ''",      # who it's for (Programmer or Paper Writer)
        "demo_scheduled_by": "TEXT DEFAULT ''",       # Marketing TL/Manager who scheduled it
        "demo_schedule_status": "TEXT DEFAULT ''",    # 'SCHEDULED' / '' (cleared once done/cancelled)
        "writing_demo_given_date": "TEXT DEFAULT ''",
    }
    for col, decl in extra_cols.items():
        con.execute(f"ALTER TABLE clients ADD COLUMN IF NOT EXISTS {col} {decl}")
    con.commit()

    con.execute("ALTER TABLE tasks ADD COLUMN IF NOT EXISTS task_type TEXT DEFAULT ''")
    con.commit()

    con.execute("ALTER TABLE clients ADD COLUMN IF NOT EXISTS display_id TEXT")
    con.execute("UPDATE clients SET display_id = id WHERE display_id IS NULL OR display_id=''")
    con.commit()

    # Backfill Project IDs (PRJ-2001...) for any existing rows that don't have one yet -
    # every service/record gets its own Project ID, separate from the shared CL-ID.
    missing_proj = con.execute(
        "SELECT id FROM clients WHERE project_id IS NULL OR project_id='' ORDER BY created_at ASC, id ASC").fetchall()
    if missing_proj:
        pn = 2001
        for r in con.execute("SELECT project_id FROM clients WHERE project_id IS NOT NULL AND project_id<>''"):
            m = re.match(r"^PRJ-(\d+)$", r["project_id"] or "")
            if m:
                pn = max(pn, int(m.group(1)) + 1)
        for r in missing_proj:
            con.execute("UPDATE clients SET project_id=? WHERE id=?", (f"PRJ-{pn}", r["id"]))
            pn += 1
        con.commit()

    # ----- one-time repair: some client records from before family-linking existed (or
    #       added a different way) share the same phone/email as another client but never
    #       got grouped under the same display_id - so their "other services" switcher never
    #       finds each other and the client portal only ever showed the most recent one.
    #       Group them here by normalized phone (falling back to email) and unify each group
    #       under its earliest record's display_id.
    rows = con.execute(
        "SELECT id, display_id, phone, email, created_at FROM clients ORDER BY created_at ASC, id ASC").fetchall()
    groups = {}
    for r in rows:
        key = None
        if r["phone"] and r["phone"].strip():
            key = "p:" + re.sub(r"\s+", "", r["phone"]).lower()
        elif r["email"] and r["email"].strip():
            key = "e:" + r["email"].strip().lower()
        if not key:
            continue
        groups.setdefault(key, []).append(r)
    for members in groups.values():
        did_set = {(m["display_id"] or m["id"]) for m in members}
        if len(did_set) > 1:
            canonical = members[0]["display_id"] or members[0]["id"]
            for m in members:
                if (m["display_id"] or m["id"]) != canonical:
                    con.execute("UPDATE clients SET display_id=? WHERE id=?", (canonical, m["id"]))
    con.commit()

    # ----- Delivery + client-approval gate restored for Proposal, Code Implementation, and
    #       Paper Writing (Technical Manager / Technical TL request, see UPDATE_NOTES). Any
    #       client left sitting at the OLD "sent to client, awaiting approval" holding stages
    #       (IMPLEMENTATION_CLIENT_REVIEW / CLIENT_REVIEW) from before this restore is left
    #       exactly where it is — those stages are meaningful again, so the Technical TL /
    #       Manager dashboards will simply show them as "delivered — waiting on the client",
    #       same as any new client reaching that point from now on. No migration needed.

    con.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS note TEXT DEFAULT ''")
    con.commit()

    con.execute("""INSERT INTO settings (id, from_email, to_email) VALUES (1, ?, ?)
                   ON CONFLICT (id) DO NOTHING""", (DEFAULT_FROM_EMAIL, DEFAULT_TO_EMAIL))
    con.commit()

    # ----- SECURITY: migrate any legacy plain-text passwords to salted PBKDF2 hashes.
    #       Runs on every startup but is a no-op once a password is already hashed, so
    #       it is safe to leave in place permanently. Existing logins (e.g. the shared
    #       default "0803") keep working exactly as before — only the storage changes.
    for r in con.execute("SELECT role, password FROM users"):
        if r["password"] and not is_hashed_password(r["password"]):
            con.execute("UPDATE users SET password=? WHERE role=?",
                        (hash_password(r["password"]), r["role"]))
    for r in con.execute("SELECT id, password FROM employees"):
        if r["password"] and not is_hashed_password(r["password"]):
            con.execute("UPDATE employees SET password=? WHERE id=?",
                        (hash_password(r["password"]), r["id"]))
    for r in con.execute("SELECT id, client_password FROM clients "
                          "WHERE client_password IS NOT NULL AND client_password<>''"):
        if not is_hashed_password(r["client_password"]):
            con.execute("UPDATE clients SET client_password=? WHERE id=?",
                        (hash_password(r["client_password"]), r["id"]))
    con.commit()

    # ----- SECURITY: purge any expired sessions left over from a previous run. Computed
    #       in Python (rather than a SQL-side "now") so it uses the exact same clock as
    #       get_session()'s own idle-timeout check above.
    _cutoff = (datetime.now() - timedelta(hours=SESSION_TTL_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    con.execute("DELETE FROM sessions WHERE last_seen < ?", (_cutoff,))
    con.commit()
    con.close()


# ---------------------------------------------------------- helpers
def iso(v):
    return v.replace(" ", "T") if v else None


def amt(v):
    if v is None or v == "":
        return ""
    s = f"{float(v):.2f}".rstrip("0").rstrip(".")
    return s


def names(csv_str):
    return [x for x in (csv_str or "").split(",") if x]


XLSX_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _col_to_idx(col_letters):
    idx = 0
    for ch in col_letters:
        idx = idx * 26 + (ord(ch.upper()) - ord("A") + 1)
    return idx - 1


def _excel_serial_to_iso(n):
    try:
        base = datetime(1899, 12, 30)
        return (base + timedelta(days=float(n))).date().isoformat()
    except Exception:
        return None


def read_xlsx_rows(file_bytes):
    """Minimal .xlsx reader (first worksheet only), stdlib-only (zipfile + XML) -
    no openpyxl / pandas required, so this keeps working on a plain Python install."""
    z = zipfile.ZipFile(io.BytesIO(file_bytes))
    names_in_zip = z.namelist()
    shared = []
    if "xl/sharedStrings.xml" in names_in_zip:
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        for si in root.findall(XLSX_NS + "si"):
            texts = si.findall(XLSX_NS + "t")
            if texts:
                shared.append("".join(t.text or "" for t in texts))
            else:
                runs = si.findall(XLSX_NS + "r")
                shared.append("".join((r.find(XLSX_NS + "t").text or "")
                                       for r in runs if r.find(XLSX_NS + "t") is not None))
    sheet_path = next((n for n in names_in_zip
                        if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")), None)
    if not sheet_path:
        raise ApiError("That file doesn't look like a valid .xlsx workbook.")
    root = ET.fromstring(z.read(sheet_path))
    sheet_data = root.find(XLSX_NS + "sheetData")
    rows = []
    if sheet_data is None:
        return rows
    for row_el in sheet_data.findall(XLSX_NS + "row"):
        cells, max_idx = {}, -1
        for c_el in row_el.findall(XLSX_NS + "c"):
            ref = c_el.get("r") or ""
            col_letters = "".join(ch for ch in ref if ch.isalpha())
            idx = _col_to_idx(col_letters) if col_letters else (max_idx + 1)
            ctype = c_el.get("t")
            v_el, is_el = c_el.find(XLSX_NS + "v"), c_el.find(XLSX_NS + "is")
            value = None
            if ctype == "s" and v_el is not None:
                si = int(v_el.text)
                value = shared[si] if 0 <= si < len(shared) else ""
            elif ctype == "inlineStr" and is_el is not None:
                t_el = is_el.find(XLSX_NS + "t")
                value = t_el.text if t_el is not None else ""
            elif v_el is not None:
                raw = v_el.text
                try:
                    value = float(raw)
                    if value.is_integer():
                        value = int(value)
                except (TypeError, ValueError):
                    value = raw
            cells[idx] = value
            max_idx = max(max_idx, idx)
        rows.append([cells.get(i) for i in range(max_idx + 1)])
    return rows


HEADER_ALIASES = {
    "name": "name", "client name": "name", "client": "name", "customer name": "name",
    "phone": "phone", "phone number": "phone", "mobile": "phone", "mobile number": "phone",
    "contact": "phone", "contact number": "phone", "whatsapp": "phone",
    "email": "email", "email id": "email", "mail": "email", "e-mail": "email",
    "domain": "domain", "project domain": "domain", "topic": "domain",
    "address": "address", "location": "address", "city": "address",
    "date": "regDate", "reg date": "regDate", "registration date": "regDate", "reg_date": "regDate",
    "deadline": "deadlineDate", "deadline date": "deadlineDate", "project deadline": "deadlineDate",
    "reg/2nd work": "callType", "work type": "callType", "call type": "callType",
}


def _map_headers(header_row):
    mapping, extra_labels = {}, {}
    for i, h in enumerate(header_row):
        label = (str(h).strip() if h is not None else "")
        field = HEADER_ALIASES.get(label.lower())
        mapping[i] = field
        if not field:
            extra_labels[i] = label or f"Column {i + 1}"
    return mapping, extra_labels


def _normalize_date_str(s):
    s = (s or "").strip()
    if not s:
        return date.today().isoformat()
    if re.match(r"^\d{4}-\d{2}-\d{2}", s):
        return s[:10]
    m = re.match(r"^(\d{1,2})[/\-](\d{1,2})[/\-](\d{2,4})$", s)
    if m:
        d, mo, y = m.groups()
        y = y if len(y) == 4 else ("20" + y)
        try:
            return date(int(y), int(mo), int(d)).isoformat()
        except Exception:
            pass
    return s


def _default_deadline(reg_iso):
    try:
        y, m, dd = [int(x) for x in reg_iso.split("-")[:3]]
        return (date(y, m, dd) + timedelta(days=30)).isoformat()
    except Exception:
        return reg_iso


def _row_to_fields(row, mapping, extra_labels):
    out = {"name": "", "phone": "", "email": "", "domain": "", "address": "",
           "regDate": "", "deadlineDate": "", "callType": ""}
    extra_notes = []
    for i, val in enumerate(row):
        if val is None:
            continue
        sval = str(val).strip()
        if sval == "":
            continue
        field = mapping.get(i)
        if field in ("regDate", "deadlineDate"):
            out[field] = (_excel_serial_to_iso(val) or sval) if isinstance(val, (int, float)) \
                else _normalize_date_str(sval)
        elif field:
            out[field] = sval
        else:
            extra_notes.append(f"{extra_labels.get(i, f'Column {i + 1}')}: {sval}")
    return out, extra_notes


def parse_sheet_rows(rows):
    """Turn raw spreadsheet rows (first = header) into (rowNumber, fields, extraNotes) tuples."""
    if not rows:
        return []
    header, data_rows = rows[0], rows[1:]
    mapping, extra_labels = _map_headers(header)
    if mapping.get(0) is None and "regDate" not in mapping.values():
        sample = [r[0] for r in data_rows[:5] if len(r) > 0 and r[0] not in (None, "")]
        if sample and all(isinstance(v, (int, float)) for v in sample):
            mapping[0] = "regDate"
            extra_labels.pop(0, None)
    out = []
    for idx, row in enumerate(data_rows, start=2):
        if not any((str(v).strip() if v is not None else "") for v in row):
            continue
        fields, extra_notes = _row_to_fields(row, mapping, extra_labels)
        out.append((idx, fields, extra_notes))
    return out


def check_pay_key(k):
    if k not in PAY_KEYS:
        raise ApiError("Invalid payment stage.")


STAFF_ROLE_LABELS = {
    "super_admin": "Super Admin", "md_admin": "MD / Admin", "telecaller": "Telecaller",
    "marketing_tl": "Marketing TL", "marketing_manager": "Marketing Manager",
    "account_team": "Accounts Team", "technical_manager": "Technical Manager",
    "technical_tl": "Technical TL", "journal_manager": "Journal Manager", "journal_tl": "Journal TL",
}
EMP_ROLE_GROUP_LABELS = {"PROGRAMMER": "Programmer", "PAPER_WRITER": "Paper Writer", "JOURNAL_EMPLOYEE": "Journal Team"}


def dm_pair(a, b):
    return (a, b) if a <= b else (b, a)


def dm_person_name(con, key):
    if key.startswith("EMP:"):
        try:
            eid = int(key[4:])
        except ValueError:
            return key
        r = con.execute("SELECT name FROM employees WHERE id=?", (eid,)).fetchone()
        return r["name"] if r else "Former employee"
    if key.startswith("ROLE:"):
        return STAFF_ROLE_LABELS.get(key[5:], key[5:])
    return key


STAGE_LABELS = {
    "NEW": "Lead entry (Telecaller)", "TL_REVIEW": "Marketing TL review",
    "MANAGER_REVIEW": "Marketing Manager review", "ACCOUNT_REVIEW": "Accounts review",
    "TECH_ASSIGNED": "Sent to Technical Team", "PROPOSAL_ASSIGNED": "Proposal writing assigned",
    "PROPOSAL_SUBMITTED": "Proposal submitted - awaiting verification",
    "PROPOSAL_VERIFIED": "Proposal approved by TM/TL - ready for delivery to client",
    "PROPOSAL_CLIENT_REVIEW": "Proposal delivered - awaiting client approval",
    "PROPOSAL_APPROVED": "Proposal approved by client - ready for implementation",
    "IMPLEMENTATION_ASSIGNED": "Implementation in progress",
    "IMPLEMENTATION_COMPLETE": "Implementation approved by TM/TL - ready for delivery to client",
    "IMPLEMENTATION_CLIENT_REVIEW": "Implementation delivered - awaiting client approval",
    "IMPLEMENTATION_APPROVED": "Implementation approved by client - ready for paper writing",
    "PAPERWRITER_ASSIGNED": "Paper writing in progress",
    "COORDINATOR_REVIEW": "With Content Coordinator for review",
    "WRITER_FIXING": "Sent back to writer for correction",
    "TECHTL_REVIEW": "With Technical TL for review",
    "TECHMGR_REVIEW": "With Technical Manager for review",
    "WRITING_COMPLETE": "Writing approved by TM/TL - ready for delivery to client",
    "CLIENT_REVIEW": "Paper delivered - awaiting client approval",
    "CLIENT_ACCEPTED": "Client approved the paper - ready for Journal Team",
    "JOURNAL_MANAGER_REVIEW": "With Journal Manager",
    "PROOFREAD_COORD_ASSIGNED": "Proofreading coordinator assigned",
    "PROOFREADING": "Proofreading in progress",
    "PROOFREAD_CORRECTION": "Sent back to writer (proofreading correction)",
    "PROOFREAD_RECHECK": "Proofreading re-check",
    "JOURNAL_MANAGER_FORMATTING": "With Journal Manager for formatting assignment",
    "FORMATTING_ASSIGNED": "Formatting coordinator assigned",
    "FORMATTING_IN_PROGRESS": "Formatting in progress",
    "FORMATTING_MANAGER_REVIEW": "With Journal Manager (formatting review)",
    "SUBMISSION": "With Submission team",
    "JOURNAL_SUBMITTED": "Submitted to journal",
    "COMPLETED": "Completed",
}


def require_stage(c, stage):
    if c["stage"] != stage:
        raise ApiError("This client is now at '" + STAGE_LABELS.get(c["stage"], c["stage"]) +
                       "'. It may already be processed - the page refreshes automatically.")


def get_client(con, cid):
    c = con.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    if not c:
        raise ApiError("Client not found.", 404)
    # SECURITY (IDOR): a client-portal session may only reach its own CL-ID family.
    # Answering 404 rather than 403 keeps this from being used to probe which
    # client IDs exist. Every handler that touches a client goes through here.
    if not client_visible_to(con, cid):
        raise ApiError("Client not found.", 404)
    return c


def move_stage(con, cid, stage, actor, note=""):
    con.execute("UPDATE clients SET stage=? WHERE id=?", (stage, cid))
    con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                (cid, stage, actor, note or ""))


def active_names(con, role, team_type=None):
    if team_type:
        return [r["name"] for r in con.execute(
            "SELECT name FROM employees WHERE role=? AND team_type=? AND active=1 AND deleted_at IS NULL",
            (role, team_type))]
    return [r["name"] for r in
            con.execute("SELECT name FROM employees WHERE role=? AND active=1 AND deleted_at IS NULL", (role,))]


def apply_pre_implementation(con, c, verifier):
    """If an implementation team was pre-assigned at intake (alongside the proposal
    writer), apply it now - client must currently be at PROPOSAL_APPROVED. Shared by
    verify_proposal and by the Work Updates task-approval sync, so both paths behave
    identically. Returns True if a team was actually applied."""
    pre_impl = (c["pre_impl_programmers"] or "").strip()
    if not pre_impl:
        return False
    picked = [p for p in pre_impl.split(",") if p and p in active_names(con, "PROGRAMMER")]
    pre_deadline = (c["pre_impl_deadline"] or "").strip()
    con.execute("""UPDATE clients SET pre_impl_programmers='', pre_impl_deadline='',
                   pre_impl_by='' WHERE id=?""", (c["id"],))
    if picked and pre_deadline:
        con.execute("""UPDATE clients SET assigned_programmers=?, implementation_deadline=?,
                       impl_coordinator='', impl_awaiting_team_pick=0 WHERE id=?""",
                    (",".join(picked), pre_deadline, c["id"]))
        move_stage(con, c["id"], "IMPLEMENTATION_ASSIGNED", c["pre_impl_by"] or verifier,
                   f"Auto-assigned to the team pre-selected at intake: {', '.join(picked)}.")
        return True
    con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                (c["id"], "PROPOSAL_APPROVED", "System",
                 "The programmer(s) pre-selected at intake are no longer available — "
                 "pick the implementation team manually."))
    return False


def apply_pre_writer(con, c, actor):
    """If a paper writer was pre-assigned at intake, apply it now - client must
    currently be at IMPLEMENTATION_APPROVED. Shared by complete_implementation and by
    the Work Updates task-approval sync. Returns True if a writer was actually applied."""
    pre_write = (c["pre_write_writers"] or "").strip()
    if not pre_write:
        return False
    picked = [w for w in pre_write.split(",") if w and w in active_names(con, "PAPER_WRITER")]
    pre_deadline = (c["pre_write_deadline"] or "").strip()
    con.execute("""UPDATE clients SET pre_write_writers='', pre_write_deadline='',
                   pre_write_by='' WHERE id=?""", (c["id"],))
    if picked and pre_deadline:
        con.execute("""UPDATE clients SET assigned_writers=?, writing_deadline=?,
                       coordinator_name='', writing_awaiting_team_pick=0, review_level='',
                       coordinator_rounds=0, techtl_rounds=0, techmgr_rounds=0 WHERE id=?""",
                    (",".join(picked), pre_deadline, c["id"]))
        move_stage(con, c["id"], "PAPERWRITER_ASSIGNED", c["pre_write_by"] or actor,
                   f"Auto-assigned to the writer(s) pre-selected at intake: {', '.join(picked)}.")
        return True
    con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                (c["id"], "IMPLEMENTATION_APPROVED", "System",
                 "The paper writer(s) pre-selected at intake are no longer available — "
                 "assign paper writing manually."))
    return False


def all_employees(con):
    rows = con.execute(
        "SELECT * FROM employees WHERE active=1 AND deleted_at IS NULL ORDER BY role, team_type, name").fetchall()
    names_by_id = {r["id"]: r["name"] for r in rows}
    return [{"id": r["id"], "name": r["name"], "role": r["role"],
             "teamType": r["team_type"] or "", "empUid": r["emp_uid"] or "", "email": r["email"] or "",
             "isCoordinator": bool(r["is_coordinator"]), "coordinatorId": r["coordinator_id"],
             "coordinatorName": names_by_id.get(r["coordinator_id"], "") if r["coordinator_id"] else "",
             "joiningDate": r["joining_date"] or "", "dateOfBirth": r["date_of_birth"] or "",
             "branch": r["branch"] or "", "department": r["department"] or "",
             "phone": r["phone"] or "", "designation": r["designation"] or ""}
            for r in rows]


def deleted_employees(con):
    rows = con.execute(
        "SELECT * FROM employees WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC").fetchall()
    return [{"id": r["id"], "name": r["name"], "role": r["role"], "teamType": r["team_type"] or "",
             "empUid": r["emp_uid"] or "", "deletedAt": r["deleted_at"]} for r in rows]


def try_auto_email(con, client, subject, body):
    """Best-effort automated handoff email. Silently records a history note either
    way; never blocks the pipeline transition if Gmail isn't configured or fails."""
    pwd = GMAIL_APP_PASSWORD.replace(" ", "")
    to = get_settings(con)["toEmail"]
    if not pwd or not to:
        return
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = GMAIL_USER
        msg["To"] = to
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as smtp:
            smtp.login(GMAIL_USER, pwd)
            smtp.sendmail(GMAIL_USER, [to], msg.as_string())
    except Exception:
        pass


def get_settings(con):
    s = con.execute("SELECT * FROM settings WHERE id=1").fetchone()
    if not s:
        return {"fromEmail": DEFAULT_FROM_EMAIL or GMAIL_USER, "toEmail": DEFAULT_TO_EMAIL}
    return {"fromEmail": s["from_email"], "toEmail": s["to_email"]}


# =====================================================================
# RESPONSE SCRUBBING — least-privilege shaping of the bootstrap payload.
# The client and employee dashboards genuinely need a client list; they do
# not need the whole business's money, PII and portal tokens.
# =====================================================================

# Never leaves the server for a non-staff caller: the portal setup token is a
# credential, and the rest is internal commentary about the client.
_CLIENT_INTERNAL_FIELDS = (
    "inviteToken", "inviteSentAt", "passwordResetRequested", "passwordResetRequestedAt",
    "notes", "history", "workUpdates", "holdReason", "holdRequestedBy",
    "rejectReason", "rejected", "rejectedAt", "extReason", "extRequestedBy",
    "bdc", "referredBy", "calls", "demoScheduledNote", "coordinatorRounds",
    "techtlRounds", "techmgrRounds", "reviewLevel", "lastLoginAt",
)

# Additionally hidden from employees: commercials and colleague contact details.
_EMPLOYEE_HIDDEN_FIELDS = _CLIENT_INTERNAL_FIELDS + (
    "payments", "installments", "totalAmount", "extAmount", "serviceItems",
    "installmentPlanName", "email", "institutionalEmail", "altMobile", "address",
)


def scrub_client_for_client(c):
    """Client-portal view of a client record."""
    out = {k: v for k, v in c.items() if k not in _CLIENT_INTERNAL_FIELDS}
    # A client may see its own chat threads, but not staff-to-staff previews.
    out.pop("messageThreads", None)
    return out


def scrub_client_for_employee(c):
    """Employee (programmer/writer/...) view of a client record."""
    return {k: v for k, v in c.items() if k not in _EMPLOYEE_HIDDEN_FIELDS}


def scrub_employee(e):
    """Colleague directory entry without personal contact details."""
    keep = ("id", "name", "role", "active", "team_type", "teamType", "emp_uid",
            "empUid", "is_coordinator", "isCoordinator", "coordinator_id",
            "coordinatorId", "designation", "department")
    return {k: v for k, v in e.items() if k in keep}


def employee_visible_client_ids(con, emp_id, emp_name, tasks, queries):
    """Clients an individually-added employee is actually attached to:
    assigned as programmer/writer/formatter/proofreader/coordinator, or
    holding one of their tasks or queries."""
    visible = set()
    name = (emp_name or "").strip()
    if name:
        like = "%" + name + "%"
        for r in con.execute(
            """SELECT id FROM clients
               WHERE proposal_writer=? OR proposal_coordinator=? OR impl_coordinator=?
                  OR coordinator_name=? OR format_coordinator=? OR proofread_coordinator=?
                  OR technical_person=?
                  OR assigned_programmers LIKE ? OR assigned_writers LIKE ?
                  OR assigned_formatters LIKE ? OR assigned_proofreaders LIKE ?
                  OR pre_impl_programmers LIKE ? OR pre_write_writers LIKE ?""",
                (name, name, name, name, name, name, name,
                 like, like, like, like, like, like)):
            visible.add(r["id"])
    for t in tasks or []:
        if (t.get("assignedTo") or "").strip() == name or t.get("assignedEmpId") == emp_id:
            if t.get("client_id"):
                visible.add(t["client_id"])
    for q in queries or []:
        if (q.get("assigned_to") or q.get("assignedTo") or "").strip() == name:
            if q.get("client_id"):
                visible.add(q["client_id"])
    return visible


def all_clients(con):
    calls_by, pays_by, hist_by, work_by, svc_by, inst_by = {}, {}, {}, {}, {}, {}
    for r in con.execute("SELECT * FROM calls ORDER BY created_at DESC, id DESC"):
        calls_by.setdefault(r["client_id"], []).append(r)
    for r in con.execute("SELECT * FROM payments"):
        pays_by.setdefault(r["client_id"], {})[r["pay_key"]] = r
    for r in con.execute("SELECT * FROM history ORDER BY created_at DESC, id DESC"):
        hist_by.setdefault(r["client_id"], []).append(r)
    for r in con.execute("SELECT * FROM work_updates ORDER BY created_at DESC, id DESC"):
        work_by.setdefault(r["client_id"], []).append(r)
    for r in con.execute("SELECT * FROM service_items ORDER BY created_at ASC, id ASC"):
        svc_by.setdefault(r["client_id"], {}).setdefault(r["pay_key"], []).append(r)
    for r in con.execute("SELECT * FROM client_installments ORDER BY sort_order ASC, id ASC"):
        inst_by.setdefault(r["client_id"], []).append(r)
    jt_by = {}
    for r in con.execute("SELECT * FROM journal_targets ORDER BY created_at ASC, id ASC"):
        jt_by.setdefault(r["client_id"], []).append(r)
    msgs_by = {}
    for r in con.execute("""SELECT id, client_id, thread_with, sender_type, body, file_name,
                                    read_by_client, read_by_staff, created_at
                             FROM messages ORDER BY created_at ASC, id ASC"""):
        msgs_by.setdefault(r["client_id"], {}).setdefault(r["thread_with"], []).append(r)
    reads_by = {}
    for r in con.execute("SELECT client_id, thread_with, viewer_key, last_read_id FROM thread_reads"):
        reads_by.setdefault(r["client_id"], {}).setdefault(r["thread_with"], {})[r["viewer_key"]] = r["last_read_id"]

    out = []
    for r in con.execute("SELECT * FROM clients ORDER BY created_at DESC, id DESC"):
        cid = r["id"]
        payments = {}
        for k in PAY_KEYS:
            p = pays_by.get(cid, {}).get(k)
            payments[k] = ({"status": p["status"], "amount": amt(p["amount"]), "date": p["pay_date"]}
                           if p else {"status": "pending", "amount": "", "date": None})
        service_items = {}
        for k in PAY_KEYS:
            items = svc_by.get(cid, {}).get(k, [])
            service_items[k] = [{"id": it["id"], "name": it["name"], "amount": amt(it["amount"])} for it in items]
        journal_targets = [{"id": jt["id"], "name": jt["name"], "status": jt["status"] or "",
                             "addedBy": jt["added_by"] or "", "addedAt": iso(jt["created_at"])}
                            for jt in jt_by.get(cid, [])]
        message_threads = []
        for tw, msgs in msgs_by.get(cid, {}).items():
            unread_client = sum(1 for m in msgs if m["sender_type"] == "staff" and not m["read_by_client"])
            last = msgs[-1]
            preview = (last["body"] or "").strip()
            if not preview and last["file_name"]:
                preview = "Sent a file: " + last["file_name"]
            client_msg_ids = [m["id"] for m in msgs if m["sender_type"] == "client"]
            read_by = reads_by.get(cid, {}).get(tw, {})
            # Legacy fallback for viewers that haven't opened this thread since the per-viewer
            # read tracking was added: fall back to the old shared read_by_staff flag so old
            # threads don't all suddenly look unread.
            legacy_read = all(m["read_by_staff"] for m in msgs if m["sender_type"] == "client") if msgs else True
            message_threads.append({
                "threadWith": tw, "unreadForClient": unread_client,
                "clientMsgIds": client_msg_ids, "readBy": read_by, "legacyRead": legacy_read,
                "lastAt": iso(last["created_at"]), "lastPreview": preview[:80], "lastSender": last["sender_type"],
            })
        message_threads.sort(key=lambda t: t["lastAt"] or "", reverse=True)
        out.append({
            "id": cid, "displayId": r["display_id"] or cid, "projectId": r["project_id"] or cid,
            "name": r["name"], "phone": r["phone"], "email": r["email"],
            "domain": r["domain"], "address": r["address"], "notes": r["notes"],
            "designation": r["designation"] or "", "institution": r["institution"] or "",
            "topic": r["topic"] or "", "technicalPerson": r["technical_person"] or "",
            "basePaperProvided": bool(r["base_paper_provided"]), "bdc": r["bdc"] or "",
            "altMobile": r["alt_mobile"] or "", "institutionalEmail": r["institutional_email"] or "",
            "department": r["department"] or "", "referredBy": r["referred_by"] or "",
            "hasClientLogin": bool(r["client_password"]), "inviteSentAt": r["invite_sent_at"] or "",
            "inviteToken": (r["invite_token"] or "") if not r["client_password"] else "",
            "lastLoginAt": r["last_login_at"] or "",
            "passwordResetRequested": bool(r["password_reset_requested"]),
            "passwordResetRequestedAt": r["password_reset_requested_at"] or "",
            "totalAmount": amt(r["total_amount"]),
            "regDate": r["reg_date"], "deadlineDate": r["deadline_date"],
            "stage": r["stage"],
            "proposalVerifiedBy": r["proposal_verified_by"] or None,
            "assignedProgrammers": names(r["assigned_programmers"]),
            "implementationDeadline": r["implementation_deadline"],
            "proposalWriter": r["proposal_writer"] or "",
            "proposalDeadline": r["proposal_deadline"],
            "onHold": bool(r["on_hold"]), "holdReason": r["hold_reason"] or "",
            "extRequested": bool(r["ext_requested"]), "extReason": r["ext_reason"] or "",
            "extRequestedBy": r["ext_requested_by"] or "", "extAmount": r["ext_amount"] or "",
            "extTarget": r["ext_target"] or "",
            "holdRequestedBy": r["hold_requested_by"] or "", "requestedDeadline": r["requested_deadline"],
            "proposalSubmittedAt": r["proposal_submitted_at"],
            "assignedWriters": names(r["assigned_writers"]),
            "nextFollowUp": r["next_follow_up"],
            "createdAt": iso(r["created_at"]),
            "calls": [{"type": c["call_type"], "note": c["note"],
                       "at": iso(c["created_at"]), "next": c["next_date"]}
                      for c in calls_by.get(cid, [])],
            "payments": payments,
            "serviceItems": service_items,
            "installmentPlanName": r["installment_plan_name"] or "",
            "installments": [{"id": it["id"], "title": it["title"], "amount": amt(it["amount"]),
                               "status": it["status"], "paidDate": it["paid_date"]}
                              for it in inst_by.get(cid, [])],
            "history": [{"stage": h["stage"], "actor": h["actor"], "at": iso(h["created_at"]),
                         "note": h["note"] or ""}
                        for h in hist_by.get(cid, [])],
            "workUpdates": [{"empName": w["emp_name"], "milestone": w["milestone"], "note": w["note"],
                              "at": iso(w["created_at"])} for w in work_by.get(cid, [])],
            "rejected": bool(r["rejected"]), "rejectReason": r["reject_reason"] or "",
            "rejectedAt": iso(r["rejected_at"]) if r["rejected_at"] else None,
            "writingDeadline": r["writing_deadline"],
            "demoCompletedDate": r["demo_completed_date"],
            "demoGivenDate": r["demo_given_date"],
            "demoSatisfied": r["demo_satisfied"] or "",
            "demoApprovedAt": r["demo_approved_at"],
            "demoApprovedBy": r["demo_approved_by"] or "",
            "writingDemoGivenDate": r["writing_demo_given_date"] or "",
            "demoScheduledType": r["demo_scheduled_type"] or "",
            "demoScheduledDate": r["demo_scheduled_date"] or "",
            "demoScheduledTime": r["demo_scheduled_time"] or "",
            "demoScheduledNote": r["demo_scheduled_note"] or "",
            "demoScheduledEmp": r["demo_scheduled_emp"] or "",
            "demoScheduledBy": r["demo_scheduled_by"] or "",
            "demoScheduleStatus": r["demo_schedule_status"] or "",
            "messageThreads": message_threads,
            "reviewLevel": r["review_level"] or "",
            "coordinatorName": r["coordinator_name"] or "",
            "writingAwaitingTeamPick": bool(r["writing_awaiting_team_pick"]),
            "proposalCoordinator": r["proposal_coordinator"] or "",
            "proposalAwaitingTeamPick": bool(r["proposal_awaiting_team_pick"]),
            "implCoordinator": r["impl_coordinator"] or "",
            "implAwaitingTeamPick": bool(r["impl_awaiting_team_pick"]),
            "coordinatorRounds": r["coordinator_rounds"],
            "techtlRounds": r["techtl_rounds"],
            "techmgrRounds": r["techmgr_rounds"],
            "clientApprovedAt": iso(r["client_approved_at"]) if r["client_approved_at"] else None,
            "journalName": r["journal_name"] or "",
            "journalTargets": journal_targets,
            "proofreadCoordinator": r["proofread_coordinator"] or "",
            "assignedProofreaders": names(r["assigned_proofreaders"]),
            "proofreadRounds": r["proofread_rounds"],
            "formatCoordinator": r["format_coordinator"] or "",
            "assignedFormatters": names(r["assigned_formatters"]),
            "formatRounds": r["format_rounds"],
            "submissionPerson": r["submission_person"] or "",
            "journalStatus": r["journal_status"] or "",
            "serviceKey": r["service_key"] or DEFAULT_SERVICE,
            "writingApprovedAt": iso(r["writing_approved_at"]) if r["writing_approved_at"] else None,
        })
    return out


def _import_rows(con, rows):
    parsed = parse_sheet_rows(rows)
    if not parsed:
        raise ApiError("No data rows found in that sheet.")

    existing_phones = {r["phone"].strip().lower() for r in con.execute("SELECT phone FROM clients")
                       if r["phone"]}
    existing_name_domain = {(r["name"].strip().lower(), (r["domain"] or "").strip().lower())
                            for r in con.execute("SELECT name, domain FROM clients")}
    n = 1001
    for r in con.execute("SELECT id FROM clients"):
        m = re.match(r"^CL-(\d+)$", r["id"])
        if m:
            n = max(n, int(m.group(1)) + 1)
    pn = 2001
    for r in con.execute("SELECT project_id FROM clients"):
        m = re.match(r"^PRJ-(\d+)$", r["project_id"] or "")
        if m:
            pn = max(pn, int(m.group(1)) + 1)

    added, skipped, errors = 0, 0, []
    for idx, fields, extra_notes in parsed:
        name = fields["name"].strip()
        if not name:
            skipped += 1
            errors.append(f"Row {idx}: missing a name, skipped.")
            continue
        phone = fields["phone"].strip()
        domain = fields["domain"].strip()
        if phone and phone.lower() in existing_phones:
            skipped += 1
            errors.append(f"Row {idx}: {name} — phone already exists, skipped.")
            continue
        if not phone and (name.lower(), domain.lower()) in existing_name_domain:
            skipped += 1
            errors.append(f"Row {idx}: {name} — looks like a duplicate, skipped.")
            continue
        reg_date = fields["regDate"] or date.today().isoformat()
        deadline = fields["deadlineDate"] or _default_deadline(reg_date)
        notes = " | ".join(extra_notes)[:2000]
        cid = f"CL-{n}"
        n += 1
        project_id = f"PRJ-{pn}"
        pn += 1
        con.execute("""INSERT INTO clients
                       (id,display_id,project_id,name,phone,email,domain,address,notes,reg_date,deadline_date,stage)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,'NEW')""",
                    (cid, cid, project_id, name, phone, fields["email"].strip(), domain,
                     fields["address"].strip(), notes, reg_date, deadline))
        for k in PAY_KEYS:
            con.execute("INSERT INTO payments (client_id, pay_key) VALUES (?,?)", (cid, k))
        con.execute("INSERT INTO history (client_id, stage, actor) VALUES (?,'NEW','Telecaller (import)')",
                    (cid,))
        con.execute("INSERT INTO calls (client_id, call_type, note) VALUES (?,?,?)",
                    (cid, fields["callType"].strip() or "Imported lead", "Imported from spreadsheet."))
        if phone:
            existing_phones.add(phone.lower())
        existing_name_domain.add((name.lower(), domain.lower()))
        added += 1
    con.commit()
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:30]}


# ----------------------------------------------------------------------------
# GENERIC BULK IMPORT (every dashboard section, not just the Telecaller's
# "Add leads" screen) - reuses the same file/Google-Sheet reading machinery
# above, but maps columns onto whichever record type that section deals with
# (notes, contacts, tasks, team members, payments, client queries) instead of
# always creating brand-new clients.
# ----------------------------------------------------------------------------

# =====================================================================
# SSRF PROTECTION for the "import from Google Sheet link" feature.
# urlopen() will follow file://, ftp://, RFC1918 addresses and the cloud
# metadata endpoint unless it is explicitly constrained. Only Google's
# spreadsheet hosts over https are permitted, and redirects may not leave
# that set.
# =====================================================================
MAX_SHEET_BYTES = int(_env("MAX_SHEET_BYTES", str(8 * 1024 * 1024)))

_SHEET_HOSTS = {
    "docs.google.com",
    "drive.google.com",
    "spreadsheets.google.com",
    "googleusercontent.com",
}


def _sheet_host_allowed(host):
    host = (host or "").split(":")[0].strip().lower().rstrip(".")
    if not host:
        return False
    if host in _SHEET_HOSTS:
        return True
    # Google serves export redirects from *.googleusercontent.com
    return host.endswith(".googleusercontent.com")


def _assert_sheet_url_allowed(url):
    try:
        p = urlparse(url)
    except ValueError:
        raise ApiError("That link could not be read. Paste the Google Sheet link again.")
    if p.scheme.lower() != "https":
        raise ApiError("Only https Google Sheet links can be imported.")
    if not _sheet_host_allowed(p.hostname):
        raise ApiError("Only Google Sheets links can be imported. Publish or share your sheet "
                       "on Google Sheets and paste that link.")


class _SheetRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-checks the destination on every redirect hop, so an allowed Google URL
    cannot bounce the request to an internal address."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _assert_sheet_url_allowed(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_sheet_rows(url):
    """Fetch a Google Sheet (or any CSV-serving URL) and return raw rows."""
    url = (url or "").strip()
    if not url:
        raise ApiError("Paste a Google Sheet link first.")
    m = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", url)
    if m and "output=csv" not in url and "/pub" not in url:
        gid_m = re.search(r"[?&#]gid=(\d+)", url)
        gid = gid_m.group(1) if gid_m else "0"
        url = f"https://docs.google.com/spreadsheets/d/{m.group(1)}/export?format=csv&gid={gid}"
    # SECURITY (SSRF): only Google's own spreadsheet hosts over https are reachable.
    # Without this, urlopen() would happily fetch file:///etc/passwd, internal RFC1918
    # addresses and the cloud metadata endpoint on behalf of any logged-in user.
    _assert_sheet_url_allowed(url)
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        opener = urllib.request.build_opener(_SheetRedirectHandler)
        with opener.open(req, timeout=20) as resp:
            raw = resp.read(MAX_SHEET_BYTES + 1)
        if len(raw) > MAX_SHEET_BYTES:
            raise ApiError("That sheet is too large to import (limit %d MB)."
                           % (MAX_SHEET_BYTES // (1024 * 1024)))
    except ApiError:
        raise
    except Exception:
        # SECURITY: never echo the upstream error back — it turns this into an
        # oracle for probing the internal network.
        raise ApiError("Could not fetch that link. Make sure it is a Google Sheet shared as "
                       "'Anyone with the link can view', then try again.")
    return list(csv.reader(io.StringIO(raw.decode("utf-8", errors="ignore"))))


def _rows_from_upload(filename, b64, csv_text):
    filename = (filename or "").strip().lower()
    if csv_text is not None:
        return list(csv.reader(io.StringIO(csv_text)))
    if b64:
        try:
            raw = base64.b64decode(b64)
        except Exception:
            raise ApiError("Could not read that file — it may be corrupted.")
        if filename.endswith(".csv") or filename.endswith(".tsv"):
            return list(csv.reader(io.StringIO(raw.decode("utf-8", errors="ignore"))))
        if filename.endswith(".xlsx"):
            return read_xlsx_rows(raw)
        raise ApiError("Please upload a .xlsx or .csv file.")
    raise ApiError("No file was received.")


def _find_client(con, ref):
    """Look up a client by CL-id / display id, or (failing that) phone number."""
    ref = (ref or "").strip()
    if not ref:
        return None
    row = con.execute("SELECT * FROM clients WHERE id=? OR display_id=?", (ref, ref)).fetchone()
    if row:
        return row
    return con.execute("SELECT * FROM clients WHERE phone=?", (ref,)).fetchone()


def _rows_to_dicts(rows, alias_map):
    """Generic column-header -> field-name mapper, shared by every non-client
    importer below (headers are matched case-insensitively; unrecognised
    columns are ignored rather than causing an error)."""
    if not rows:
        return []
    header, data_rows = rows[0], rows[1:]
    mapping = {}
    for i, h in enumerate(header):
        label = (str(h).strip() if h is not None else "").lower()
        mapping[i] = alias_map.get(label)
    out = []
    for idx, row in enumerate(data_rows, start=2):
        if not any((str(v).strip() if v is not None else "") for v in row):
            continue
        rec = {}
        for i, val in enumerate(row):
            field = mapping.get(i)
            if not field or val is None:
                continue
            sval = str(val).strip()
            if sval:
                rec[field] = sval
        out.append((idx, rec))
    return out


NOTES_ALIASES = {
    "client id": "clientId", "clientid": "clientId", "client": "clientId", "cl id": "clientId", "id": "clientId",
    "title": "title", "note title": "title", "note": "title",
    "description": "description", "note description": "description", "details": "description",
}
REFERRAL_ALIASES = {
    "client id": "clientId", "clientid": "clientId", "client": "clientId", "cl id": "clientId", "id": "clientId",
    "name": "name", "contact name": "name", "contact": "name",
    "designation": "designation", "email": "email", "email id": "email",
    "mobile": "mobile", "phone": "mobile", "mobile number": "mobile", "contact number": "mobile",
}
TASK_ALIASES = {
    "client id": "clientId", "clientid": "clientId", "client": "clientId", "cl id": "clientId",
    "title": "title", "task": "title", "task title": "title",
    "description": "description", "details": "description",
    "priority": "priority", "assigned to": "assignedTo", "assignee": "assignedTo", "owner": "assignedTo",
    "start date": "startDate", "finish date": "finishDate", "due date": "finishDate", "deadline": "finishDate",
    "task type": "taskType", "type": "taskType",
}
TEAM_ALIASES = {
    "name": "name", "employee name": "name",
    "role": "role", "team role": "role",
    "team type": "teamType", "journal team type": "teamType",
    "email": "email", "email id": "email",
    "phone": "phone", "mobile": "phone", "mobile number": "phone",
    "designation": "designation", "branch": "branch", "department": "department",
    "employee id": "empUid", "emp id": "empUid", "emp uid": "empUid",
    "joining date": "joiningDate", "date of birth": "dateOfBirth", "dob": "dateOfBirth",
}
PAYMENT_ALIASES = {
    "client id": "clientId", "clientid": "clientId", "client": "clientId", "cl id": "clientId",
    "payment stage": "payKey", "stage": "payKey", "pay key": "payKey", "payment": "payKey",
    "amount": "amount", "date": "date", "payment date": "date", "paid date": "date",
}
PAY_KEY_ALIASES = {
    "reg": "reg", "registration": "reg", "start": "start", "start work": "start",
    "code": "code", "code implementation": "code", "implementation": "code",
    "writing": "writing", "writing fee": "writing", "paper": "paper", "paper delivery": "paper",
}
QUERY_ALIASES = {
    "client id": "clientId", "clientid": "clientId", "client": "clientId", "cl id": "clientId",
    "query": "queryText", "query text": "queryText", "question": "queryText",
    "assigned to": "assignedTo", "date": "queryDate", "query date": "queryDate",
}


def _import_notes_rows(con, rows, default_client_id="", actor=""):
    parsed = _rows_to_dicts(rows, NOTES_ALIASES)
    if not parsed:
        raise ApiError("No data rows found in that sheet.")
    added, skipped, errors = 0, 0, []
    for idx, rec in parsed:
        ref = rec.get("clientId") or default_client_id
        title = (rec.get("title") or "").strip()
        if not ref:
            skipped += 1; errors.append(f"Row {idx}: no client id given, skipped."); continue
        c = _find_client(con, ref)
        if not c:
            skipped += 1; errors.append(f"Row {idx}: client '{ref}' not found, skipped."); continue
        if not title:
            skipped += 1; errors.append(f"Row {idx}: missing a note title, skipped."); continue
        con.execute("""INSERT INTO client_notes_v2 (client_id, title, description, created_by)
                       VALUES (?,?,?,?)""",
                    (c["id"], title, (rec.get("description") or "").strip(), actor or "Import"))
        added += 1
    con.commit()
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:30]}


def _import_referrals_rows(con, rows, default_client_id=""):
    parsed = _rows_to_dicts(rows, REFERRAL_ALIASES)
    if not parsed:
        raise ApiError("No data rows found in that sheet.")
    added, skipped, errors = 0, 0, []
    for idx, rec in parsed:
        ref = rec.get("clientId") or default_client_id
        name = (rec.get("name") or "").strip()
        if not ref:
            skipped += 1; errors.append(f"Row {idx}: no client id given, skipped."); continue
        c = _find_client(con, ref)
        if not c:
            skipped += 1; errors.append(f"Row {idx}: client '{ref}' not found, skipped."); continue
        if not name:
            skipped += 1; errors.append(f"Row {idx}: missing a contact name, skipped."); continue
        con.execute("""INSERT INTO client_referrals (client_id, designation, name, email, mobile)
                       VALUES (?,?,?,?,?)""",
                    (c["id"], (rec.get("designation") or "").strip(), name,
                     (rec.get("email") or "").strip(), (rec.get("mobile") or "").strip()))
        added += 1
    con.commit()
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:30]}


def _import_tasks_rows(con, rows, default_client_id="", actor=""):
    parsed = _rows_to_dicts(rows, TASK_ALIASES)
    if not parsed:
        raise ApiError("No data rows found in that sheet.")
    added, skipped, errors = 0, 0, []
    for idx, rec in parsed:
        title = (rec.get("title") or "").strip()
        if not title:
            skipped += 1; errors.append(f"Row {idx}: missing a task title, skipped."); continue
        ref = rec.get("clientId") or default_client_id
        client_id = None
        if ref:
            c = _find_client(con, ref)
            if not c:
                skipped += 1; errors.append(f"Row {idx}: client '{ref}' not found, skipped."); continue
            client_id = c["id"]
        priority = (rec.get("priority") or "MEDIUM").strip().upper()
        if priority not in ("LOW", "MEDIUM", "HIGH"):
            priority = "MEDIUM"
        task_type = (rec.get("taskType") or "").strip().upper().replace(" ", "_")
        if task_type not in VALID_TASK_TYPES:
            task_type = ""
        start_date = _normalize_date_str(rec["startDate"]) if rec.get("startDate") else None
        finish_date = _normalize_date_str(rec["finishDate"]) if rec.get("finishDate") else None
        con.execute("""INSERT INTO tasks
            (title, description, client_id, priority, start_date, finish_date, assigned_to, created_by, task_type)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (title, (rec.get("description") or "").strip(), client_id, priority,
             start_date, finish_date, (rec.get("assignedTo") or "").strip(), actor or "Import", task_type))
        added += 1
    con.commit()
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:30]}


TEAM_ROLE_ALIASES = {
    "PROGRAMMER": "PROGRAMMER", "PAPER_WRITER": "PAPER_WRITER", "WRITER": "PAPER_WRITER",
    "PAPER WRITER": "PAPER_WRITER", "JOURNAL": "JOURNAL_EMPLOYEE", "JOURNAL_EMPLOYEE": "JOURNAL_EMPLOYEE",
    "JOURNAL TEAM": "JOURNAL_EMPLOYEE", "TELECALLER": "TELECALLER",
}
TEAM_TYPE_ALIASES = {
    "PROOFREAD_COORDINATOR": "PROOFREAD_COORDINATOR", "PROOFREADING COORDINATOR": "PROOFREAD_COORDINATOR",
    "PROOFREADER": "PROOFREADER", "FORMAT_COORDINATOR": "FORMAT_COORDINATOR",
    "FORMATTING COORDINATOR": "FORMAT_COORDINATOR", "FORMATTER": "FORMATTER", "SUBMISSION": "SUBMISSION",
}


def _next_emp_uid(con):
    n = 1001
    for r in con.execute("SELECT emp_uid FROM employees WHERE emp_uid IS NOT NULL AND emp_uid<>''"):
        m = re.match(r"^EMP-(\d+)$", r["emp_uid"] or "")
        if m:
            n = max(n, int(m.group(1)) + 1)
    return f"EMP-{n}"


def _import_team_rows(con, rows):
    parsed = _rows_to_dicts(rows, TEAM_ALIASES)
    if not parsed:
        raise ApiError("No data rows found in that sheet.")
    added, skipped, errors = 0, 0, []
    for idx, rec in parsed:
        name = (rec.get("name") or "").strip()
        if not name:
            skipped += 1; errors.append(f"Row {idx}: missing a name, skipped."); continue
        role = TEAM_ROLE_ALIASES.get((rec.get("role") or "").strip().upper())
        if not role:
            skipped += 1
            errors.append(f"Row {idx}: {name} — unrecognised role "
                          f"'{rec.get('role') or ''}' (use Programmer / Paper Writer / Journal / Telecaller), skipped.")
            continue
        team_type = TEAM_TYPE_ALIASES.get((rec.get("teamType") or "").strip().upper(), "")
        if role == "JOURNAL_EMPLOYEE" and not team_type:
            skipped += 1
            errors.append(f"Row {idx}: {name} — journal team members need a team type "
                          f"(Proofreader / Proofreading Coordinator / Formatter / Formatting Coordinator / Submission), skipped.")
            continue
        if role != "JOURNAL_EMPLOYEE":
            team_type = ""
        dup = con.execute("SELECT id FROM employees WHERE LOWER(name)=LOWER(?) AND active=1 AND deleted_at IS NULL",
                          (name,)).fetchone()
        if dup:
            skipped += 1; errors.append(f"Row {idx}: {name} is already on the team, skipped."); continue
        manual_uid = (rec.get("empUid") or "").strip()
        if manual_uid:
            if con.execute("SELECT id FROM employees WHERE UPPER(emp_uid)=UPPER(?)", (manual_uid,)).fetchone():
                skipped += 1
                errors.append(f"Row {idx}: {name} — employee ID '{manual_uid}' is already in use, skipped.")
                continue
            uid = manual_uid
        else:
            uid = _next_emp_uid(con)
        con.execute("""INSERT INTO employees
                       (name, role, team_type, email, emp_uid, password, is_coordinator, coordinator_id,
                        joining_date, date_of_birth, branch, department, phone, designation)
                       VALUES (?,?,?,?,?,?,0,NULL,?,?,?,?,?,?)""",
                    (name, role, team_type, (rec.get("email") or "").strip(), uid,
                     "",   # SECURITY: no password set — the manager must issue one
                     (rec.get("joiningDate") or "").strip(), (rec.get("dateOfBirth") or "").strip(),
                     (rec.get("branch") or "").strip(), (rec.get("department") or "").strip(),
                     (rec.get("phone") or "").strip(), (rec.get("designation") or "").strip()))
        added += 1
    con.commit()
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:30]}


def _import_payments_rows(con, rows):
    parsed = _rows_to_dicts(rows, PAYMENT_ALIASES)
    if not parsed:
        raise ApiError("No data rows found in that sheet.")
    added, skipped, errors = 0, 0, []
    for idx, rec in parsed:
        ref = rec.get("clientId")
        if not ref:
            skipped += 1; errors.append(f"Row {idx}: no client id given, skipped."); continue
        c = _find_client(con, ref)
        if not c:
            skipped += 1; errors.append(f"Row {idx}: client '{ref}' not found, skipped."); continue
        raw_key = (rec.get("payKey") or "").strip().lower()
        key = PAY_KEY_ALIASES.get(raw_key) or (raw_key if raw_key in PAY_KEYS else None)
        if not key:
            skipped += 1
            errors.append(f"Row {idx}: {c['name']} — unrecognised payment stage "
                          f"'{rec.get('payKey') or ''}', skipped.")
            continue
        amount_raw = rec.get("amount")
        try:
            amount_val = float(amount_raw) if amount_raw not in (None, "") else None
        except ValueError:
            amount_val = None
        pay_date = _normalize_date_str(rec["date"]) if rec.get("date") else date.today().isoformat()
        con.execute("""UPDATE payments SET status='paid', amount=?, pay_date=?
                       WHERE client_id=? AND pay_key=?""", (amount_val, pay_date, c["id"], key))
        added += 1
    con.commit()
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:30]}


def _import_queries_rows(con, rows, default_client_id="", actor=""):
    parsed = _rows_to_dicts(rows, QUERY_ALIASES)
    if not parsed:
        raise ApiError("No data rows found in that sheet.")
    added, skipped, errors = 0, 0, []
    for idx, rec in parsed:
        ref = rec.get("clientId") or default_client_id
        text = (rec.get("queryText") or "").strip()
        if not ref:
            skipped += 1; errors.append(f"Row {idx}: no client id given, skipped."); continue
        c = _find_client(con, ref)
        if not c:
            skipped += 1; errors.append(f"Row {idx}: client '{ref}' not found, skipped."); continue
        if not text:
            skipped += 1; errors.append(f"Row {idx}: missing the query text, skipped."); continue
        qdate = _normalize_date_str(rec["queryDate"]) if rec.get("queryDate") else datetime.now().strftime("%Y-%m-%d")
        con.execute("""INSERT INTO client_queries (client_id, query_text, query_date, assigned_to, created_by)
                       VALUES (?,?,?,?,?)""",
                    (c["id"], text, qdate, (rec.get("assignedTo") or "").strip(), actor or "Import"))
        added += 1
    con.commit()
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:30]}


BULK_IMPORT_KINDS = {"clients", "notes", "referrals", "tasks", "team", "payments", "queries"}


def _dispatch_bulk_import(con, kind, rows, d):
    actor = (d.get("actorName") or d.get("role") or "").strip()
    default_client_id = (d.get("clientId") or "").strip()
    if kind == "clients":
        return _import_rows(con, rows)
    if kind == "notes":
        return _import_notes_rows(con, rows, default_client_id, actor)
    if kind == "referrals":
        return _import_referrals_rows(con, rows, default_client_id)
    if kind == "tasks":
        return _import_tasks_rows(con, rows, default_client_id, actor)
    if kind == "team":
        return _import_team_rows(con, rows)
    if kind == "payments":
        return _import_payments_rows(con, rows)
    if kind == "queries":
        return _import_queries_rows(con, rows, default_client_id, actor)
    raise ApiError("Unknown import type.")


def handle_action(action, d, ip=""):
    con = db()
    try:
        # SECURITY: "login_options" was removed. It returned every employee's name,
        # role, team and ID to anonymous callers so the login screen could show
        # employee cards. Employees now type their ID instead.

        # "Who am I?" — lets the page restore the signed-in view after a refresh
        # from the HttpOnly cookie alone, instead of trusting sessionStorage.
        if action == "session":
            sess = get_session(con, d.get("_session_token"))
            if not sess:
                return {"authenticated": False}
            out = {"authenticated": True, "kind": sess["kind"], "role": sess["role"],
                   "csrfToken": sess["csrf"]}
            if sess["kind"] == "employee":
                out.update({"empId": sess["emp_id"], "empUid": sess["emp_uid"],
                            "empName": sess["emp_name"], "empRole": sess["emp_role"],
                            "empTeamType": sess["emp_team_type"] or ""})
            elif sess["kind"] == "client":
                out["clientId"] = sess["client_id"]
            return out

        if action == "logout":
            delete_session(con, d.get("_session_token"))
            return {"ok": True, "_clear_cookie": True}

        if action == "login":
            # SECURITY: brute-force throttling on login attempts, per source IP.
            if _rate_limited(ip, "login", limit=10, window_seconds=300):
                raise ApiError("Too many login attempts. Please wait a few minutes and try again.")
            role = d.get("role") or ""
            if role == "employee":
                uid = (d.get("empUid") or "").strip()
                if not uid:
                    raise ApiError("Enter your employee ID.")
                e = con.execute("SELECT * FROM employees WHERE UPPER(emp_uid)=UPPER(?)", (uid,)).fetchone()
                if not e:
                    raise ApiError("Employee ID not found. Ask your Technical Manager to check it.")
                if not e["active"]:
                    raise ApiError("Your access has been disabled by the Super Admin. Contact them for help.")
                if not verify_password(d.get("password") or "", e["password"] or ""):
                    raise ApiError("Incorrect password. Please try again.")
                delete_session(con, d.get("_session_token"))   # no session fixation
                sess = create_session(con, "employee", "employee", ip=ip, emp_id=e["id"],
                                       emp_uid=e["emp_uid"], emp_name=e["name"], emp_role=e["role"],
                                       emp_team_type=e["team_type"] or "")
                return {"ok": True, "empId": e["id"], "empName": e["name"], "empRole": e["role"],
                        "empTeamType": e["team_type"] or "", "empUid": e["emp_uid"],
                        "csrfToken": sess["csrf"], "_session_token": sess["token"]}
            if role == "client":
                key = (d.get("clientKey") or "").strip()
                if not key:
                    raise ApiError("Enter your registered phone number or client ID.")
                c = con.execute("""SELECT * FROM clients
                                   WHERE LOWER(id)=LOWER(?)
                                      OR LOWER(display_id)=LOWER(?)
                                      OR REPLACE(phone,' ','')=REPLACE(?,' ','')
                                   ORDER BY created_at DESC, id DESC""",
                                (key, key, key)).fetchone()
                if not c:
                    raise ApiError("No client found with that phone/ID. Ask your telecaller to register you.")
                if not c["client_password"]:
                    raise ApiError("Your account isn't set up yet. Check your email for the invitation from "
                                   "iMatiz, or ask your BDC/Marketing contact to resend it.")
                if not verify_password(d.get("password") or "", c["client_password"]):
                    raise ApiError("Incorrect password. Please try again.")
                con.execute("UPDATE clients SET last_login_at=? WHERE id=?",
                            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), c["id"]))
                con.commit()
                delete_session(con, d.get("_session_token"))
                sess = create_session(con, "client", "client", ip=ip, client_id=c["id"])
                return {"ok": True, "clientId": c["id"],
                        "csrfToken": sess["csrf"], "_session_token": sess["token"]}
            u = con.execute("SELECT * FROM users WHERE role=?", (role,)).fetchone()
            if not u:
                raise ApiError("Please select a role above.")
            if not u["enabled"]:
                raise ApiError("This role's access has been disabled by the Super Admin. Contact them for help.")
            if not verify_password(d.get("password") or "", u["password"] or ""):
                raise ApiError("Incorrect password. Please try again.")
            delete_session(con, d.get("_session_token"))
            sess = create_session(con, "dept", role, ip=ip)
            return {"ok": True, "csrfToken": sess["csrf"], "_session_token": sess["token"]}

        if action == "create_invite_link":
            # Generates (or reuses) a pending setup code and hands back a shareable
            # link, without requiring an email on file or sending anything — for
            # staff who'd rather share it directly (WhatsApp, SMS, in person, etc.)
            client_id = (d.get("clientId") or "").strip()
            actor_role = (d.get("role") or "").strip()
            if actor_role not in INVITE_ROLES:
                raise ApiError("You don't have permission to create a client invite link.")
            c = get_client(con, client_id)
            token = c["invite_token"] or secrets.token_hex(4).upper()
            sent_at = c["invite_sent_at"] or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            con.execute("UPDATE clients SET invite_token=?, invite_sent_at=? WHERE id=?",
                        (token, sent_at, c["id"]))
            con.commit()
            display_id = c["display_id"] or c["id"]
            return {"ok": True, "token": token, "displayId": display_id, "clientName": c["name"]}

        if action == "send_client_invite":
            client_id = (d.get("clientId") or "").strip()
            actor_role = (d.get("role") or "").strip()
            if actor_role not in INVITE_ROLES:
                raise ApiError("You don't have permission to send client invitations.")
            c = get_client(con, client_id)
            if not c["email"]:
                raise ApiError("This client doesn't have an email on file yet — add one first.")
            pwd = GMAIL_APP_PASSWORD.replace(" ", "")
            sender = GMAIL_USER.strip()
            if not sender or not pwd:
                raise ApiError("Email isn't set up yet. Set GMAIL_USER and GMAIL_APP_PASSWORD in the server's environment (.env), then restart. See README.txt."
                               "GMAIL_USER and GMAIL_APP_PASSWORD in the environment (.env), then restart the "
                               "server (stop it with Ctrl+C and run 'python server.py' again). Steps are in "
                               "README.txt under 'AUTOMATIC EMAILS'.")
            token = c["invite_token"] or secrets.token_hex(4).upper()
            display_id = c["display_id"] or c["id"]
            origin = (d.get("origin") or "").strip()
            link = portal_link(display_id, token, origin)
            plain_body = (f"Hi {c['name']},\n\n"
                    f"Welcome to iMatiz Technology! Your client portal is ready.\n\n"
                    f"Your Client ID (this is your login username): {display_id}\n"
                    f"Your one-time setup code: {token}\n\n"
                    f"Set your password the easy way — just open this link:\n"
                    f"{link}\n\n"
                    f"Or set it up manually:\n"
                    f"1. Open the iMatiz portal and choose \"Client\" on the login screen.\n"
                    f"2. Select \"First time? Set your password\".\n"
                    f"3. Enter your Client ID and the setup code above, then choose your own password.\n\n"
                    f"Keep your Client ID and password safe — you'll use them every time you log in.\n\n"
                    f"— iMatiz Technology")
            html_body = invite_email_html(c["name"], display_id, token, link)
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "Your iMatiz client portal is ready"
            msg["From"] = sender
            msg["To"] = c["email"]
            msg.attach(MIMEText(plain_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))
            try:
                with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
                    smtp.login(sender, pwd)
                    smtp.sendmail(sender, [c["email"]], msg.as_string())
            except smtplib.SMTPAuthenticationError:
                raise ApiError("Gmail rejected the login. Double-check GMAIL_USER is the exact Gmail "
                               "address the app password belongs to, that the app password has no typos "
                               "or extra spaces, and that 2-Step Verification is ON for this Gmail account.")
            except (smtplib.SMTPException, OSError, TimeoutError) as e:
                raise ApiError("Could not reach Gmail to send the email (" + str(e) + "). "
                               "Check your internet connection and try again.")
            # Only mark the invite as sent once the email genuinely went out.
            con.execute("UPDATE clients SET invite_token=?, invite_sent_at=? WHERE id=?",
                        (token, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), c["id"]))
            con.commit()
            return {"ok": True, "email": c["email"], "token": token, "displayId": display_id, "link": link}

        if action == "set_client_password":
            # SECURITY: throttle setup-code guessing (this action is intentionally public).
            if _rate_limited(ip, "set_client_password", limit=10, window_seconds=300):
                raise ApiError("Too many attempts. Please wait a few minutes and try again.")
            key = (d.get("clientKey") or "").strip()
            token = (d.get("token") or "").strip().upper()
            new_password = (d.get("newPassword") or "").strip()
            if not key or not token:
                raise ApiError("Enter your Client ID and the setup code from your invitation email.")
            if len(new_password) < MIN_PASSWORD_LENGTH:
                raise ApiError("Choose a password at least %d characters long." % MIN_PASSWORD_LENGTH)
            c = con.execute("""SELECT * FROM clients
                               WHERE LOWER(id)=LOWER(?) OR LOWER(display_id)=LOWER(?)
                                  OR REPLACE(phone,' ','')=REPLACE(?,' ','')
                               ORDER BY created_at DESC, id DESC""", (key, key, key)).fetchone()
            if not c:
                raise ApiError("No client found with that Client ID or phone number.")
            if not c["invite_token"] or c["invite_token"].upper() != token:
                raise ApiError("That setup code doesn't match. Double check your invitation email, "
                               "or ask Marketing to resend it.")
            con.execute("UPDATE clients SET client_password=?, invite_token='', password_reset_requested=0, "
                       "password_reset_requested_at='' WHERE id=?", (hash_password(new_password), c["id"]))
            con.commit()
            return {"ok": True, "clientId": c["id"]}

        if action == "request_client_password_reset":
            # SECURITY: throttle to slow down account enumeration / spam requests.
            if _rate_limited(ip, "request_client_password_reset", limit=10, window_seconds=300):
                raise ApiError("Too many requests. Please wait a few minutes and try again.")
            key = (d.get("clientKey") or "").strip()
            if not key:
                raise ApiError("Enter your registered phone number or client ID.")
            c = con.execute("""SELECT * FROM clients
                               WHERE LOWER(id)=LOWER(?) OR LOWER(display_id)=LOWER(?)
                                  OR REPLACE(phone,' ','')=REPLACE(?,' ','')
                               ORDER BY created_at DESC, id DESC""", (key, key, key)).fetchone()
            if not c:
                # SECURITY: don't reveal whether that phone/ID exists in the system.
                return {"ok": True}
            con.execute("UPDATE clients SET password_reset_requested=1, password_reset_requested_at=? WHERE id=?",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), c["id"]))
            con.commit()
            return {"ok": True}

        if action == "admin_reset_client_password":
            client_id = (d.get("clientId") or "").strip()
            actor_role = (d.get("role") or "").strip()
            if actor_role not in INVITE_ROLES:
                raise ApiError("You don't have permission to reset a client's password.")
            new_password = (d.get("newPassword") or "").strip()
            if len(new_password) < MIN_PASSWORD_LENGTH:
                raise ApiError("Choose a password at least %d characters long." % MIN_PASSWORD_LENGTH)
            c = get_client(con, client_id)
            con.execute("""UPDATE clients SET client_password=?, invite_token='', password_reset_requested=0,
                           password_reset_requested_at='' WHERE id=?""",
                        (hash_password(new_password), c["id"]))
            con.commit()
            return {"ok": True}

        if action == "bootstrap":
            events = [dict(r) for r in con.execute(
                """SELECT id, title, event_date, event_time, note, color, created_by, created_by_id, visibility
                   FROM calendar_events ORDER BY event_date""")]
            queries = [dict(r) for r in con.execute(
                """SELECT id, client_id, query_text, query_date, assigned_to, status,
                          resolved_on, reply_text, replied_on, created_by, created_at
                   FROM client_queries ORDER BY query_date DESC, id DESC""")]
            tasks = [dict(r) for r in con.execute(
                """SELECT id, title, description, client_id, priority, start_date, finish_date,
                          status, assigned_to, notes, created_by, created_at, task_type
                   FROM tasks ORDER BY created_at DESC, id DESC""")]
            comments_by = {}
            for r in con.execute("SELECT * FROM task_comments ORDER BY created_at ASC, id ASC"):
                comments_by.setdefault(r["task_id"], []).append(
                    {"author": r["author"], "body": r["body"], "at": iso(r["created_at"])})
            for t in tasks:
                t["comments"] = comments_by.get(t["id"], [])
            # Document metadata only (never the file bytes) — keeps every page load light.
            client_docs = [dict(r) for r in con.execute(
                """SELECT id, client_id, file_name, file_type, uploaded_by, created_at
                   FROM client_documents ORDER BY created_at DESC""")]
            client_notes = [dict(r) for r in con.execute(
                """SELECT id, client_id, title, description, created_by, created_at
                   FROM client_notes_v2 ORDER BY created_at DESC""")]
            client_refs = [dict(r) for r in con.execute(
                """SELECT id, client_id, designation, name, email, mobile, created_at
                   FROM client_referrals ORDER BY created_at DESC""")]
            clients_out = all_clients(con)

            # SECURITY (IDOR fix): a logged-in "client" session must only ever receive data
            # about itself (and any other service under the same CL-ID "family" — the app's
            # own "Same client, another service" feature already groups those together on
            # the front end via displayId). Previously every client received every OTHER
            # client's full record (payments, notes, documents, addresses...) in this same
            # response; staff dashboards intentionally still get the full shared dataset.
            if (d.get("role") or "") == "client":
                self_row = con.execute("SELECT id, display_id FROM clients WHERE id=?",
                                        (d.get("clientId") or "",)).fetchone()
                family_did = (self_row["display_id"] or self_row["id"]) if self_row else None
                family_ids = {r["id"] for r in con.execute(
                    "SELECT id FROM clients WHERE COALESCE(NULLIF(display_id,''), id)=?",
                    (family_did,))} if family_did else set()
                clients_out = [c for c in clients_out if c["id"] in family_ids]
                queries = [q for q in queries if q["client_id"] in family_ids]
                tasks = [t for t in tasks if t.get("client_id") in family_ids]
                client_docs = [x for x in client_docs if x["client_id"] in family_ids]
                client_notes = [x for x in client_notes if x["client_id"] in family_ids]
                client_refs = [x for x in client_refs if x["client_id"] in family_ids]
                events = [e for e in events if (e.get("visibility") or "everyone") != "private"]
                # SECURITY: strip internal-only fields from the client's own record.
                # These were being sent to the portal: staff call notes, the portal
                # setup token, hold/rejection reasons and internal history.
                clients_out = [scrub_client_for_client(c) for c in clients_out]
                client_notes = []          # internal staff notes are not portal content

            # SECURITY: individually-added employees (programmers, writers, ...) used to
            # receive the entire client table here — every phone number, e-mail address,
            # fee breakdown, payment row and portal setup token in the business. They now
            # get only the clients they are actually attached to, with money and portal
            # tokens removed, plus a reduced employee directory.
            elif (d.get("role") or "") == "employee":
                emp_name = (d.get("empName") or "").strip()
                emp_id = d.get("empId")
                visible = employee_visible_client_ids(con, emp_id, emp_name, tasks, queries)
                clients_out = [scrub_client_for_employee(c) for c in clients_out
                               if c["id"] in visible]
                queries = [q for q in queries if q["client_id"] in visible]
                tasks = [t for t in tasks if t.get("client_id") in visible]
                client_docs = [x for x in client_docs if x["client_id"] in visible]
                client_notes = [x for x in client_notes if x["client_id"] in visible]
                client_refs = []
                events = [e for e in events if (e.get("visibility") or "everyone") != "private"]

            employees_out = all_employees(con)
            if (d.get("role") or "") in ("client", "employee"):
                employees_out = [scrub_employee(e) for e in employees_out]

            return {"clients": clients_out, "employees": employees_out,
                    "settings": get_settings(con), "calendarEvents": events, "clientQueries": queries,
                    "tasks": tasks, "clientDocuments": client_docs, "clientNotes": client_notes,
                    "clientReferrals": client_refs,
                    "services": {k: {"label": v["label"], "hasImplementation": v["hasImplementation"],
                                      "requiresWritingFee": v.get("requiresWritingFee", False),
                                      "amounts": v["amounts"]} for k, v in SERVICES.items()}}

        if action == "add_client":
            name = (d.get("name") or "").strip()
            phone = (d.get("phone") or "").strip()
            deadline = d.get("deadlineDate") or ""
            if not name or not phone:
                raise ApiError("Client name and phone are required.")
            if not deadline:
                raise ApiError("Project deadline date is required.")
            service_key = (d.get("serviceKey") or "").strip().upper()
            if service_key not in SERVICES:
                raise ApiError("Pick a service for this client.")

            try:
                reg_amount = float(d.get("regAmount"))
            except (TypeError, ValueError):
                raise ApiError("Enter the registration amount the client paid.")
            if reg_amount <= 0:
                raise ApiError("Registration amount must be greater than zero to register the client.")

            try:
                total_amount = float(d.get("totalAmount")) if d.get("totalAmount") not in (None, "") else 0.0
            except (TypeError, ValueError):
                raise ApiError("Enter a valid total amount.")

            reg = d.get("regDate") or date.today().isoformat()
            email = (d.get("email") or "").strip()

            display_id = None
            norm_phone = phone.replace(" ", "").lower()
            existing_family = con.execute(
                """SELECT * FROM clients
                   WHERE (phone<>'' AND LOWER(REPLACE(phone,' ',''))=?)
                      OR (email<>'' AND ?<>'' AND LOWER(email)=LOWER(?))
                   ORDER BY created_at ASC, id ASC""",
                (norm_phone, email, email)).fetchall()
            if existing_family:
                # Same phone or email as an existing client -> this is another work for
                # that SAME client (santhosh can take Scopus-paid twice, three times,
                # whatever) — keep the one CL-ID and just add another work record under
                # it. No blocking here, even if it's the exact same service again; the
                # "Work X of Y" badge (serviceFamilyInfo in index.html) numbers them.
                display_id = existing_family[0]["display_id"] or existing_family[0]["id"]

            n = 1001
            for r in con.execute("SELECT id FROM clients"):
                m = re.match(r"^CL-(\d+)$", r["id"])
                if m:
                    n = max(n, int(m.group(1)) + 1)

            if display_id:
                siblings = con.execute(
                    "SELECT COUNT(*) c FROM clients WHERE display_id=?", (display_id,)).fetchone()["c"]
                cid = f"{display_id}-S{siblings + 1}"
            else:
                cid = f"CL-{n}"
                display_id = cid

            pn = 2001
            for r in con.execute("SELECT project_id FROM clients"):
                m = re.match(r"^PRJ-(\d+)$", r["project_id"] or "")
                if m:
                    pn = max(pn, int(m.group(1)) + 1)
            project_id = f"PRJ-{pn}"

            con.execute("""INSERT INTO clients
                           (id,display_id,project_id,name,phone,email,domain,address,notes,reg_date,deadline_date,
                            stage,service_key,designation,institution,topic,technical_person,
                            base_paper_provided,bdc,total_amount,alt_mobile,institutional_email,
                            department,referred_by)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,'NEW',?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (cid, display_id, project_id, name, phone, email,
                         (d.get("domain") or "").strip(), (d.get("address") or "").strip(),
                         (d.get("notes") or "").strip(), reg, deadline, service_key,
                         (d.get("designation") or "").strip(), (d.get("institution") or "").strip(),
                         (d.get("topic") or "").strip(), (d.get("technicalPerson") or "").strip(),
                         1 if d.get("basePaperProvided") else 0, (d.get("bdc") or "").strip(), total_amount,
                         (d.get("altMobile") or "").strip(), (d.get("institutionalEmail") or "").strip(),
                         (d.get("department") or "").strip(), (d.get("referredBy") or "").strip()))
            plan_name = (d.get("installmentPlanName") or "").strip()
            if plan_name:
                con.execute("UPDATE clients SET installment_plan_name=? WHERE id=?", (plan_name, cid))
            for k in PAY_KEYS:
                if k == "reg":
                    con.execute("""INSERT INTO payments (client_id, pay_key, status, amount, pay_date)
                                   VALUES (?,?,'paid',?,?)""", (cid, k, reg_amount, reg))
                else:
                    con.execute("INSERT INTO payments (client_id, pay_key) VALUES (?,?)", (cid, k))

            # ----- amount split-up, entered ONCE by the Telecaller/Marketing person right here at
            #       registration (not added manually later, stage by stage, by other roles). This
            #       becomes the pre-filled/expected amount for every later stage payment.
            split = d.get("amountSplit") or {}
            if isinstance(split, dict):
                for k in PAY_KEYS:
                    try:
                        v = float(split.get(k)) if split.get(k) not in (None, "") else 0.0
                    except (TypeError, ValueError):
                        v = 0.0
                    if v > 0:
                        con.execute(
                            """INSERT INTO service_items (client_id, pay_key, name, amount)
                               VALUES (?,?,?,?)""",
                            (cid, k, "Split set at registration" if k != "reg" else "Registration amount", v))

            actor = (d.get("actorLabel") or "").strip() or "Telecaller"
            con.execute("INSERT INTO history (client_id, stage, actor) VALUES (?,'NEW',?)", (cid, actor))
            con.commit()
            return {"ok": True, "id": cid, "displayId": display_id, "projectId": project_id}

        if action == "add_call":
            c = get_client(con, d.get("clientId") or "")
            nxt = d.get("next") or None
            con.execute("INSERT INTO calls (client_id, call_type, note, next_date) VALUES (?,?,?,?)",
                        (c["id"], d.get("type") or "Follow-up", (d.get("note") or "").strip(), nxt))
            if nxt:
                con.execute("UPDATE clients SET next_follow_up=? WHERE id=?", (nxt, c["id"]))
            con.commit()
            return {"ok": True}

        if action == "mark_paid":
            c = get_client(con, d.get("clientId") or "")
            k = d.get("payKey") or ""
            check_pay_key(k)
            amount = None if d.get("amount") in (None, "") else float(d["amount"])
            pay_date = d.get("date") or date.today().isoformat()
            con.execute("""UPDATE payments SET status='paid', amount=?, pay_date=?
                           WHERE client_id=? AND pay_key=?""", (amount, pay_date, c["id"], k))
            con.commit()
            return {"ok": True}

        MARKETING_ROLES = ("telecaller", "marketing_tl", "marketing_manager", "super_admin", "md_admin")

        if action == "add_service_item":
            if (d.get("role") or "") not in MARKETING_ROLES:
                raise ApiError("Only the Telecaller, a Marketing person, or an Admin can set the amount split-up.")
            c = get_client(con, d.get("clientId") or "")
            k = d.get("payKey") or ""
            check_pay_key(k)
            name = (d.get("name") or "").strip()
            if not name:
                raise ApiError("Service name is required.")
            try:
                amount = float(d.get("amount") or 0)
            except (TypeError, ValueError):
                raise ApiError("Enter a valid amount.")
            con.execute("INSERT INTO service_items (client_id, pay_key, name, amount) VALUES (?,?,?,?)",
                        (c["id"], k, name, amount))
            con.commit()
            return {"ok": True}

        if action == "delete_service_item":
            if (d.get("role") or "") not in MARKETING_ROLES:
                raise ApiError("Only the Telecaller, a Marketing person, or an Admin can edit the amount split-up.")
            item_id = d.get("itemId")
            if not item_id:
                raise ApiError("Missing item.")
            con.execute("DELETE FROM service_items WHERE id=?", (item_id,))
            con.commit()
            return {"ok": True}

        # ----- Freeform custom installment plan, entered once at registration time.
        #       Unlike service_items (which are tied to a fixed payment stage like
        #       "Code Implementation"), these have whatever title the Telecaller /
        #       Marketing person / Admin typed in, and simply need to add up to the
        #       remaining balance (total amount minus the registration payment).
        if action == "add_client_installments":
            if (d.get("role") or "") not in MARKETING_ROLES:
                raise ApiError("Only the Telecaller, a Marketing person, or an Admin can set the split-up.")
            c = get_client(con, d.get("clientId") or "")
            items = d.get("items") or []
            if not isinstance(items, list):
                raise ApiError("Invalid installment list.")
            for idx, it in enumerate(items):
                title = (it.get("title") or "").strip() if isinstance(it, dict) else ""
                if not title:
                    raise ApiError("Every installment needs a title.")
                try:
                    amount = float(it.get("amount") or 0)
                except (TypeError, ValueError):
                    raise ApiError("Enter a valid amount for every installment.")
                if amount <= 0:
                    raise ApiError("Every installment amount must be greater than zero.")
                con.execute("""INSERT INTO client_installments (client_id, title, amount, sort_order)
                               VALUES (?,?,?,?)""", (c["id"], title, amount, idx))
            con.commit()
            return {"ok": True}

        if action == "mark_installment_paid":
            inst_id = d.get("installmentId")
            if not inst_id:
                raise ApiError("Missing installment.")
            row = con.execute("SELECT * FROM client_installments WHERE id=?", (inst_id,)).fetchone()
            if not row:
                raise ApiError("That installment no longer exists.")
            amount = row["amount"] if d.get("amount") in (None, "") else float(d["amount"])
            pay_date = d.get("date") or date.today().isoformat()
            con.execute("""UPDATE client_installments SET status='paid', amount=?, paid_date=?
                           WHERE id=?""", (amount, pay_date, inst_id))
            con.commit()
            return {"ok": True}

        if action == "delete_client_installment":
            if (d.get("role") or "") not in MARKETING_ROLES:
                raise ApiError("Only the Telecaller, a Marketing person, or an Admin can edit the split-up.")
            inst_id = d.get("installmentId")
            if not inst_id:
                raise ApiError("Missing installment.")
            con.execute("DELETE FROM client_installments WHERE id=?", (inst_id,))
            con.commit()
            return {"ok": True}

        if action == "reject_client":
            c = get_client(con, d.get("clientId") or "")
            reason = (d.get("reason") or "").strip()
            con.execute("""UPDATE clients SET rejected=1, reject_reason=?,
                           rejected_at=to_char(now(), 'YYYY-MM-DD HH24:MI:SS') WHERE id=?""", (reason, c["id"]))
            con.commit()
            return {"ok": True}

        if action == "unreject_client":
            c = get_client(con, d.get("clientId") or "")
            con.execute("UPDATE clients SET rejected=0, reject_reason='', rejected_at=NULL WHERE id=?",
                        (c["id"],))
            con.commit()
            return {"ok": True}

        if action == "update_client":
            c = get_client(con, d.get("clientId") or "")
            col_map = {"name": "name", "phone": "phone", "email": "email", "domain": "domain",
                       "address": "address", "notes": "notes", "deadlineDate": "deadline_date",
                       "designation": "designation", "institution": "institution", "topic": "topic",
                       "technicalPerson": "technical_person", "bdc": "bdc",
                       "altMobile": "alt_mobile", "institutionalEmail": "institutional_email",
                       "department": "department", "referredBy": "referred_by",
                       "installmentPlanName": "installment_plan_name"}
            field_label = {"name": "Name", "phone": "Phone", "email": "Email", "domain": "Domain name",
                           "address": "Address", "notes": "Notes", "deadlineDate": "Project deadline",
                           "designation": "Designation", "institution": "University/College/Company",
                           "topic": "Topic", "technicalPerson": "Technical person", "bdc": "BDC",
                           "altMobile": "Alternative mobile", "institutionalEmail": "Institutional email",
                           "department": "Department", "referredBy": "Referred by",
                           "installmentPlanName": "Split-up plan name"}
            updates = {}
            for key, col in col_map.items():
                if key in d:
                    updates[col] = (d.get(key) or "").strip()

            # Non-text fields handled separately (boolean / numeric).
            numeric_changes = []
            if "basePaperProvided" in d:
                new_bp = 1 if d.get("basePaperProvided") else 0
                if new_bp != (c["base_paper_provided"] or 0):
                    numeric_changes.append(
                        f"Base paper provided: \"{'Yes' if c['base_paper_provided'] else 'No'}\" -> \"{'Yes' if new_bp else 'No'}\"")
                updates["base_paper_provided"] = new_bp
            if "totalAmount" in d and d.get("totalAmount") not in (None, ""):
                try:
                    new_total = float(d.get("totalAmount"))
                except (TypeError, ValueError):
                    raise ApiError("Enter a valid total amount.")
                if amt(new_total) != amt(c["total_amount"]):
                    numeric_changes.append(f"Total amount: \"{amt(c['total_amount']) or 0}\" -> \"{amt(new_total)}\"")
                updates["total_amount"] = new_total

            # FEATURE: allow Telecaller / Marketing TL / Marketing Manager / Admin to change
            # a client's service (and, via the totalAmount block above, the total contract
            # amount) after registration. Restricted to SERVICE_EDIT_ROLES since the service
            # drives the whole payment schedule.
            if "serviceKey" in d or ("totalAmount" in d and d.get("totalAmount") not in (None, "")):
                actor_role = (d.get("role") or "").strip()
                if actor_role not in SERVICE_EDIT_ROLES:
                    raise ApiError("Only the Telecaller, Marketing TL/Manager, or an Admin can change the service or amount.")
            if "serviceKey" in d:
                new_service = (d.get("serviceKey") or "").strip().upper()
                if new_service not in SERVICES:
                    raise ApiError("Pick a valid service.")
                if new_service != (c["service_key"] or DEFAULT_SERVICE):
                    numeric_changes.append(
                        f"Service: \"{service_conf(c['service_key'])['label']}\" -> \"{SERVICES[new_service]['label']}\"")
                updates["service_key"] = new_service

            if "name" in updates and not updates["name"]:
                raise ApiError("Name cannot be empty.")
            if "phone" in updates and not updates["phone"]:
                raise ApiError("Phone cannot be empty.")
            if not updates:
                raise ApiError("Nothing to update.")

            changes = []
            for key, col in col_map.items():
                if col in updates and updates[col] != (c[col] or ""):
                    old_val = c[col] or "(blank)"
                    new_val = updates[col] or "(blank)"
                    changes.append(f"{field_label[key]}: \"{old_val}\" -> \"{new_val}\"")
            changes += numeric_changes

            display_id = c["display_id"] or c["id"]
            merge_note = ""
            if ("phone" in updates or "email" in updates):
                new_phone = updates.get("phone", c["phone"] or "")
                new_email = updates.get("email", c["email"] or "")
                norm_phone = (new_phone or "").replace(" ", "").lower()
                other_match = con.execute(
                    """SELECT * FROM clients
                       WHERE id<>? AND display_id<>?
                         AND ((phone<>'' AND LOWER(REPLACE(phone,' ',''))=?)
                           OR (email<>'' AND ?<>'' AND LOWER(email)=LOWER(?)))
                       ORDER BY created_at ASC, id ASC""",
                    (c["id"], display_id, norm_phone, new_email, new_email)).fetchall()
                if other_match:
                    target_family = other_match[0]["display_id"] or other_match[0]["id"]
                    # Same as add_client: matching phone/email means this is the same
                    # client taking another work — merge into that family's CL-ID even
                    # if they already have one (or several) of the same service on file.
                    updates["display_id"] = target_family
                    merge_note = f"CL-ID changed from {display_id} to {target_family} (matches an existing client's phone/email)."
                    display_id = target_family

            set_clause = ", ".join(f"{col}=?" for col in updates)
            con.execute(f"UPDATE clients SET {set_clause} WHERE id=?", (*updates.values(), c["id"]))

            actor = (d.get("actorLabel") or "").strip() or "Staff"
            note_parts = changes + ([merge_note] if merge_note else [])
            if note_parts:
                con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,'EDITED',?,?)",
                            (c["id"], actor, "Edited details — " + "; ".join(note_parts)))
            con.commit()
            return {"ok": True, "displayId": display_id}

        if action == "import_clients":
            rows = _rows_from_upload(d.get("filename"), d.get("contentBase64"), d.get("csvText"))
            return _import_rows(con, rows)

        if action == "bulk_import":
            kind = (d.get("kind") or "").strip()
            if kind not in BULK_IMPORT_KINDS:
                raise ApiError("Unknown import type.")
            rows = _rows_from_upload(d.get("filename"), d.get("contentBase64"), d.get("csvText"))
            return _dispatch_bulk_import(con, kind, rows, d)

        if action == "bulk_import_from_url":
            kind = (d.get("kind") or "").strip()
            if kind not in BULK_IMPORT_KINDS:
                raise ApiError("Unknown import type.")
            rows = _fetch_sheet_rows(d.get("url"))
            return _dispatch_bulk_import(con, kind, rows, d)

        if action == "add_calendar_event":
            title = (d.get("title") or "").strip()
            event_date = (d.get("eventDate") or "").strip()
            if not title:
                raise ApiError("Give the event a title.")
            if not event_date:
                raise ApiError("Pick a date for the event.")
            color = (d.get("color") or "gold").strip() or "gold"
            note = (d.get("note") or "").strip()
            event_time = (d.get("eventTime") or "").strip()
            visibility = "private" if (d.get("visibility") == "private") else "everyone"
            actor = (d.get("actorName") or d.get("role") or "MD Admin").strip()
            actor_role = (d.get("role") or "").strip()
            actor_emp_name = (d.get("empName") or "").strip()
            # Identity key used to check "is this my own private event" - an individual
            # employee is identified by their own name; every other login is a shared role
            # account (Technical Manager, Admin, etc.), so "only me" there means "only this
            # role's login", matching how the rest of the app treats those logins.
            created_by_id = ("emp:" + actor_emp_name) if (actor_role == "employee" and actor_emp_name) else actor_role
            cur = con.execute(
                """INSERT INTO calendar_events (title, event_date, event_time, note, color, created_by, created_by_id, visibility)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (title, event_date, event_time, note, color, actor, created_by_id, visibility))
            con.commit()
            return {"ok": True, "id": cur.lastrowid}

        if action == "delete_calendar_event":
            eid = d.get("id")
            if not eid:
                raise ApiError("Missing event id.")
            con.execute("DELETE FROM calendar_events WHERE id=?", (eid,))
            con.commit()
            return {"ok": True}

        if action == "add_query":
            client_id = (d.get("clientId") or "").strip()
            query_text = (d.get("queryText") or "").strip()
            query_date = (d.get("queryDate") or "").strip() or datetime.now().strftime("%Y-%m-%d")
            assigned_to = (d.get("assignedTo") or "").strip()
            if not client_id:
                raise ApiError("Pick which client this query is from.")
            if not query_text:
                raise ApiError("Enter the query itself.")
            get_client(con, client_id)  # raises if not found
            actor = (d.get("actorName") or d.get("role") or "MD Admin").strip()
            cur = con.execute("""INSERT INTO client_queries
                (client_id, query_text, query_date, assigned_to, created_by)
                VALUES (?,?,?,?,?)""", (client_id, query_text, query_date, assigned_to, actor))
            con.commit()
            return {"ok": True, "id": cur.lastrowid}

        if action == "update_query":
            qid = d.get("id")
            if not qid:
                raise ApiError("Missing query id.")
            row = con.execute("SELECT * FROM client_queries WHERE id=?", (qid,)).fetchone()
            if not row:
                raise ApiError("That query no longer exists.")
            fields, vals = [], []
            if "assignedTo" in d:
                fields.append("assigned_to=?"); vals.append((d.get("assignedTo") or "").strip())
            if "replyText" in d:
                fields.append("reply_text=?"); vals.append((d.get("replyText") or "").strip())
                if (d.get("replyText") or "").strip() and not row["replied_on"]:
                    fields.append("replied_on=?"); vals.append(datetime.now().strftime("%Y-%m-%d"))
            if "status" in d:
                status = (d.get("status") or "OPEN").strip().upper()
                if status not in ("OPEN", "IN_PROGRESS", "RESOLVED"):
                    raise ApiError("Unknown status.")
                fields.append("status=?"); vals.append(status)
                if status == "RESOLVED" and not row["resolved_on"]:
                    fields.append("resolved_on=?"); vals.append(datetime.now().strftime("%Y-%m-%d"))
                if status != "RESOLVED":
                    fields.append("resolved_on=?"); vals.append(None)
            if not fields:
                raise ApiError("Nothing to update.")
            vals.append(qid)
            con.execute(f"UPDATE client_queries SET {', '.join(fields)} WHERE id=?", vals)
            con.commit()
            return {"ok": True}

        if action == "delete_query":
            qid = d.get("id")
            if not qid:
                raise ApiError("Missing query id.")
            con.execute("DELETE FROM client_queries WHERE id=?", (qid,))
            con.commit()
            return {"ok": True}

        if action == "add_task":
            # A task must never be created/assigned unless ALL required fields are
            # present: title, client, at least one employee, a start date, and a
            # deadline. The frontend already checks this for instant feedback, but
            # that can never be trusted alone — this is the authoritative check that
            # actually keeps incomplete task records out of the database.
            title = (d.get("title") or "").strip()
            if not title:
                raise ApiError("Give the task a title.")
            client_id = (d.get("clientId") or "").strip()
            if not client_id:
                raise ApiError("Select a client before assigning this task.")
            get_client(con, client_id)  # raises if not found
            assigned_to = (d.get("assignedTo") or "").strip()
            if not assigned_to:
                raise ApiError("Select at least one employee to assign this task to.")
            start_date = (d.get("startDate") or "").strip()
            if not start_date:
                raise ApiError("Select a start date for this task.")
            finish_date = (d.get("finishDate") or "").strip()
            if not finish_date:
                raise ApiError("Select a deadline / due date for this task.")
            priority = (d.get("priority") or "MEDIUM").strip().upper()
            if priority not in ("LOW", "MEDIUM", "HIGH"):
                priority = "MEDIUM"
            task_type = (d.get("taskType") or "").strip().upper()
            if task_type not in VALID_TASK_TYPES:
                task_type = ""
            actor = (d.get("actorName") or d.get("role") or "Marketing Manager").strip()
            cur = con.execute("""INSERT INTO tasks
                (title, description, client_id, priority, start_date, finish_date, assigned_to, created_by, task_type)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (title, (d.get("description") or "").strip(), client_id, priority,
                 start_date, finish_date, assigned_to, actor, task_type))
            con.commit()
            return {"ok": True, "id": cur.lastrowid}

        if action == "update_task":
            tid = d.get("id")
            if not tid:
                raise ApiError("Missing task id.")
            row = con.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
            if not row:
                raise ApiError("That task no longer exists.")
            fields, vals = [], []
            simple_map = {"title": "title", "description": "description", "assignedTo": "assigned_to",
                          "startDate": "start_date", "finishDate": "finish_date", "notes": "notes"}
            for key, col in simple_map.items():
                if key in d:
                    fields.append(f"{col}=?"); vals.append((d.get(key) or "").strip())
            if "taskType" in d:
                task_type = (d.get("taskType") or "").strip().upper()
                if task_type not in VALID_TASK_TYPES:
                    task_type = ""
                fields.append("task_type=?"); vals.append(task_type)
            if "priority" in d:
                priority = (d.get("priority") or "MEDIUM").strip().upper()
                if priority not in ("LOW", "MEDIUM", "HIGH"):
                    raise ApiError("Unknown priority.")
                fields.append("priority=?"); vals.append(priority)
            if "status" in d:
                status = (d.get("status") or "OPEN").strip().upper()
                if status not in ("OPEN", "IN_PROGRESS", "SUBMITTED", "COMPLETED", "NEEDS_CORRECTION"):
                    raise ApiError("Unknown status.")
                actor_role = (d.get("role") or "").strip()
                if status == "COMPLETED" and actor_role not in TASK_COMPLETION_ROLES:
                    raise ApiError("Only a Technical Manager/TL (technical tasks) or Journal Manager/TL (journal tasks) can approve a task as fully complete.")
                fields.append("status=?"); vals.append(status)
                note_author = (d.get("actorName") or actor_role or "Someone").strip()
                extra_note = (d.get("note") or "").strip()
                note_map = {
                    "IN_PROGRESS": f"{note_author} started this task.",
                    "SUBMITTED": f"{note_author} marked this as done — waiting on Technical Manager / TL approval.",
                    "COMPLETED": f"{note_author} approved this task as complete.",
                    "NEEDS_CORRECTION": f"{note_author} sent this back for correction." + (f" Note: {extra_note}" if extra_note else ""),
                }
                if status in note_map:
                    con.execute("INSERT INTO task_comments (task_id, author, body) VALUES (?,?,?)",
                                (tid, note_author, note_map[status]))
            if not fields:
                raise ApiError("Nothing to update.")
            vals.append(tid)
            con.execute(f"UPDATE tasks SET {', '.join(fields)} WHERE id=?", vals)

            # ----- keep the REAL client pipeline in sync. This task list is a separate
            #       tracking record for stats/boards - approving a task here used to be
            #       purely cosmetic, so the client's actual stage never moved and it never
            #       showed up in "Ready for Journal Team" (or anywhere else downstream).
            #       Now, approving a PROPOSAL / IMPLEMENTATION / PAPER_WRITING task also
            #       advances the real pipeline the same way the dedicated review buttons
            #       elsewhere do - but only if the client is actually sitting at the
            #       matching decision point right now. If it isn't (e.g. the writer hasn't
            #       actually submitted a draft yet), nothing is faked - the task is still
            #       marked complete for tracking, but a note explains it wasn't reflected
            #       in the real pipeline, so a TM/TL isn't misled into thinking it is.
            sync_note = None
            if "status" in d and status == "COMPLETED" and row["client_id"] and (row["task_type"] or "") in ("PROPOSAL", "IMPLEMENTATION", "PAPER_WRITING"):
                c = con.execute("SELECT * FROM clients WHERE id=?", (row["client_id"],)).fetchone()
                actor_label = "Technical TL" if actor_role == "technical_tl" else "Technical Manager"
                ttype = row["task_type"]
                if not c:
                    pass
                elif ttype == "PROPOSAL":
                    if c["stage"] == "PROPOSAL_SUBMITTED":
                        con.execute("UPDATE clients SET proposal_verified_by=? WHERE id=?", (actor_label, c["id"]))
                        move_stage(con, c["id"], "PROPOSAL_VERIFIED", actor_label,
                                   "Approved via Work Updates approval — ready for delivery to the client.")
                    elif stageIdxServer(c["stage"]) > stageIdxServer("PROPOSAL_SUBMITTED"):
                        pass  # already moved on for real - nothing to sync
                    else:
                        sync_note = ("Task marked complete, but the proposal hasn't actually been "
                                      "submitted yet in the real pipeline, so nothing moved forward there.")
                elif ttype == "IMPLEMENTATION":
                    if c["stage"] == "IMPLEMENTATION_ASSIGNED":
                        if c["demo_given_date"] and not c["demo_approved_at"]:
                            sync_note = ("Task marked complete, but this client's implementation is still "
                                          "waiting on demo approval before it can move forward for real — "
                                          "approve the demo first.")
                        else:
                            c = con.execute("SELECT * FROM clients WHERE id=?", (c["id"],)).fetchone()
                            move_stage(con, c["id"], "IMPLEMENTATION_COMPLETE", actor_label,
                                       "Marked complete via Work Updates approval — ready for delivery to the client.")
                    elif stageIdxServer(c["stage"]) > stageIdxServer("IMPLEMENTATION_ASSIGNED"):
                        pass
                    else:
                        sync_note = ("Task marked complete, but implementation hasn't actually started "
                                      "yet in the real pipeline, so nothing moved forward there.")
                elif ttype == "PAPER_WRITING":
                    # ----- BUG: this used to move the client forward only ONE review round
                    #       at a time (Coordinator -> Technical TL -> Technical Manager), but
                    #       the companion task is marked COMPLETED and vanishes from Work
                    #       Updates the moment it's approved once - so there was no way to
                    #       approve the remaining rounds from here, and the client got stuck
                    #       mid-review, never reaching WRITING_COMPLETE / Ready for Journal
                    #       Team, unlike Proposal and Implementation which only ever need one
                    #       approval and so always "just worked". Fixed: one "Approve — mark
                    #       complete" click here now walks through every remaining review
                    #       round in one go, all the way to WRITING_COMPLETE, matching the
                    #       one-click behaviour Proposal/Implementation already had.
                    review_chain = ["COORDINATOR_REVIEW", "TECHTL_REVIEW", "TECHMGR_REVIEW"]
                    if c["stage"] in review_chain:
                        next_stage_map = {"COORDINATOR_REVIEW": "TECHTL_REVIEW",
                                           "TECHTL_REVIEW": "TECHMGR_REVIEW",
                                           "TECHMGR_REVIEW": "WRITING_COMPLETE"}
                        note_map = {
                            "COORDINATOR_REVIEW": "Approved via Work Updates — sent on for Technical TL review.",
                            "TECHTL_REVIEW": "Approved via Work Updates — sent on for Technical Manager review.",
                            "TECHMGR_REVIEW": "Approved via Work Updates — writing approved internally, "
                                               "ready for the Journal Team.",
                        }
                        start_idx = review_chain.index(c["stage"])
                        for stage_name in review_chain[start_idx:]:
                            move_stage(con, c["id"], next_stage_map[stage_name], actor_label, note_map[stage_name])
                        if start_idx < len(review_chain) - 1:
                            sync_note = ("Approved — this also signed off the remaining internal review "
                                         "round(s) for you, and the client is now ready for the Journal Team.")
                    elif c["stage"] == "PAPERWRITER_ASSIGNED":
                        sync_note = ("Task marked complete, but the writer hasn't actually submitted their "
                                      "draft yet in the real pipeline — check with them before assuming this "
                                      "paper is ready to move on.")
                    elif c["stage"] == "WRITER_FIXING":
                        sync_note = ("Task marked complete, but this paper is currently sent back to the "
                                      "writer for correction in the real pipeline, so nothing moved forward there.")
                    elif stageIdxServer(c["stage"]) > stageIdxServer("TECHMGR_REVIEW"):
                        pass
                    else:
                        sync_note = ("Task marked complete, but nothing matching is currently waiting on "
                                      "review in the real pipeline for this client.")


            con.commit()
            return {"ok": True, "pipelineSyncNote": sync_note} if sync_note else {"ok": True}

        if action == "delete_task":
            tid = d.get("id")
            if not tid:
                raise ApiError("Missing task id.")
            con.execute("DELETE FROM tasks WHERE id=?", (tid,))
            con.commit()
            return {"ok": True}

        if action == "add_task_comment":
            tid = d.get("taskId")
            body = (d.get("body") or "").strip()
            author = (d.get("author") or d.get("role") or "").strip()
            if not tid:
                raise ApiError("Missing task id.")
            if not body:
                raise ApiError("Write a comment first.")
            if not con.execute("SELECT id FROM tasks WHERE id=?", (tid,)).fetchone():
                raise ApiError("That task no longer exists.")
            con.execute("INSERT INTO task_comments (task_id, author, body) VALUES (?,?,?)", (tid, author, body))
            con.commit()
            return {"ok": True}

        if action == "dm_directory":
            people = []
            for r in con.execute(
                "SELECT id, name, role, team_type FROM employees WHERE active=1 AND deleted_at IS NULL ORDER BY name"
            ):
                grp = EMP_ROLE_GROUP_LABELS.get(r["role"], r["role"])
                if r["team_type"]:
                    grp += " — " + r["team_type"].replace("_", " ").title()
                people.append({"key": f"EMP:{r['id']}", "name": r["name"], "group": grp})
            for rk in ["super_admin", "md_admin", "telecaller", "marketing_tl", "marketing_manager",
                       "account_team", "technical_manager", "technical_tl", "journal_manager", "journal_tl"]:
                people.append({"key": f"ROLE:{rk}", "name": STAFF_ROLE_LABELS.get(rk, rk), "group": "Department"})
            return {"people": people}

        if action == "dm_send":
            my_key = (d.get("myKey") or "").strip()
            my_name = (d.get("myName") or "").strip() or "Someone"
            to_key = (d.get("toKey") or "").strip()
            body = (d.get("body") or "").strip()
            file_name = sanitize_upload_filename(d.get("fileName"))
            file_type = sanitize_upload_filetype(d.get("fileType"))
            file_data = d.get("fileData") or ""
            if not my_key or not to_key:
                raise ApiError("Missing sender or recipient.")
            if my_key == to_key:
                raise ApiError("You can't message yourself.")
            if not body and not file_data:
                raise ApiError("Type a message or attach a file.")
            file_data = check_base64_payload(file_data, MAX_ATTACHMENT_BYTES, "attachment")
            p1, p2 = dm_pair(my_key, to_key)
            con.execute(
                "INSERT INTO dm_messages (p1,p2,sender_key,sender_name,body,file_name,file_type,file_data) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (p1, p2, my_key, my_name, body, file_name, file_type, file_data))
            con.commit()
            return {"ok": True}

        if action == "dm_typing":
            my_key = (d.get("myKey") or "").strip()
            other_key = (d.get("otherKey") or "").strip()
            if not my_key or not other_key:
                raise ApiError("Missing participant.")
            p1, p2 = dm_pair(my_key, other_key)
            _typing_touch(_TYPING_DM, (p1, p2, my_key))
            return {"ok": True}

        if action == "dm_thread":
            my_key = (d.get("myKey") or "").strip()
            other_key = (d.get("otherKey") or "").strip()
            if not my_key or not other_key:
                raise ApiError("Missing participant.")
            p1, p2 = dm_pair(my_key, other_key)
            rows = con.execute(
                "SELECT * FROM dm_messages WHERE p1=? AND p2=? ORDER BY created_at ASC, id ASC", (p1, p2)
            ).fetchall()
            con.execute(
                "INSERT INTO dm_reads (p1,p2,viewer_key,last_read_at) VALUES (?,?,?,to_char(now(), 'YYYY-MM-DD HH24:MI:SS')) "
                "ON CONFLICT(p1,p2,viewer_key) DO UPDATE SET last_read_at=excluded.last_read_at",
                (p1, p2, my_key))
            con.commit()
            other_typing = _typing_is_active(_TYPING_DM, (p1, p2, other_key))
            messages = [{
                "id": r["id"], "senderKey": r["sender_key"], "senderName": r["sender_name"],
                "body": r["body"], "fileName": r["file_name"], "fileType": r["file_type"],
                "fileData": r["file_data"], "at": iso(r["created_at"]),
            } for r in rows]
            return {"otherTyping": other_typing, "messages": messages}

        if action == "dm_inbox":
            my_key = (d.get("myKey") or "").strip()
            if not my_key:
                return {"threads": []}
            pairs = con.execute(
                "SELECT DISTINCT p1,p2 FROM dm_messages WHERE p1=? OR p2=?", (my_key, my_key)
            ).fetchall()
            threads = []
            for pr in pairs:
                p1, p2 = pr["p1"], pr["p2"]
                other = p2 if p1 == my_key else p1
                last = con.execute(
                    "SELECT * FROM dm_messages WHERE p1=? AND p2=? ORDER BY created_at DESC, id DESC LIMIT 1",
                    (p1, p2)).fetchone()
                readrow = con.execute(
                    "SELECT last_read_at FROM dm_reads WHERE p1=? AND p2=? AND viewer_key=?",
                    (p1, p2, my_key)).fetchone()
                last_read = readrow["last_read_at"] if readrow else None
                if last_read:
                    unread = con.execute(
                        "SELECT COUNT(*) c FROM dm_messages WHERE p1=? AND p2=? AND sender_key!=? AND created_at>?",
                        (p1, p2, my_key, last_read)).fetchone()["c"]
                else:
                    unread = con.execute(
                        "SELECT COUNT(*) c FROM dm_messages WHERE p1=? AND p2=? AND sender_key!=?",
                        (p1, p2, my_key)).fetchone()["c"]
                threads.append({
                    "otherKey": other, "otherName": dm_person_name(con, other),
                    "lastPreview": (last["body"] or (("Attachment: " + last["file_name"]) if last["file_name"] else "")) if last else "",
                    "lastAt": iso(last["created_at"]) if last else None,
                    "unread": unread,
                })
            threads.sort(key=lambda t: t["lastAt"] or "", reverse=True)
            return {"threads": threads}

        if action == "delete_client":
            client_id = (d.get("clientId") or "").strip()
            if not client_id:
                raise ApiError("Missing client id.")
            get_client(con, client_id)  # raises if not found
            con.execute("DELETE FROM clients WHERE id=?", (client_id,))
            con.commit()
            return {"ok": True}

        if action == "add_client_document":
            client_id = (d.get("clientId") or "").strip()
            file_name = sanitize_upload_filename(d.get("fileName"))
            file_data = d.get("fileData") or ""
            file_type = sanitize_upload_filetype(d.get("fileType"))
            if not client_id:
                raise ApiError("Missing client id.")
            if not file_name:
                raise ApiError("Give the file a name.")
            if not file_data:
                raise ApiError("Choose a file to upload.")
            file_data = check_base64_payload(file_data, MAX_UPLOAD_BYTES, "document")
            get_client(con, client_id)
            actor = (d.get("actorName") or d.get("role") or "").strip()
            cur = con.execute("""INSERT INTO client_documents (client_id, file_name, file_type, file_data, uploaded_by)
                                  VALUES (?,?,?,?,?)""", (client_id, file_name, file_type, file_data, actor))
            con.commit()
            return {"ok": True, "id": cur.lastrowid}

        if action == "delete_client_document":
            did = d.get("id")
            if not did:
                raise ApiError("Missing document id.")
            con.execute("DELETE FROM client_documents WHERE id=?", (did,))
            con.commit()
            return {"ok": True}

        if action == "get_client_document":
            did = d.get("id")
            row = con.execute("SELECT * FROM client_documents WHERE id=?", (did,)).fetchone()
            if not row:
                raise ApiError("That document no longer exists.")
            if (d.get("role") or "") == "client":
                # SECURITY (IDOR fix): a client may only fetch documents that belong to
                # their own CL-ID family, never another client's, by guessing/incrementing
                # the document id.
                self_row = con.execute("SELECT display_id FROM clients WHERE id=?",
                                        (d.get("clientId") or "",)).fetchone()
                doc_client = con.execute("SELECT display_id FROM clients WHERE id=?",
                                          (row["client_id"],)).fetchone()
                self_fam = (self_row["display_id"] or d.get("clientId")) if self_row else None
                doc_fam = (doc_client["display_id"] or row["client_id"]) if doc_client else None
                if not self_fam or self_fam != doc_fam:
                    raise ApiError("You don't have permission to view that document.")
            return {"id": row["id"], "fileName": row["file_name"], "fileType": row["file_type"],
                     "fileData": row["file_data"]}

        if action == "add_client_note":
            client_id = (d.get("clientId") or "").strip()
            title = (d.get("title") or "").strip()
            description = (d.get("description") or "").strip()
            if not client_id:
                raise ApiError("Missing client id.")
            if not title:
                raise ApiError("Give the note a title.")
            get_client(con, client_id)
            actor = (d.get("actorName") or d.get("role") or "").strip()
            cur = con.execute("""INSERT INTO client_notes_v2 (client_id, title, description, created_by)
                                  VALUES (?,?,?,?)""", (client_id, title, description, actor))
            con.commit()
            return {"ok": True, "id": cur.lastrowid}

        if action == "delete_client_note":
            nid = d.get("id")
            if not nid:
                raise ApiError("Missing note id.")
            con.execute("DELETE FROM client_notes_v2 WHERE id=?", (nid,))
            con.commit()
            return {"ok": True}

        if action == "add_client_referral":
            client_id = (d.get("clientId") or "").strip()
            name = (d.get("name") or "").strip()
            if not client_id:
                raise ApiError("Missing client id.")
            if not name:
                raise ApiError("Give the contact a name.")
            get_client(con, client_id)
            cur = con.execute("""INSERT INTO client_referrals (client_id, designation, name, email, mobile)
                                  VALUES (?,?,?,?,?)""",
                               (client_id, (d.get("designation") or "").strip(), name,
                                (d.get("email") or "").strip(), (d.get("mobile") or "").strip()))
            con.commit()
            return {"ok": True, "id": cur.lastrowid}

        if action == "delete_client_referral":
            rid = d.get("id")
            if not rid:
                raise ApiError("Missing referral id.")
            con.execute("DELETE FROM client_referrals WHERE id=?", (rid,))
            con.commit()
            return {"ok": True}

        if action == "import_clients_from_url":
            rows = _fetch_sheet_rows(d.get("url"))
            return _import_rows(con, rows)

        if action == "send_to_tl":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "NEW")
            calls = con.execute("SELECT COUNT(*) c FROM calls WHERE client_id=?", (c["id"],)).fetchone()["c"]
            if not calls:
                raise ApiError("Log at least one call before sending to the Marketing TL.")
            move_stage(con, c["id"], "TL_REVIEW", "Telecaller")
            con.commit()
            return {"ok": True}

        if action == "tl_verify":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "TL_REVIEW")
            move_stage(con, c["id"], "MANAGER_REVIEW", "Marketing TL")
            con.commit()
            return {"ok": True}

        if action == "manager_approve":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "MANAGER_REVIEW")
            move_stage(con, c["id"], "ACCOUNT_REVIEW", "Marketing Manager")
            con.commit()
            return {"ok": True}

        if action == "manager_fasttrack":
            c = get_client(con, d.get("clientId") or "")
            if c["rejected"]:
                raise ApiError("This client is marked as rejected — restore them first.")
            if c["stage"] not in ("NEW", "TL_REVIEW", "MANAGER_REVIEW"):
                raise ApiError("This client has already moved past Marketing Manager review.")
            move_stage(con, c["id"], "ACCOUNT_REVIEW", "Marketing Manager",
                       note="Fast-tracked directly to Accounts by the Marketing Manager, "
                            "skipping Marketing TL/Telecaller review.")
            con.commit()
            return {"ok": True}

        if action == "account_approve":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "ACCOUNT_REVIEW")
            move_stage(con, c["id"], "TECH_ASSIGNED", "Accounts Team")
            con.commit()
            return {"ok": True}

        if action == "assign_proposal_writer":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "TECH_ASSIGNED")
            if not service_conf(c["service_key"])["hasImplementation"]:
                raise ApiError("This service does not use a separate proposal/implementation stage — "
                                "assign a paper writer directly instead.")
            name = (d.get("name") or "").strip()
            if name not in active_names(con, "PAPER_WRITER"):
                raise ApiError("Unknown or inactive writer.")
            deadline = d.get("deadline") or ""
            if not deadline:
                raise ApiError("Set a proposal deadline.")
            actor = (d.get("actorLabel") or "Technical Team").strip()
            coord_row = con.execute(
                "SELECT is_coordinator FROM employees WHERE name=? AND role='PAPER_WRITER' AND active=1 AND deleted_at IS NULL",
                (name,)).fetchone()
            is_coord = bool(coord_row and coord_row["is_coordinator"])

            # ----- optional pre-assignment: Technical Manager/TL can pick the implementation
            #       team and/or paper writer(s) right now too, so nobody has to come back and
            #       assign them later - they're applied automatically the moment each becomes
            #       ready (proposal verified -> implementation starts; implementation complete
            #       -> paper writing starts). Both are optional and independent of each other.
            extra_notes = []
            pre_impl_programmers, pre_impl_deadline, pre_impl_by = "", "", ""
            pre_write_writers, pre_write_deadline, pre_write_by = "", "", ""

            impl_picked = [p for p in (d.get("preImplProgrammers") or []) if p in active_names(con, "PROGRAMMER")]
            impl_deadline = (d.get("preImplDeadline") or "").strip()
            if impl_picked and impl_deadline:
                pre_impl_programmers = ",".join(impl_picked)
                pre_impl_deadline = impl_deadline
                pre_impl_by = actor
                extra_notes.append(f"pre-assigned implementation to {', '.join(impl_picked)} "
                                    f"(will start automatically once the proposal is verified)")
            elif impl_picked or impl_deadline:
                raise ApiError("To pre-assign implementation, pick at least one programmer AND set an implementation deadline.")

            write_picked = [w for w in (d.get("preWriteWriters") or []) if w in active_names(con, "PAPER_WRITER")]
            write_deadline = (d.get("preWriteDeadline") or "").strip()
            if write_picked and write_deadline:
                pre_write_writers = ",".join(write_picked)
                pre_write_deadline = write_deadline
                pre_write_by = actor
                extra_notes.append(f"pre-assigned paper writing to {', '.join(write_picked)} "
                                    f"(will start automatically once implementation is complete)")
            elif write_picked or write_deadline:
                raise ApiError("To pre-assign paper writing, pick at least one writer AND set a writing deadline.")

            con.execute("""UPDATE clients SET proposal_writer=?, proposal_deadline=?,
                           proposal_coordinator=?, proposal_awaiting_team_pick=?,
                           pre_impl_programmers=?, pre_impl_deadline=?, pre_impl_by=?,
                           pre_write_writers=?, pre_write_deadline=?, pre_write_by=? WHERE id=?""",
                        (name, deadline, name if is_coord else "", 1 if is_coord else 0,
                         pre_impl_programmers, pre_impl_deadline, pre_impl_by,
                         pre_write_writers, pre_write_deadline, pre_write_by, c["id"]))
            note = f"Assigned to coordinator {name} — they'll write it themselves or hand it to a team member." if is_coord else ""
            if extra_notes:
                note = (note + " " if note else "") + "Also " + "; also ".join(extra_notes) + "."
            move_stage(con, c["id"], "PROPOSAL_ASSIGNED", actor, note)
            con.commit()
            return {"ok": True}

        if action == "coordinator_take_proposal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_ASSIGNED")
            if not c["proposal_awaiting_team_pick"]:
                raise ApiError("This isn't awaiting a team pick.")
            actor = (d.get("actorLabel") or c["proposal_coordinator"] or "Coordinator").strip()
            con.execute("UPDATE clients SET proposal_awaiting_team_pick=0 WHERE id=?", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"{actor} will write this proposal themselves."))
            con.commit()
            return {"ok": True}

        if action == "coordinator_assign_proposal_writer":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_ASSIGNED")
            if not c["proposal_awaiting_team_pick"]:
                raise ApiError("This isn't awaiting a team pick.")
            coordinator_name = (c["proposal_coordinator"] or "").strip()
            coord_row = con.execute(
                "SELECT id FROM employees WHERE name=? AND role='PAPER_WRITER' AND active=1 AND deleted_at IS NULL",
                (coordinator_name,)).fetchone()
            if not coord_row:
                raise ApiError("Coordinator not found.")
            valid_team = {r["name"] for r in con.execute(
                "SELECT name FROM employees WHERE role='PAPER_WRITER' AND coordinator_id=? AND active=1 AND deleted_at IS NULL",
                (coord_row["id"],))}
            name = (d.get("name") or "").strip()
            if name not in valid_team:
                raise ApiError("Pick someone from your own team.")
            actor = (d.get("actorLabel") or coordinator_name).strip()
            con.execute("UPDATE clients SET proposal_writer=?, proposal_awaiting_team_pick=0 WHERE id=?",
                        (name, c["id"]))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"{actor} assigned this proposal to team member {name}."))
            con.commit()
            return {"ok": True}

        if action == "submit_proposal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_ASSIGNED")
            who = (d.get("empName") or "").strip() or (c["proposal_writer"] or "Writer")
            con.execute("UPDATE clients SET proposal_submitted_at=to_char(now(), 'YYYY-MM-DD HH24:MI:SS') WHERE id=?",
                        (c["id"],))
            move_stage(con, c["id"], "PROPOSAL_SUBMITTED", who)
            con.commit()
            return {"ok": True}

        if action == "verify_proposal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_SUBMITTED")
            name = (d.get("name") or "").strip()
            if name:
                if name not in active_names(con, "PROGRAMMER"):
                    raise ApiError("Unknown or inactive programmer.")
                verifier = name
            else:
                verifier = (d.get("actorLabel") or "Technical TL").strip()
            con.execute("UPDATE clients SET proposal_verified_by=? WHERE id=?", (verifier, c["id"]))
            # ----- Technical TL/Manager (or a Programmer on their behalf) approves the
            #       proposal internally. It now waits in the "Delivery" queue - Technical
            #       TL/Manager still needs to explicitly deliver it to the client (see
            #       "deliver_proposal" below) before the client can approve it and
            #       implementation can be assigned.
            move_stage(con, c["id"], "PROPOSAL_VERIFIED", verifier,
                       "Approved by " + verifier + " — ready for delivery to the client.")
            con.commit()
            return {"ok": True}

        # ----- Delivery step: Technical TL/Manager hands the internally-approved proposal to
        #       the client. Shows in the "Delivery" section of New Work To Assign / Task Board.
        if action == "deliver_proposal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_VERIFIED")
            role = (d.get("role") or "").strip()
            if role not in ("technical_tl", "technical_manager"):
                raise ApiError("Only the Technical TL or Technical Manager can deliver this to the client.")
            actor = (d.get("actorLabel") or ("Technical TL" if role == "technical_tl" else "Technical Manager")).strip()
            move_stage(con, c["id"], "PROPOSAL_CLIENT_REVIEW", actor,
                       "Delivered to the client for approval.")
            con.commit()
            return {"ok": True}

        if action == "client_approve_proposal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_CLIENT_REVIEW")
            move_stage(con, c["id"], "PROPOSAL_APPROVED", "Client", "Client approved the proposal.")

            # ----- if an implementation team was pre-assigned at intake (alongside the
            #       proposal writer), apply it automatically right now instead of waiting for
            #       someone to come back and assign it manually.
            c = get_client(con, c["id"])
            apply_pre_implementation(con, c, "Client approval")
            con.commit()
            return {"ok": True}

        # ----- client, instead of approving, asks for changes. Sends it back to the
        #       proposal writer (their normal queue) with the client's note attached, so it
        #       can be reworked, resubmitted, re-verified, and re-delivered.
        if action == "client_request_correction_proposal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_CLIENT_REVIEW")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a note explaining what needs to change.")
            move_stage(con, c["id"], "PROPOSAL_ASSIGNED", "Client",
                       "Client asked for corrections on the proposal: " + note)
            con.commit()
            return {"ok": True}

        # ----- staff override: if the client doesn't respond, Technical TL/Manager can move
        #       the work forward without waiting on the client's own approval. Requires a
        #       reason so it's clear in Stage history that this wasn't the client acting.
        if action == "override_client_approval_proposal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_CLIENT_REVIEW")
            role = (d.get("role") or "").strip()
            if role not in ("technical_tl", "technical_manager"):
                raise ApiError("Only the Technical TL or Technical Manager can do this.")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a short reason for continuing without the client's approval.")
            actor = (d.get("actorLabel") or ("Technical TL" if role == "technical_tl" else "Technical Manager")).strip()
            move_stage(con, c["id"], "PROPOSAL_APPROVED", actor,
                       "Continued without waiting for the client's approval — " + note)
            c = get_client(con, c["id"])
            apply_pre_implementation(con, c, actor)
            con.commit()
            return {"ok": True}

        # ----- hold work: a Paper Writer/Programmer currently doing active work can pause it,
        #       give a reason, and optionally request a new deadline. Technical TL/Manager then
        #       set the new deadline to resume it. Both steps are logged in Stage history.
        if action == "request_hold":
            c = get_client(con, d.get("clientId") or "")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a reason for putting this on hold.")
            if c["on_hold"]:
                raise ApiError("This is already on hold, waiting for a new deadline.")
            active_stages = {"PROPOSAL_ASSIGNED", "IMPLEMENTATION_ASSIGNED", "PAPERWRITER_ASSIGNED", "WRITER_FIXING"}
            if c["stage"] not in active_stages:
                raise ApiError("This client isn't at a stage where work can be put on hold.")
            actor = (d.get("actorLabel") or "").strip() or "Employee"
            requested_deadline = (d.get("requestedDeadline") or "").strip() or None
            con.execute("""UPDATE clients SET on_hold=1, hold_reason=?, hold_requested_by=?, requested_deadline=?
                           WHERE id=?""", (note, actor, requested_deadline, c["id"]))
            note_text = f'Work put on hold by {actor}: "{note}".'
            if requested_deadline:
                note_text += f" Requested new deadline: {requested_deadline}."
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,'ON_HOLD',?,?)",
                        (c["id"], actor, note_text))
            con.commit()
            return {"ok": True}

        if action == "resolve_hold":
            c = get_client(con, d.get("clientId") or "")
            if not c["on_hold"]:
                raise ApiError("This client isn't currently on hold.")
            new_deadline = (d.get("newDeadline") or "").strip()
            if not new_deadline:
                raise ApiError("Pick a new deadline.")
            actor = (d.get("actorLabel") or "").strip() or "Technical TL"
            deadline_field = {
                "PROPOSAL_ASSIGNED": "proposal_deadline",
                "IMPLEMENTATION_ASSIGNED": "implementation_deadline",
                "PAPERWRITER_ASSIGNED": "writing_deadline",
                "WRITER_FIXING": "writing_deadline",
            }.get(c["stage"])
            if deadline_field:
                con.execute(f"UPDATE clients SET {deadline_field}=? WHERE id=?", (new_deadline, c["id"]))
            con.execute("""UPDATE clients SET on_hold=0, hold_reason='', hold_requested_by='', requested_deadline=NULL
                           WHERE id=?""", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,'HOLD_RESOLVED',?,?)",
                        (c["id"], actor, f"New deadline {new_deadline} set by {actor}. Work resumed."))
            con.commit()
            return {"ok": True}

        # ----- deadline extension request: unlike "hold", the employee keeps working while
        #       asking their Manager/TL for more time (e.g. "1 more day" or "half a day").
        #       Works for any active team (Technical, Journal) and also for the project
        #       deadline the Telecaller originally gave the client.
        EXT_DEADLINE_FIELD = {
            "PROPOSAL_ASSIGNED": "proposal_deadline",
            "IMPLEMENTATION_ASSIGNED": "implementation_deadline",
            "PAPERWRITER_ASSIGNED": "writing_deadline",
            "WRITER_FIXING": "writing_deadline",
            "PROOFREAD_COORD_ASSIGNED": "proposal_deadline",  # no dedicated proofreading deadline field yet
        }

        if action == "request_deadline_extension":
            c = get_client(con, d.get("clientId") or "")
            target = (d.get("target") or "").strip()
            reason = (d.get("reason") or "").strip()
            amount = (d.get("amount") or "").strip()
            actor = (d.get("actorLabel") or "").strip() or "Employee"
            if not reason:
                raise ApiError("Add a reason for the extension request.")
            if not amount:
                raise ApiError("Say how much extra time you need (e.g. '1 day' or 'half a day').")
            if c["ext_requested"]:
                raise ApiError("A deadline-extension request is already pending for this client.")
            if target == "project":
                # The overall project deadline the Telecaller/Marketing gave the client -
                # can be requested regardless of pipeline stage.
                pass
            else:
                if c["stage"] not in EXT_DEADLINE_FIELD:
                    raise ApiError("This client isn't at a stage where a deadline extension applies.")
                target = c["stage"]
            con.execute("""UPDATE clients SET ext_requested=1, ext_reason=?, ext_requested_by=?,
                           ext_amount=?, ext_target=? WHERE id=?""",
                        (reason, actor, amount, target, c["id"]))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor,
                         f'Requested a deadline extension ({amount}): "{reason}".'))
            con.commit()
            return {"ok": True}

        if action == "resolve_deadline_extension":
            c = get_client(con, d.get("clientId") or "")
            if not c["ext_requested"]:
                raise ApiError("There's no pending deadline-extension request for this client.")
            new_deadline = (d.get("newDeadline") or "").strip()
            if not new_deadline:
                raise ApiError("Pick the new deadline.")
            actor = (d.get("actorLabel") or "").strip() or "Manager"
            target = c["ext_target"] or ""
            if target == "project":
                con.execute("UPDATE clients SET deadline_date=? WHERE id=?", (new_deadline, c["id"]))
            else:
                field = EXT_DEADLINE_FIELD.get(target)
                if field:
                    con.execute(f"UPDATE clients SET {field}=? WHERE id=?", (new_deadline, c["id"]))
            con.execute("""UPDATE clients SET ext_requested=0, ext_reason='', ext_requested_by='',
                           ext_amount='', ext_target='' WHERE id=?""", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"Deadline extension approved — new deadline {new_deadline}."))
            con.commit()
            return {"ok": True}

        if action == "reject_deadline_extension":
            c = get_client(con, d.get("clientId") or "")
            if not c["ext_requested"]:
                raise ApiError("There's no pending deadline-extension request for this client.")
            actor = (d.get("actorLabel") or "").strip() or "Manager"
            con.execute("""UPDATE clients SET ext_requested=0, ext_reason='', ext_requested_by='',
                           ext_amount='', ext_target='' WHERE id=?""", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, "Deadline extension request declined."))
            con.commit()
            return {"ok": True}

        if action == "assign_programmers":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROPOSAL_APPROVED")
            deadline = d.get("deadline") or ""
            if not deadline:
                raise ApiError("Set a deadline.")
            actor = (d.get("actorLabel") or "Technical TL").strip()
            if d.get("coordinatorMode"):
                coord_name = (d.get("coordinatorName") or "").strip()
                coord_row = con.execute(
                    """SELECT id FROM employees WHERE name=? AND role='PROGRAMMER' AND is_coordinator=1
                       AND active=1 AND deleted_at IS NULL""", (coord_name,)).fetchone()
                if not coord_row:
                    raise ApiError("Unknown or inactive coordinator.")
                con.execute("""UPDATE clients SET assigned_programmers=?, implementation_deadline=?,
                               impl_coordinator=?, impl_awaiting_team_pick=1 WHERE id=?""",
                            (coord_name, deadline, coord_name, c["id"]))
                note = f"Assigned to coordinator {coord_name} — they'll build the implementation team."
            else:
                valid = active_names(con, "PROGRAMMER")
                picked = [p for p in (d.get("programmers") or []) if p in valid]
                if not picked:
                    raise ApiError("Pick at least one programmer and a deadline.")
                con.execute("""UPDATE clients SET assigned_programmers=?, implementation_deadline=?,
                               impl_coordinator='', impl_awaiting_team_pick=0 WHERE id=?""",
                            (",".join(picked), deadline, c["id"]))
                note = ""
            move_stage(con, c["id"], "IMPLEMENTATION_ASSIGNED", actor, note)
            con.commit()
            return {"ok": True}

        if action == "coordinator_take_implementation":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "IMPLEMENTATION_ASSIGNED")
            if not c["impl_awaiting_team_pick"]:
                raise ApiError("This isn't awaiting a team pick.")
            actor = (d.get("actorLabel") or c["impl_coordinator"] or "Coordinator").strip()
            con.execute("UPDATE clients SET impl_awaiting_team_pick=0 WHERE id=?", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"{actor} will do this implementation themselves."))
            con.commit()
            return {"ok": True}

        if action == "coordinator_assign_implementation_team":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "IMPLEMENTATION_ASSIGNED")
            if not c["impl_awaiting_team_pick"]:
                raise ApiError("This isn't awaiting a team pick.")
            coordinator_name = (c["impl_coordinator"] or "").strip()
            coord_row = con.execute(
                "SELECT id FROM employees WHERE name=? AND role='PROGRAMMER' AND active=1 AND deleted_at IS NULL",
                (coordinator_name,)).fetchone()
            if not coord_row:
                raise ApiError("Coordinator not found.")
            valid_team = {r["name"] for r in con.execute(
                "SELECT name FROM employees WHERE role='PROGRAMMER' AND coordinator_id=? AND active=1 AND deleted_at IS NULL",
                (coord_row["id"],))}
            picked = [p for p in (d.get("programmers") or []) if p in valid_team]
            if not picked:
                raise ApiError("Pick at least one team member.")
            actor = (d.get("actorLabel") or coordinator_name).strip()
            con.execute("UPDATE clients SET assigned_programmers=?, impl_awaiting_team_pick=0 WHERE id=?",
                        (",".join(picked), c["id"]))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"{actor} assigned the implementation team: {', '.join(picked)}."))
            con.commit()
            return {"ok": True}

        # ----- Programmer marks implementation complete (once the demo, if any, is approved).
        #       This moves it into the Technical TL/Manager's "Delivery" queue - it still needs
        #       to be delivered to the client and approved there before paper writing can be
        #       assigned (see "send_implementation_to_client" / "client_approve_implementation").
        if action == "complete_implementation":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "IMPLEMENTATION_ASSIGNED")
            if c["demo_given_date"] and not c["demo_approved_at"]:
                raise ApiError("Waiting on Technical TL/Manager to approve the demo before you can "
                                "mark implementation complete.")
            move_stage(con, c["id"], "IMPLEMENTATION_COMPLETE", c["assigned_programmers"] or "Programmer",
                       "Implementation complete — ready for Technical TL/Manager delivery to the client.")
            con.commit()
            return {"ok": True}

        # ----- Delivery step: Technical TL/Manager approves & hands the completed
        #       implementation to the client. Shows in the "Delivery" section of New Work To
        #       Assign / Task Board.
        if action == "send_implementation_to_client":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "IMPLEMENTATION_COMPLETE")
            role = (d.get("role") or "").strip()
            if role not in ("technical_tl", "technical_manager"):
                raise ApiError("Only the Technical TL or Technical Manager can deliver this to the client.")
            actor = (d.get("actorLabel") or ("Technical TL" if role == "technical_tl" else "Technical Manager")).strip()
            move_stage(con, c["id"], "IMPLEMENTATION_CLIENT_REVIEW", actor,
                       "Delivered to the client for approval.")
            con.commit()
            return {"ok": True}

        if action == "client_approve_implementation":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "IMPLEMENTATION_CLIENT_REVIEW")
            move_stage(con, c["id"], "IMPLEMENTATION_APPROVED", "Client", "Client approved the implementation.")

            # ----- if a paper writer was pre-assigned at intake (alongside the proposal writer),
            #       apply it automatically right now instead of waiting for someone to come back
            #       and assign it manually.
            c = get_client(con, c["id"])
            apply_pre_writer(con, c, "Client approval")
            con.commit()
            return {"ok": True}

        # ----- client, instead of approving, asks for changes. Sends it back to the
        #       implementation team's normal queue with the client's note attached, so it can
        #       be reworked, marked complete again, and re-delivered.
        if action == "client_request_correction_implementation":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "IMPLEMENTATION_CLIENT_REVIEW")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a note explaining what needs to change.")
            move_stage(con, c["id"], "IMPLEMENTATION_ASSIGNED", "Client",
                       "Client asked for corrections on the implementation: " + note)
            con.commit()
            return {"ok": True}

        # ----- staff override: continue without waiting for the client's approval.
        if action == "override_client_approval_implementation":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "IMPLEMENTATION_CLIENT_REVIEW")
            role = (d.get("role") or "").strip()
            if role not in ("technical_tl", "technical_manager"):
                raise ApiError("Only the Technical TL or Technical Manager can do this.")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a short reason for continuing without the client's approval.")
            actor = (d.get("actorLabel") or ("Technical TL" if role == "technical_tl" else "Technical Manager")).strip()
            move_stage(con, c["id"], "IMPLEMENTATION_APPROVED", actor,
                       "Continued without waiting for the client's approval — " + note)
            c = get_client(con, c["id"])
            apply_pre_writer(con, c, actor)
            con.commit()
            return {"ok": True}

        if action == "assign_writers":
            c = get_client(con, d.get("clientId") or "")
            conf = service_conf(c["service_key"])
            if conf["hasImplementation"]:
                require_stage(c, "IMPLEMENTATION_APPROVED")
                # Payment status (Code Implementation fee) is no longer required to move on -
                # it's tracked and shown, but doesn't block assigning paper writers.
            else:
                # No proposal/implementation stage for this service - go straight from
                # Accounts hand-off to writer assignment.
                require_stage(c, "TECH_ASSIGNED")
            deadline = d.get("deadline") or ""
            if not deadline:
                raise ApiError("Set a writing deadline.")
            actor = (d.get("actorLabel") or "Technical Manager").strip()
            if d.get("coordinatorMode"):
                coord_name = (d.get("coordinatorName") or "").strip()
                coord_row = con.execute(
                    """SELECT id FROM employees WHERE name=? AND role='PAPER_WRITER' AND is_coordinator=1
                       AND active=1 AND deleted_at IS NULL""", (coord_name,)).fetchone()
                if not coord_row:
                    raise ApiError("Unknown or inactive coordinator.")
                con.execute("""UPDATE clients SET assigned_writers=?, writing_deadline=?, coordinator_name=?,
                               writing_awaiting_team_pick=1, review_level='', coordinator_rounds=0,
                               techtl_rounds=0, techmgr_rounds=0 WHERE id=?""",
                            (coord_name, deadline, coord_name, c["id"]))
                note = f"Assigned to coordinator {coord_name} — they'll build the writing team."
            else:
                valid = active_names(con, "PAPER_WRITER")
                picked = [w for w in (d.get("writers") or []) if w in valid]
                if not picked:
                    raise ApiError("Pick at least one paper writer.")
                con.execute("""UPDATE clients SET assigned_writers=?, writing_deadline=?,
                               writing_awaiting_team_pick=0, review_level='', coordinator_rounds=0,
                               techtl_rounds=0, techmgr_rounds=0 WHERE id=?""",
                            (",".join(picked), deadline, c["id"]))
                note = ""
            move_stage(con, c["id"], "PAPERWRITER_ASSIGNED", actor, note)
            con.commit()
            return {"ok": True}

        if action == "coordinator_take_writing":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PAPERWRITER_ASSIGNED")
            if not c["writing_awaiting_team_pick"]:
                raise ApiError("This isn't awaiting a team pick.")
            actor = (d.get("actorLabel") or c["coordinator_name"] or "Coordinator").strip()
            con.execute("UPDATE clients SET writing_awaiting_team_pick=0 WHERE id=?", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"{actor} will write this themselves."))
            con.commit()
            return {"ok": True}

        if action == "coordinator_assign_writing_team":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PAPERWRITER_ASSIGNED")
            if not c["writing_awaiting_team_pick"]:
                raise ApiError("This isn't awaiting a team pick.")
            coordinator_name = (c["coordinator_name"] or "").strip()
            coord_row = con.execute(
                "SELECT id FROM employees WHERE name=? AND role='PAPER_WRITER' AND active=1 AND deleted_at IS NULL",
                (coordinator_name,)).fetchone()
            if not coord_row:
                raise ApiError("Coordinator not found.")
            valid_team = {r["name"] for r in con.execute(
                "SELECT name FROM employees WHERE role='PAPER_WRITER' AND coordinator_id=? AND active=1 AND deleted_at IS NULL",
                (coord_row["id"],))}
            picked = [w for w in (d.get("writers") or []) if w in valid_team]
            if not picked:
                raise ApiError("Pick at least one team member.")
            actor = (d.get("actorLabel") or coordinator_name).strip()
            con.execute("UPDATE clients SET assigned_writers=?, writing_awaiting_team_pick=0 WHERE id=?",
                        (",".join(picked), c["id"]))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"{actor} assigned the writing team: {', '.join(picked)}."))
            con.commit()
            return {"ok": True}

        if action == "submit_writing_demo":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PAPERWRITER_ASSIGNED")
            who = (d.get("empName") or "").strip() or (c["assigned_writers"] or "Paper Writer")
            con.execute("UPDATE clients SET demo_completed_date=? WHERE id=?",
                        (d.get("demoDate") or date.today().isoformat(), c["id"]))
            first_writer = (c["assigned_writers"] or "").split(",")[0].strip()
            coord_row = con.execute(
                """SELECT co.name AS coord_name FROM employees w
                   JOIN employees co ON co.id = w.coordinator_id
                   WHERE w.name=? AND w.role='PAPER_WRITER' AND w.active=1 AND w.deleted_at IS NULL
                     AND co.active=1 AND co.deleted_at IS NULL""", (first_writer,)).fetchone()
            note = d.get("note") or ""
            if coord_row:
                con.execute("UPDATE clients SET coordinator_name=? WHERE id=?", (coord_row["coord_name"], c["id"]))
                move_stage(con, c["id"], "COORDINATOR_REVIEW", who, note)
            else:
                con.execute("UPDATE clients SET coordinator_name='' WHERE id=?", (c["id"],))
                move_stage(con, c["id"], "TECHTL_REVIEW", who,
                           (note + " " if note else "") + "(no coordinator on this writer's team — sent straight to Technical TL)")
            con.commit()
            return {"ok": True}

        if action == "writer_resubmit":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "WRITER_FIXING")
            who = (d.get("empName") or "").strip() or (c["assigned_writers"] or "Paper Writer")
            dest = {"COORDINATOR": "COORDINATOR_REVIEW", "TECHTL": "TECHTL_REVIEW",
                    "TECHMGR": "TECHMGR_REVIEW"}.get(c["review_level"] or "", "COORDINATOR_REVIEW")
            if dest == "COORDINATOR_REVIEW" and not (c["coordinator_name"] or "").strip():
                dest = "TECHTL_REVIEW"
            move_stage(con, c["id"], dest, who, d.get("note") or "")
            con.commit()
            return {"ok": True}

        def _review_decision(client, from_stage, level, approve_stage, actor_label, round_col, subj, body):
            require_stage(client, from_stage)
            approve = bool(d.get("approve"))
            note = (d.get("note") or "").strip()
            if approve:
                move_stage(con, client["id"], approve_stage, actor_label, note)
                try_auto_email(con, client, subj, body + (("\n\nNote: " + note) if note else ""))
            else:
                if not note:
                    raise ApiError("Add a correction note for the writer before sending it back.")
                con.execute(f"UPDATE clients SET review_level=?, {round_col}={round_col}+1 WHERE id=?",
                            (level, client["id"]))
                move_stage(con, client["id"], "WRITER_FIXING", actor_label, note)
            con.commit()
            return {"ok": True}

        if action == "coordinator_decision":
            c = get_client(con, d.get("clientId") or "")
            actor_label = (d.get("actorLabel") or c["coordinator_name"] or "Coordinator").strip()
            return _review_decision(
                c, "COORDINATOR_REVIEW", "COORDINATOR", "TECHTL_REVIEW", actor_label,
                "coordinator_rounds", "iMatiz: paper ready for Technical TL review",
                f"Client {c['id']} ({c['name']}) — the coordinator approved the draft; it now needs Technical TL review.")

        if action == "techtl_decision":
            c = get_client(con, d.get("clientId") or "")
            return _review_decision(
                c, "TECHTL_REVIEW", "TECHTL", "TECHMGR_REVIEW", "Technical TL",
                "techtl_rounds", "iMatiz: paper ready for Technical Manager review",
                f"Client {c['id']} ({c['name']}) — the Technical TL approved the paper; it now needs final Technical Manager review.")

        if action == "techmgr_decision":
            c = get_client(con, d.get("clientId") or "")
            return _review_decision(
                c, "TECHMGR_REVIEW", "TECHMGR", "WRITING_COMPLETE", "Technical Manager",
                "techmgr_rounds", "iMatiz: writing approved — ready for client delivery",
                f"Client {c['id']} ({c['name']}) — writing has been fully approved internally and is ready to be sent to the client.")

       
        # ----- Accounts sign-off on the writing fee. This is still a manual step Accounts
        #       performs, but it's no longer conditional on the payment being marked paid.
        if action == "approve_writing_fee":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "WRITING_COMPLETE")
            con.execute("UPDATE clients SET writing_approved_at=to_char(now(), 'YYYY-MM-DD HH24:MI:SS') WHERE id=?",
                        (c["id"],))
            con.commit()
            return {"ok": True}

        # ----- Delivery step: Technical Manager (or Technical TL) sends the internally-approved
        #       paper to the client. Shows in the "Delivery" section of New Work To Assign /
        #       Task Board. Payment status (writing fee / paper-delivery) is tracked and shown,
        #       but doesn't block this step.
        if action == "send_to_client":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "WRITING_COMPLETE")
            actor = (d.get("actorLabel") or "Technical Manager").strip()
            move_stage(con, c["id"], "CLIENT_REVIEW", actor, "Delivered to the client for approval.")
            con.commit()
            return {"ok": True}

        if action == "client_approve_paper":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "CLIENT_REVIEW")
            con.execute("UPDATE clients SET client_approved_at=to_char(now(), 'YYYY-MM-DD HH24:MI:SS') WHERE id=?",
                        (c["id"],))
            move_stage(con, c["id"], "CLIENT_ACCEPTED", "Client", "Client approved the paper.")
            con.commit()
            return {"ok": True}

        # ----- client, instead of approving, asks for changes. Sends it back into the writing
        #       correction loop (same place a Technical Manager rejection would) with the
        #       client's note attached, so the writer can fix it, and it goes back through
        #       final Technical Manager review before being re-delivered.
        if action == "client_request_correction_paper":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "CLIENT_REVIEW")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a note explaining what needs to change.")
            con.execute("UPDATE clients SET review_level='TECHMGR', techmgr_rounds=techmgr_rounds+1 WHERE id=?",
                        (c["id"],))
            move_stage(con, c["id"], "WRITER_FIXING", "Client",
                       "Client asked for corrections on the paper: " + note)
            con.commit()
            return {"ok": True}

        # ----- staff override: continue without waiting for the client's approval.
        if action == "override_client_approval_paper":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "CLIENT_REVIEW")
            role = (d.get("role") or "").strip()
            if role not in ("technical_tl", "technical_manager"):
                raise ApiError("Only the Technical TL or Technical Manager can do this.")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a short reason for continuing without the client's approval.")
            actor = (d.get("actorLabel") or ("Technical TL" if role == "technical_tl" else "Technical Manager")).strip()
            con.execute("UPDATE clients SET client_approved_at=to_char(now(), 'YYYY-MM-DD HH24:MI:SS') WHERE id=?",
                        (c["id"],))
            move_stage(con, c["id"], "CLIENT_ACCEPTED", actor,
                       "Continued without waiting for the client's approval — " + note)
            con.commit()
            return {"ok": True}

        # ----- target journal is chosen by Technical Manager or Technical TL, not the client -
        #       but only once the client has actually approved the delivered paper
        #       (CLIENT_ACCEPTED). Writing being approved internally (WRITING_COMPLETE) or
        #       delivered and awaiting the client (CLIENT_REVIEW) isn't enough on its own.
        if action == "set_journal_name":
            c = get_client(con, d.get("clientId") or "")
            if c["stage"] != "CLIENT_ACCEPTED":
                raise ApiError("The target journal can only be set once the client has approved the paper.")
            role = (d.get("role") or "").strip()
            if role not in ("technical_manager", "technical_tl"):
                raise ApiError("Only the Technical Manager or Technical TL can set the target journal.")
            journal = (d.get("journalName") or "").strip()
            if not journal:
                raise ApiError("Enter the target journal name.")
            actor = (d.get("actorLabel") or "").strip() or ("Technical TL" if role == "technical_tl" else "Technical Manager")
            con.execute("UPDATE clients SET journal_name=? WHERE id=?", (journal, c["id"]))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"Set target journal: {journal}."))
            con.commit()
            return {"ok": True}

        # ----- extra target journals: a paper can realistically be tried at more than one
        #       journal (e.g. a backup if the first one rejects it). Technical Manager or
        #       Technical TL can add as many as they like; each is tracked with its own status.
        if action == "add_target_journal":
            c = get_client(con, d.get("clientId") or "")
            role = (d.get("role") or "").strip()
            if role not in ("technical_manager", "technical_tl"):
                raise ApiError("Only the Technical Manager or Technical TL can add a target journal.")
            name = (d.get("name") or "").strip()
            if not name:
                raise ApiError("Enter the journal name.")
            actor = (d.get("actorLabel") or "").strip() or ("Technical TL" if role == "technical_tl" else "Technical Manager")
            con.execute("INSERT INTO journal_targets (client_id, name, added_by) VALUES (?,?,?)",
                        (c["id"], name, actor))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"Added target journal: {name}."))
            con.commit()
            return {"ok": True}

        if action == "update_target_journal_status":
            item_id = d.get("id")
            status = (d.get("status") or "").strip()
            if not item_id:
                raise ApiError("Missing target journal.")
            if status not in JOURNAL_STATUSES and status != "":
                raise ApiError("Unknown journal status.")
            row = con.execute("SELECT client_id FROM journal_targets WHERE id=?", (item_id,)).fetchone()
            if not row:
                raise ApiError("That target journal no longer exists.")
            con.execute("UPDATE journal_targets SET status=? WHERE id=?", (status, item_id))
            actor = (d.get("actorLabel") or "").strip() or "Staff"
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?, (SELECT stage FROM clients WHERE id=?), ?, ?)",
                        (row["client_id"], row["client_id"], actor, f"Updated target-journal status to {status or 'pending'}."))
            con.commit()
            return {"ok": True}

        if action == "delete_target_journal":
            item_id = d.get("id")
            role = (d.get("role") or "").strip()
            if role not in ("technical_manager", "technical_tl"):
                raise ApiError("Only the Technical Manager or Technical TL can remove a target journal.")
            if not item_id:
                raise ApiError("Missing target journal.")
            con.execute("DELETE FROM journal_targets WHERE id=?", (item_id,))
            con.commit()
            return {"ok": True}

        # ----- Journal Team pipeline. Starts once writing is approved internally by the
        #       Technical TL/Manager AND delivered to and approved by the client
        #       (CLIENT_ACCEPTED). Sent by the Technical TL/Manager, with the target journal
        #       name(s).
        if action == "select_journal":
            c = get_client(con, d.get("clientId") or "")
            if c["stage"] != "CLIENT_ACCEPTED":
                raise ApiError("This client isn't ready to be sent to the Journal Team yet — "
                                "the client needs to approve the delivered paper first.")
            journal = (d.get("journalName") or c["journal_name"] or "").strip()
            if not journal:
                raise ApiError("Enter the target journal name before sending this to the Journal Team.")
            if journal != (c["journal_name"] or "").strip():
                con.execute("UPDATE clients SET journal_name=? WHERE id=?", (journal, c["id"]))
            actor = (d.get("actorLabel") or "Technical Manager").strip()
            move_stage(con, c["id"], "JOURNAL_MANAGER_REVIEW", actor)
            con.commit()
            return {"ok": True}

        if action == "assign_proofread_coordinator":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "JOURNAL_MANAGER_REVIEW")
            name = (d.get("name") or "").strip()
            if name not in active_names(con, "JOURNAL_EMPLOYEE", "PROOFREAD_COORDINATOR"):
                raise ApiError("Unknown or inactive proofreading coordinator.")
            con.execute("UPDATE clients SET proofread_coordinator=? WHERE id=?", (name, c["id"]))
            move_stage(con, c["id"], "PROOFREAD_COORD_ASSIGNED", "Journal Manager")
            con.commit()
            return {"ok": True}

        if action == "assign_proofreaders":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROOFREAD_COORD_ASSIGNED")
            valid = active_names(con, "JOURNAL_EMPLOYEE", "PROOFREADER")
            picked = [p for p in (d.get("proofreaders") or []) if p in valid]
            if not picked:
                picked = [c["proofread_coordinator"]] if c["proofread_coordinator"] else []
            if not picked:
                raise ApiError("Pick at least one proofreader, or leave blank to do it yourself.")
            con.execute("UPDATE clients SET assigned_proofreaders=? WHERE id=?",
                        (",".join(picked), c["id"]))
            move_stage(con, c["id"], "PROOFREADING", c["proofread_coordinator"] or "Proofreading Coordinator")
            con.commit()
            return {"ok": True}

        if action == "proofread_request_correction":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROOFREADING")
            note = (d.get("note") or "").strip()
            if not note:
                raise ApiError("Add a note describing what the writer needs to fix.")
            con.execute("UPDATE clients SET proofread_rounds=proofread_rounds+1 WHERE id=?", (c["id"],))
            move_stage(con, c["id"], "PROOFREAD_CORRECTION",
                       c["proofread_coordinator"] or "Proofreading Coordinator", note)
            con.commit()
            return {"ok": True}

        if action == "writer_resubmit_proofread":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROOFREAD_CORRECTION")
            who = (d.get("empName") or "").strip() or (c["assigned_writers"] or "Paper Writer")
            move_stage(con, c["id"], "PROOFREAD_RECHECK", who, d.get("note") or "")
            con.commit()
            return {"ok": True}

        if action == "proofread_decision":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "PROOFREAD_RECHECK")
            note = (d.get("note") or "").strip()
            if bool(d.get("approve")):
                move_stage(con, c["id"], "JOURNAL_MANAGER_FORMATTING",
                           c["proofread_coordinator"] or "Proofreading Coordinator", note)
            else:
                if not note:
                    raise ApiError("Add a correction note for the writer before sending it back.")
                con.execute("UPDATE clients SET proofread_rounds=proofread_rounds+1 WHERE id=?", (c["id"],))
                move_stage(con, c["id"], "PROOFREAD_CORRECTION",
                           c["proofread_coordinator"] or "Proofreading Coordinator", note)
            con.commit()
            return {"ok": True}

        if action == "assign_format_coordinator":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "JOURNAL_MANAGER_FORMATTING")
            name = (d.get("name") or "").strip()
            if name not in active_names(con, "JOURNAL_EMPLOYEE", "FORMAT_COORDINATOR"):
                raise ApiError("Unknown or inactive formatting coordinator.")
            con.execute("UPDATE clients SET format_coordinator=? WHERE id=?", (name, c["id"]))
            move_stage(con, c["id"], "FORMATTING_ASSIGNED", "Journal Manager")
            con.commit()
            return {"ok": True}

        if action == "assign_formatters":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "FORMATTING_ASSIGNED")
            valid = active_names(con, "JOURNAL_EMPLOYEE", "FORMATTER")
            picked = [p for p in (d.get("formatters") or []) if p in valid]
            if not picked:
                picked = [c["format_coordinator"]] if c["format_coordinator"] else []
            if not picked:
                raise ApiError("Pick at least one formatter, or leave blank to do it yourself.")
            con.execute("UPDATE clients SET assigned_formatters=? WHERE id=?", (",".join(picked), c["id"]))
            move_stage(con, c["id"], "FORMATTING_IN_PROGRESS", c["format_coordinator"] or "Formatting Coordinator")
            con.commit()
            return {"ok": True}

        if action == "complete_formatting":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "FORMATTING_IN_PROGRESS")
            move_stage(con, c["id"], "SUBMISSION", c["assigned_formatters"] or "Formatting team")
            con.commit()
            return {"ok": True}

        if action == "format_decision":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "FORMATTING_IN_PROGRESS")
            note = (d.get("note") or "").strip()
            actorLabel = (d.get("actorLabel") or "").strip() or c["format_coordinator"] or "Formatting Coordinator"
            if bool(d.get("approve")):
                move_stage(con, c["id"], "FORMATTING_MANAGER_REVIEW", actorLabel, note)
            else:
                if not note:
                    raise ApiError("Add a correction note for the formatting team before sending it back.")
                con.execute("UPDATE clients SET format_rounds=format_rounds+1 WHERE id=?", (c["id"],))
                move_stage(con, c["id"], "FORMATTING_IN_PROGRESS", actorLabel, note)
            con.commit()
            return {"ok": True}

        if action == "format_manager_decision":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "FORMATTING_MANAGER_REVIEW")
            note = (d.get("note") or "").strip()
            if bool(d.get("approve")):
                move_stage(con, c["id"], "SUBMISSION", "Journal Manager", note)
            else:
                if not note:
                    raise ApiError("Add a correction note before sending it back to the formatting team.")
                con.execute("UPDATE clients SET format_rounds=format_rounds+1 WHERE id=?", (c["id"],))
                move_stage(con, c["id"], "FORMATTING_IN_PROGRESS", "Journal Manager", note)
            con.commit()
            return {"ok": True}

        if action == "submit_to_journal":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "SUBMISSION")
            who = (d.get("empName") or "").strip() or "Submission Team"
            con.execute("UPDATE clients SET submission_person=?, journal_status='SUBMITTED' WHERE id=?",
                        (who, c["id"]))
            move_stage(con, c["id"], "JOURNAL_SUBMITTED", who)
            con.commit()
            return {"ok": True}

        if action == "update_journal_status":
            c = get_client(con, d.get("clientId") or "")
            require_stage(c, "JOURNAL_SUBMITTED")
            status = (d.get("status") or "").strip().upper()
            if status not in JOURNAL_STATUSES:
                raise ApiError("Unknown journal status.")
            con.execute("UPDATE clients SET journal_status=? WHERE id=?", (status, c["id"]))
            if status in ("ACCEPTED", "PUBLISHED"):
                move_stage(con, c["id"], "COMPLETED", "Submission Team", f"Journal status: {status}")
            else:
                con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                            (c["id"], c["stage"], "Submission Team", f"Journal status: {status}"))
            con.commit()
            return {"ok": True}

        # ----- team roster
        if action == "employee_create":
            actor_role = (d.get("role") or "").strip()
            if actor_role not in STAFF_MGMT_ROLES:
                raise ApiError("You don't have permission to add team members.")
            name = (d.get("name") or "").strip()
            role = d.get("empRole") or ""
            team_type = (d.get("teamType") or "").strip().upper()
            email = (d.get("email") or "").strip()
            # SECURITY: no shared default. If the manager leaves the field blank a
            # random one-time password is generated and shown to them once.
            password = (d.get("password") or "").strip()
            generated_password = ""
            if not password:
                password = secrets.token_urlsafe(9)
                generated_password = password
            elif len(password) < MIN_PASSWORD_LENGTH:
                raise ApiError("The password must be at least %d characters." % MIN_PASSWORD_LENGTH)
            joining_date = (d.get("joiningDate") or "").strip()
            date_of_birth = (d.get("dateOfBirth") or "").strip()
            manual_uid = (d.get("empUid") or "").strip()
            branch = (d.get("branch") or "").strip()
            department = (d.get("department") or "").strip()
            phone = (d.get("phone") or "").strip()
            designation = (d.get("designation") or "").strip()
            if not name:
                raise ApiError("Name is required.")
            if role not in ("PROGRAMMER", "PAPER_WRITER", "JOURNAL_EMPLOYEE", "TELECALLER"):
                raise ApiError("Unknown team role.")
            if role == "JOURNAL_EMPLOYEE" and team_type not in (
                    "PROOFREAD_COORDINATOR", "PROOFREADER", "FORMAT_COORDINATOR", "FORMATTER", "SUBMISSION"):
                raise ApiError("Pick a journal team type (proofreading, formatting, or submission).")
            if role != "JOURNAL_EMPLOYEE":
                team_type = ""
            dup = con.execute("SELECT id FROM employees WHERE LOWER(name)=LOWER(?) AND active=1 AND deleted_at IS NULL",
                              (name,)).fetchone()
            if dup:
                raise ApiError(f"{name} is already on the team.")

            is_coordinator = 0
            coordinator_id = None
            if role in ("PROGRAMMER", "PAPER_WRITER"):
                is_coordinator = 1 if d.get("isCoordinator") else 0
                if not is_coordinator:
                    raw_cid = d.get("coordinatorId")
                    if raw_cid not in (None, "", 0, "0"):
                        coord_row = con.execute(
                            "SELECT id FROM employees WHERE id=? AND role=? AND is_coordinator=1 AND active=1 AND deleted_at IS NULL",
                            (raw_cid, role)).fetchone()
                        if not coord_row:
                            raise ApiError("Pick a valid coordinator for this role, or leave it blank.")
                        coordinator_id = coord_row["id"]

            if manual_uid:
                dup_uid = con.execute("SELECT id FROM employees WHERE UPPER(emp_uid)=UPPER(?)", (manual_uid,)).fetchone()
                if dup_uid:
                    raise ApiError(f"Employee ID '{manual_uid}' is already in use. Pick a different one.")
                uid = manual_uid
            else:
                n = 1001
                for r in con.execute("SELECT emp_uid FROM employees WHERE emp_uid IS NOT NULL AND emp_uid<>''"):
                    m = re.match(r"^EMP-(\d+)$", r["emp_uid"] or "")
                    if m:
                        n = max(n, int(m.group(1)) + 1)
                uid = f"EMP-{n}"
            con.execute("""INSERT INTO employees
                           (name, role, team_type, email, emp_uid, password, is_coordinator, coordinator_id,
                            joining_date, date_of_birth, branch, department, phone, designation)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (name, role, team_type, email, uid, hash_password(password), is_coordinator, coordinator_id,
                         joining_date, date_of_birth, branch, department, phone, designation))
            con.commit()
            # The plain-text password is returned exactly once, at creation time, so it can be
            # shown/shared with the new team member — it is never stored or retrievable again.
            return {"ok": True, "empUid": uid, "password": password,
                    "generatedPassword": bool(generated_password)}

        if action == "employee_update":
            if (d.get("role") or "").strip() not in STAFF_MGMT_ROLES:
                raise ApiError("You don't have permission to edit team members.")
            emp_id = d.get("empId")
            e = con.execute("SELECT * FROM employees WHERE id=? AND deleted_at IS NULL", (emp_id,)).fetchone()
            if not e:
                raise ApiError("Employee not found.")
            col_map = {"name": "name", "email": "email", "branch": "branch", "department": "department",
                       "phone": "phone", "designation": "designation", "joiningDate": "joining_date",
                       "dateOfBirth": "date_of_birth"}
            fields, vals = [], []
            for key, col in col_map.items():
                if key in d:
                    fields.append(f"{col}=?"); vals.append((d.get(key) or "").strip())
            if "name" in d and not (d.get("name") or "").strip():
                raise ApiError("Name cannot be empty.")
            if not fields:
                raise ApiError("Nothing to update.")
            vals.append(emp_id)
            con.execute(f"UPDATE employees SET {', '.join(fields)} WHERE id=?", vals)
            con.commit()
            return {"ok": True}

        if action == "employee_update_team":
            if (d.get("role") or "").strip() not in STAFF_MGMT_ROLES:
                raise ApiError("You don't have permission to edit team members.")
            emp_id = d.get("empId")
            e = con.execute("SELECT * FROM employees WHERE id=? AND deleted_at IS NULL", (emp_id,)).fetchone()
            if not e:
                raise ApiError("Employee not found.")
            if e["role"] not in ("PROGRAMMER", "PAPER_WRITER"):
                raise ApiError("Only Paper Writers and Programmers have a coordinator team.")
            is_coordinator = 1 if d.get("isCoordinator") else 0
            coordinator_id = None
            if not is_coordinator:
                raw_cid = d.get("coordinatorId")
                if raw_cid not in (None, "", 0, "0"):
                    if int(raw_cid) == int(emp_id):
                        raise ApiError("An employee can't report to themselves.")
                    coord_row = con.execute(
                        "SELECT id FROM employees WHERE id=? AND role=? AND is_coordinator=1 AND active=1 AND deleted_at IS NULL",
                        (raw_cid, e["role"])).fetchone()
                    if not coord_row:
                        raise ApiError("Pick a valid coordinator for this role, or leave it blank.")
                    coordinator_id = coord_row["id"]
            con.execute("UPDATE employees SET is_coordinator=?, coordinator_id=? WHERE id=?",
                        (is_coordinator, coordinator_id, emp_id))
            con.commit()
            return {"ok": True}

        if action == "employee_delete":
            if (d.get("role") or "").strip() not in STAFF_MGMT_ROLES:
                raise ApiError("You don't have permission to remove team members.")
            emp_id = d.get("empId")
            e = con.execute("SELECT * FROM employees WHERE id=? AND deleted_at IS NULL", (emp_id,)).fetchone()
            if not e:
                raise ApiError("Employee not found.")
            con.execute("UPDATE employees SET deleted_at=to_char(now(), 'YYYY-MM-DD HH24:MI:SS') WHERE id=?", (emp_id,))
            # anyone reporting to a deleted coordinator becomes independent, rather than orphaned
            con.execute("UPDATE employees SET coordinator_id=NULL WHERE coordinator_id=?", (emp_id,))
            con.commit()
            return {"ok": True}

        if action == "employee_restore":
            if (d.get("role") or "").strip() not in STAFF_MGMT_ROLES:
                raise ApiError("You don't have permission to restore team members.")
            emp_id = d.get("empId")
            e = con.execute("SELECT * FROM employees WHERE id=? AND deleted_at IS NOT NULL", (emp_id,)).fetchone()
            if not e:
                raise ApiError("Employee not found in the deleted list.")
            con.execute("UPDATE employees SET deleted_at=NULL WHERE id=?", (emp_id,))
            con.commit()
            return {"ok": True}

        # ----- Super Admin / MD Admin access-control directory: every role login + every
        #       employee, including inactive ones. SECURITY: plaintext passwords are no
        #       longer stored, so they can no longer be "revealed" here — only reset
        #       (see openChangePasswordAdmin on the front end).
        if action == "admin_directory":
            if (d.get("role") or "").strip() not in ADMIN_ROLES:
                raise ApiError("Only the Super Admin / MD Admin can view the access-control directory.")
            users_list = [{"role": r["role"], "label": r["display_name"],
                           "enabled": bool(r["enabled"])}
                          for r in con.execute("SELECT * FROM users WHERE role<>'employee' ORDER BY role")]
            emps_list = [{"id": r["id"], "name": r["name"], "role": r["role"], "teamType": r["team_type"] or "",
                         "empUid": r["emp_uid"] or "", "email": r["email"] or "",
                         "active": bool(r["active"]), "branch": r["branch"] or "", "department": r["department"] or "",
                         "phone": r["phone"] or "", "designation": r["designation"] or "",
                         "joiningDate": r["joining_date"] or ""}
                        for r in con.execute("SELECT * FROM employees ORDER BY role, team_type, name")]
            return {"users": users_list, "employees": emps_list}

        if action == "list_deleted_employees":
            if (d.get("role") or "").strip() not in STAFF_MGMT_ROLES:
                raise ApiError("You don't have permission to view deleted employees.")
            return {"deletedEmployees": deleted_employees(con)}

        if action == "set_role_access":
            if (d.get("role") or "").strip() not in ADMIN_ROLES:
                raise ApiError("Only the Super Admin / MD Admin can enable/disable a login.")
            role_key = (d.get("targetRole") or "").strip()
            row = con.execute("SELECT role FROM users WHERE role=?", (role_key,)).fetchone()
            if not row:
                raise ApiError("Unknown role.")
            if role_key == "super_admin":
                raise ApiError("The Super Admin role cannot be disabled.")
            con.execute("UPDATE users SET enabled=? WHERE role=?", (1 if d.get("enabled") else 0, role_key))
            con.commit()
            return {"ok": True}

        if action == "set_employee_active":
            if (d.get("role") or "").strip() not in ADMIN_ROLES:
                raise ApiError("Only the Super Admin / MD Admin can revoke/restore employee access.")
            emp_id = d.get("empId")
            row = con.execute("SELECT id FROM employees WHERE id=?", (emp_id,)).fetchone()
            if not row:
                raise ApiError("Unknown employee.")
            con.execute("UPDATE employees SET active=? WHERE id=?", (1 if d.get("active") else 0, emp_id))
            con.commit()
            return {"ok": True}

        if action == "change_password":
            # SECURITY: this is a *self-service* action only. An individual employee session
            # may only change its own password (empId is forced to the caller's own id by the
            # session layer, and must match here); a department/shared-login session may only
            # change its own shared role's password (role is likewise forced by the session
            # layer). Admins use the dedicated employee_reset_password / admin_change_password
            # / admin_reset_client_password actions instead, which carry their own admin-only
            # permission checks.
            new_pwd = (d.get("newPassword") or "").strip()
            if len(new_pwd) < MIN_PASSWORD_LENGTH:
                raise ApiError("Choose a password at least %d characters long." % MIN_PASSWORD_LENGTH)
            emp_id = d.get("empId")
            actor_role = (d.get("role") or "").strip()
            if emp_id:
                if actor_role != "employee":
                    raise ApiError("You can only change your own password.")
                row = con.execute("SELECT id FROM employees WHERE id=?", (emp_id,)).fetchone()
                if not row:
                    raise ApiError("Unknown employee.")
                con.execute("UPDATE employees SET password=? WHERE id=?", (hash_password(new_pwd), emp_id))
            else:
                if actor_role == "employee":
                    raise ApiError("Log in as yourself (Employee Login) to change your own password.")
                row = con.execute("SELECT role FROM users WHERE role=?", (actor_role,)).fetchone()
                if not row:
                    raise ApiError("Unknown role.")
                con.execute("UPDATE users SET password=? WHERE role=?", (hash_password(new_pwd), actor_role))
            con.commit()
            return {"ok": True}

        if action == "employee_reset_password":
            if (d.get("role") or "").strip() not in ADMIN_ROLES:
                raise ApiError("Only the Super Admin / MD Admin can reset another employee's password.")
            eid = int(d.get("id") or 0)
            newpwd = (d.get("password") or "").strip()
            if len(newpwd) < MIN_PASSWORD_LENGTH:
                raise ApiError("Choose a password at least %d characters long." % MIN_PASSWORD_LENGTH)
            e = con.execute("SELECT id FROM employees WHERE id=? AND active=1", (eid,)).fetchone()
            if not e:
                raise ApiError("Employee not found.")
            con.execute("UPDATE employees SET password=? WHERE id=?", (hash_password(newpwd), eid))
            con.commit()
            return {"ok": True}

        # ----- Super Admin / MD Admin (Team & Access screen): set ANY department login's or
        #       ANY employee's password directly, as opposed to "change_password" above which
        #       is self-service only. Uses distinct field names (targetRole/empId) so they are
        #       never confused with the caller's own identity.
        if action == "admin_change_password":
            if (d.get("role") or "").strip() not in ADMIN_ROLES:
                raise ApiError("Only the Super Admin / MD Admin can set another login's password.")
            new_pwd = (d.get("newPassword") or "").strip()
            if len(new_pwd) < MIN_PASSWORD_LENGTH:
                raise ApiError("Choose a password at least %d characters long." % MIN_PASSWORD_LENGTH)
            emp_id = d.get("empId")
            if emp_id:
                row = con.execute("SELECT id FROM employees WHERE id=?", (emp_id,)).fetchone()
                if not row:
                    raise ApiError("Unknown employee.")
                con.execute("UPDATE employees SET password=? WHERE id=?", (hash_password(new_pwd), emp_id))
            else:
                target_role = (d.get("targetRole") or "").strip()
                row = con.execute("SELECT role FROM users WHERE role=?", (target_role,)).fetchone()
                if not row:
                    raise ApiError("Unknown role.")
                con.execute("UPDATE users SET password=? WHERE role=?", (hash_password(new_pwd), target_role))
            con.commit()
            return {"ok": True}

        # ----- employee work-update timeline (code delivered / paper delivered)
        if action == "add_work_update":
            c = get_client(con, d.get("clientId") or "")
            milestone = d.get("milestone") or ""
            note = (d.get("note") or "").strip()
            emp_name = (d.get("empName") or "").strip()
            valid = {"CODE_DELIVERED", "PAPER_DELIVERED", "PROGRESS_NOTE"}
            if milestone not in valid:
                raise ApiError("Unknown update type.")
            if not emp_name:
                raise ApiError("Missing employee name.")
            if milestone == "CODE_DELIVERED":
                if emp_name not in names(c["assigned_programmers"]):
                    raise ApiError("You are not assigned as a programmer on this client.")
            elif milestone == "PAPER_DELIVERED":
                if emp_name not in names(c["assigned_writers"]):
                    raise ApiError("You are not assigned as a paper writer on this client.")
            con.execute("INSERT INTO work_updates (client_id, emp_name, milestone, note) VALUES (?,?,?,?)",
                        (c["id"], emp_name, milestone, note))
            con.commit()
            return {"ok": True}

        # ----- demo given: date + whether the client was satisfied with it. Technical TL must
        #       approve the demo before implementation can be marked complete and sent on to
        #       the client for the code-delivery approval step.
        if action == "mark_demo_given":
            c = get_client(con, d.get("clientId") or "")
            emp_name = (d.get("empName") or "").strip()
            if emp_name not in names(c["assigned_programmers"]):
                raise ApiError("You are not assigned as a programmer on this client.")
            demo_date = d.get("date") or date.today().isoformat()
            satisfied = (d.get("satisfied") or "").strip()
            if satisfied not in ("satisfied", "not_satisfied"):
                raise ApiError("Say whether the client was satisfied with the demo or not.")
            con.execute("""UPDATE clients SET demo_given_date=?, demo_satisfied=?,
                           demo_approved_at=NULL, demo_approved_by='' WHERE id=?""",
                        (demo_date, satisfied, c["id"]))
            if (c["demo_scheduled_type"] or "") == "code":
                con.execute("""UPDATE clients SET demo_scheduled_type='', demo_scheduled_date='',
                               demo_scheduled_time='', demo_scheduled_note='', demo_scheduled_emp='',
                               demo_scheduled_by='', demo_schedule_status='' WHERE id=?""", (c["id"],))
            con.commit()
            return {"ok": True}

        if action == "approve_demo":
            c = get_client(con, d.get("clientId") or "")
            if not c["demo_given_date"]:
                raise ApiError("No demo has been marked as given yet.")
            role = (d.get("role") or "").strip()
            if role not in ("technical_tl", "technical_manager"):
                raise ApiError("Only the Technical TL or Technical Manager can approve the demo.")
            actor = (d.get("actorLabel") or ("Technical TL" if role == "technical_tl" else "Technical Manager")).strip()
            con.execute("UPDATE clients SET demo_approved_at=to_char(now(), 'YYYY-MM-DD HH24:MI:SS'), demo_approved_by=? WHERE id=?",
                        (actor, c["id"]))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor,
                         f"Approved the demo ({'satisfied' if c['demo_satisfied']=='satisfied' else 'not satisfied'})."))
            con.commit()
            return {"ok": True}

        # ----- demo scheduling: Marketing TL/Manager schedule an upcoming paper or code demo.
        #       Shows up for Technical Manager/TL and on the calendar/dashboard of whichever
        #       employee (Programmer for a code demo, Paper Writer for a paper demo) is
        #       currently assigned to that side of the client's work.
        if action == "schedule_demo":
            c = get_client(con, d.get("clientId") or "")
            actor_role = (d.get("role") or "").strip()
            if actor_role not in ("marketing_tl", "marketing_manager", "super_admin", "md_admin"):
                raise ApiError("Only the Marketing TL or Marketing Manager can schedule a demo.")
            demo_type = (d.get("demoType") or "").strip().lower()
            if demo_type not in ("code", "paper"):
                raise ApiError("Say whether this is a paper demo or a code demo.")
            demo_date = (d.get("demoDate") or "").strip()
            if not demo_date:
                raise ApiError("Pick a date for the demo.")
            demo_time = (d.get("demoTime") or "").strip()
            note = (d.get("note") or "").strip()
            # Whoever it's assigned to can be picked explicitly; otherwise default to whoever
            # is currently doing that side of the client's work.
            emp_name = (d.get("empName") or "").strip()
            if not emp_name:
                pool = names(c["assigned_programmers"]) if demo_type == "code" else names(c["assigned_writers"])
                emp_name = pool[0] if pool else ""
            actor = (d.get("actorLabel") or
                     ("Marketing TL" if actor_role == "marketing_tl" else "Marketing Manager")).strip()
            con.execute("""UPDATE clients SET demo_scheduled_type=?, demo_scheduled_date=?, demo_scheduled_time=?,
                           demo_scheduled_note=?, demo_scheduled_emp=?, demo_scheduled_by=?,
                           demo_schedule_status='SCHEDULED' WHERE id=?""",
                        (demo_type, demo_date, demo_time, note, emp_name, actor, c["id"]))
            label = "Code demo" if demo_type == "code" else "Paper demo"
            when = demo_date + (f" at {demo_time}" if demo_time else "")
            who_note = f" — assigned to {emp_name}" if emp_name else " — no one assigned to this side of the work yet"
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor,
                         f"Scheduled a {label.lower()} for {when}{who_note}." + (f" Note: {note}" if note else "")))
            con.commit()
            return {"ok": True}

        if action == "cancel_demo_schedule":
            c = get_client(con, d.get("clientId") or "")
            actor_role = (d.get("role") or "").strip()
            if actor_role not in ("marketing_tl", "marketing_manager", "technical_tl", "technical_manager",
                                   "super_admin", "md_admin"):
                raise ApiError("You don't have permission to cancel this demo schedule.")
            if not c["demo_scheduled_date"]:
                raise ApiError("No demo is currently scheduled for this client.")
            actor = (d.get("actorLabel") or actor_role).strip()
            label = "Code demo" if c["demo_scheduled_type"] == "code" else "Paper demo"
            old_when = c["demo_scheduled_date"] + (f" at {c['demo_scheduled_time']}" if c["demo_scheduled_time"] else "")
            con.execute("""UPDATE clients SET demo_scheduled_type='', demo_scheduled_date='', demo_scheduled_time='',
                           demo_scheduled_note='', demo_scheduled_emp='', demo_scheduled_by='',
                           demo_schedule_status='' WHERE id=?""", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor, f"Cancelled the scheduled {label.lower()} ({old_when})."))
            con.commit()
            return {"ok": True}

        # ----- postpone: the employee actually giving the demo (Programmer for code, Paper
        #       Writer for paper) can push it to a new date/time with a reason, without losing
        #       the schedule entirely. Admins can also do this on their behalf.
        if action == "postpone_demo_schedule":
            c = get_client(con, d.get("clientId") or "")
            actor_role = (d.get("role") or "").strip()
            emp_name = (d.get("empName") or "").strip()
            is_assigned_emp = actor_role == "employee" and emp_name and emp_name == (c["demo_scheduled_emp"] or "")
            if not (is_assigned_emp or actor_role in ("super_admin", "md_admin",
                                                        "marketing_tl", "marketing_manager",
                                                        "technical_tl", "technical_manager")):
                raise ApiError("You don't have permission to postpone this demo.")
            if not c["demo_scheduled_date"] or (c["demo_schedule_status"] or "") != "SCHEDULED":
                raise ApiError("No demo is currently scheduled for this client.")
            new_date = (d.get("newDate") or "").strip()
            if not new_date:
                raise ApiError("Pick a new date for the demo.")
            new_time = (d.get("newTime") or "").strip()
            reason = (d.get("note") or "").strip()
            actor = (d.get("actorLabel") or emp_name or actor_role).strip()
            label = "Code demo" if c["demo_scheduled_type"] == "code" else "Paper demo"
            old_when = c["demo_scheduled_date"] + (f" at {c['demo_scheduled_time']}" if c["demo_scheduled_time"] else "")
            new_when = new_date + (f" at {new_time}" if new_time else "")
            con.execute("""UPDATE clients SET demo_scheduled_date=?, demo_scheduled_time=?, demo_scheduled_note=?
                           WHERE id=?""", (new_date, new_time, reason, c["id"]))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], actor,
                         f"Postponed the {label.lower()} from {old_when} to {new_when}." + (f" Reason: {reason}" if reason else "")))
            con.commit()
            return {"ok": True}

        # ----- completed: the employee giving the demo marks it done, with a note. This
        #       records the underlying "demo given" the same way the older Mark Demo
        #       Given/Mark Paper Demo Given flows do (so downstream approval logic keeps
        #       working), then clears the schedule.
        if action == "complete_demo_schedule":
            c = get_client(con, d.get("clientId") or "")
            actor_role = (d.get("role") or "").strip()
            emp_name = (d.get("empName") or "").strip()
            is_assigned_emp = actor_role == "employee" and emp_name and emp_name == (c["demo_scheduled_emp"] or "")
            if not (is_assigned_emp or actor_role in ("super_admin", "md_admin")):
                raise ApiError("Only the employee this demo was scheduled for can mark it completed.")
            if not c["demo_scheduled_date"] or (c["demo_schedule_status"] or "") != "SCHEDULED":
                raise ApiError("No demo is currently scheduled for this client.")
            demo_type = c["demo_scheduled_type"] or "code"
            note = (d.get("note") or "").strip()
            done_date = d.get("date") or date.today().isoformat()
            label = "Code demo" if demo_type == "code" else "Paper demo"
            if demo_type == "code":
                satisfied = (d.get("satisfied") or "satisfied").strip()
                if satisfied not in ("satisfied", "not_satisfied"):
                    satisfied = "satisfied"
                con.execute("""UPDATE clients SET demo_given_date=?, demo_satisfied=?,
                               demo_approved_at=NULL, demo_approved_by='' WHERE id=?""",
                            (done_date, satisfied, c["id"]))
            else:
                con.execute("UPDATE clients SET writing_demo_given_date=? WHERE id=?", (done_date, c["id"]))
            con.execute("""UPDATE clients SET demo_scheduled_type='', demo_scheduled_date='',
                           demo_scheduled_time='', demo_scheduled_note='', demo_scheduled_emp='',
                           demo_scheduled_by='', demo_schedule_status='' WHERE id=?""", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], emp_name or actor_role,
                         f"Marked the {label.lower()} completed ({done_date})." + (f" Note: {note}" if note else "")))
            con.commit()
            return {"ok": True}

        # ----- paper demo given: mirrors mark_demo_given above, but for the Paper Writer side.
        #       Just a date, no separate approval step (unlike the code demo, which needs
        #       Technical TL/Manager sign-off before implementation can be marked complete).
        if action == "mark_writing_demo_given":
            c = get_client(con, d.get("clientId") or "")
            emp_name = (d.get("empName") or "").strip()
            if emp_name not in names(c["assigned_writers"]):
                raise ApiError("You are not assigned as a paper writer on this client.")
            demo_date = d.get("date") or date.today().isoformat()
            con.execute("UPDATE clients SET writing_demo_given_date=? WHERE id=?", (demo_date, c["id"]))
            if (c["demo_scheduled_type"] or "") == "paper":
                con.execute("""UPDATE clients SET demo_scheduled_type='', demo_scheduled_date='',
                               demo_scheduled_time='', demo_scheduled_note='', demo_scheduled_emp='',
                               demo_scheduled_by='', demo_schedule_status='' WHERE id=?""", (c["id"],))
            con.execute("INSERT INTO history (client_id, stage, actor, note) VALUES (?,?,?,?)",
                        (c["id"], c["stage"], emp_name, f"Marked the paper demo as given ({demo_date})."))
            con.commit()
            return {"ok": True}

        # ----- client <-> staff chat -----
        if action == "chat_typing":
            c = get_client(con, d.get("clientId") or "")
            thread_with = (d.get("threadWith") or "").strip()
            sender_type = d.get("senderType") or ""
            if not thread_with or sender_type not in ("client", "staff"):
                raise ApiError("Missing chat info.")
            _typing_touch(_TYPING_CHAT, (c["id"], thread_with, sender_type))
            return {"ok": True}

        if action == "send_message":
            c = get_client(con, d.get("clientId") or "")
            thread_with = (d.get("threadWith") or "").strip()
            sender_type = d.get("senderType") or ""
            sender_name = (d.get("senderName") or "").strip()
            body = (d.get("body") or "").strip()
            file_name = sanitize_upload_filename(d.get("fileName"))
            file_type = sanitize_upload_filetype(d.get("fileType"))
            file_data = d.get("fileData") or ""
            if not thread_with:
                raise ApiError("Missing chat recipient.")
            if sender_type not in ("client", "staff"):
                raise ApiError("Unknown sender.")
            if not sender_name:
                raise ApiError("Missing sender name.")
            if not body and not file_name:
                raise ApiError("Type a message or attach a file.")
            if file_data and len(file_data) > 7_000_000:
                raise ApiError("That file is too large (max ~5MB).")
            read_by_client = 1 if sender_type == "client" else 0
            read_by_staff = 1 if sender_type == "staff" else 0
            con.execute("""INSERT INTO messages
                           (client_id, thread_with, sender_type, sender_name, body, file_name, file_type,
                            file_data, read_by_client, read_by_staff)
                           VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (c["id"], thread_with, sender_type, sender_name, body, file_name, file_type,
                         file_data, read_by_client, read_by_staff))
            con.commit()
            return {"ok": True}

        if action == "get_thread":
            c = get_client(con, d.get("clientId") or "")
            thread_with = (d.get("threadWith") or "").strip()
            viewer = d.get("viewer") or ""
            viewer_key = (d.get("viewerKey") or "").strip()
            if viewer not in ("client", "staff"):
                raise ApiError("Unknown viewer.")
            if not thread_with:
                raise ApiError("Missing chat recipient.")
            rows = con.execute(
                """SELECT * FROM messages WHERE client_id=? AND thread_with=?
                   ORDER BY created_at ASC, id ASC""", (c["id"], thread_with)).fetchall()
            if viewer == "client":
                con.execute("UPDATE messages SET read_by_client=1 WHERE client_id=? AND thread_with=? AND read_by_client=0",
                            (c["id"], thread_with))
            else:
                # Each staff viewer (the assigned employee, plus any Manager/TL/Coordinator with
                # oversight access) has their own independent read state for this thread - one
                # person opening it does NOT mark it read for anyone else's dashboard.
                if not viewer_key:
                    raise ApiError("Missing viewer identity.")
                max_id = con.execute(
                    "SELECT COALESCE(MAX(id),0) m FROM messages WHERE client_id=? AND thread_with=?",
                    (c["id"], thread_with)).fetchone()["m"]
                con.execute("""INSERT INTO thread_reads (client_id, thread_with, viewer_key, last_read_id)
                               VALUES (?,?,?,?)
                               ON CONFLICT(client_id, thread_with, viewer_key)
                               DO UPDATE SET last_read_id=excluded.last_read_id""",
                            (c["id"], thread_with, viewer_key, max_id))
            con.commit()
            other_side = "staff" if viewer == "client" else "client"
            other_typing = _typing_is_active(_TYPING_CHAT, (c["id"], thread_with, other_side))
            return {"otherTyping": other_typing, "messages": [{
                "id": r["id"], "senderType": r["sender_type"], "senderName": r["sender_name"],
                "body": r["body"] or "", "fileName": r["file_name"] or "", "fileType": r["file_type"] or "",
                "fileData": r["file_data"] or "", "at": iso(r["created_at"]),
            } for r in rows]}

        if action == "send_email":
            # SECURITY: this used to accept any recipient, subject and body from any
            # caller and relay it through the company Gmail account — an open relay.
            # It is now admin/marketing-management only (see ACTION_ROLES), validated,
            # header-injection-safe and rate limited.
            if _rate_limited(ip, "send_email", limit=40, window_seconds=3600):
                raise ApiError("Too many emails sent recently. Please try again later.")
            to = (d.get("to") or "").strip() or get_settings(con)["toEmail"]
            subject = (d.get("subject") or "iMatiz Pipeline update")
            body = d.get("body") or ""
            if not to:
                raise ApiError("No 'To' email is set. Add one in Email settings first.")
            if not EMAIL_RE.match(to):
                raise ApiError("That doesn't look like a valid email address.")
            # Strip CR/LF so a crafted subject cannot inject extra SMTP headers
            # (Bcc:, Content-Type:, ...) into the outgoing message.
            subject = re.sub(r"[\r\n]+", " ", str(subject))[:200]
            body = str(body)[:20000]
            pwd = GMAIL_APP_PASSWORD.replace(" ", "")
            if not pwd or not GMAIL_USER:
                raise ApiError("Email sending isn't configured. Set MAIL/GMAIL credentials in "
                               "the server's environment (.env), then restart. See README.txt.")
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = GMAIL_USER
            msg["To"] = to
            try:
                with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
                    smtp.login(GMAIL_USER, pwd)
                    smtp.sendmail(GMAIL_USER, [to], msg.as_string())
            except smtplib.SMTPAuthenticationError:
                raise ApiError("The mail account rejected the login. Check the app password in "
                               "the server environment and that 2-Step Verification is on.")
            except ApiError:
                raise
            except Exception:
                raise ApiError("Could not send the email. Please try again.")
            return {"ok": True, "to": to}

        if action == "save_settings":
            frm = (d.get("fromEmail") or "").strip() or DEFAULT_FROM_EMAIL or GMAIL_USER
            to = (d.get("toEmail") or "").strip()
            con.execute("""INSERT INTO settings (id, from_email, to_email) VALUES (1,?,?)
                           ON CONFLICT(id) DO UPDATE SET from_email=excluded.from_email,
                                                         to_email=excluded.to_email""", (frm, to))
            con.commit()
            return {"ok": True}

        raise ApiError("Unknown action.", 404)
    finally:
        con.close()


# ---------------------------------------------------------- HTTP server
class Handler(BaseHTTPRequestHandler):
    # Body cap comes from MAX_BODY_BYTES (env), above the base64 upload caps.

    # ----- security headers applied to every response -----
    # SECURITY: don't advertise "BaseHTTP/0.6 Python/3.x" — it tells an attacker
    # exactly which interpreter and stdlib server version to look up CVEs for.
    server_version = "matiz"
    sys_version = ""

    def version_string(self):
        return "matiz"

    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
        # NOTE: 'unsafe-inline' is required because this app's single-file front end uses
        # inline <script>/<style> and onclick="..." handlers throughout. This still blocks
        # loading of any script/style/frame/object from a third-party origin, which stops
        # the typical XSS payload (remote script injection, data exfiltration to another
        # host) even though it can't fully neutralize inline-script XSS. A stricter CSP
        # would require refactoring every inline handler in index.html.
        self.send_header("Content-Security-Policy",
                          "default-src 'self'; "
                          "script-src 'self' 'unsafe-inline'; "
                          "style-src 'self' 'unsafe-inline'; "
                          "img-src 'self' data:; "
                          "font-src 'self' data:; "
                          "connect-src 'self'; "
                          "frame-ancestors 'none'; "
                          "base-uri 'self'; "
                          "form-action 'self'")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if FORCE_HTTPS:
            # Only meaningful (and only honored by browsers) once served over HTTPS.
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def _client_ip(self):
        return (self.client_address[0] if self.client_address else "") or ""

    def _get_cookie(self, name):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return None

    def _origin_allowed_for_cors(self, origin):
        return bool(origin) and origin.rstrip("/") in ALLOWED_ORIGINS

    def _csrf_ok(self):
        """Lightweight CSRF defense-in-depth for state-changing (POST) requests, on top of
        the SameSite=Lax session cookie. Modern browsers always attach an Origin header to
        POST fetch/XHR requests (same-origin or cross-origin); if present, it must match
        this server's own Host. Requests without an Origin header (e.g. non-browser API
        clients / curl on the LAN) are allowed through, relying on SameSite alone — this
        keeps the documented "other devices on the LAN can just hit the API" behaviour
        working for legitimate tooling while blocking the classic browser CSRF pattern."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        if self._origin_allowed_for_cors(origin):
            return True
        host = self.headers.get("Host") or ""
        try:
            origin_host = urlparse(origin).netloc
        except ValueError:
            return False
        return origin_host == host

    def _json(self, obj, code=200, extra_headers=None):
        try:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            if extra_headers:
                for h_name, h_val in extra_headers:
                    self.send_header(h_name, h_val)
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            # The browser tab was refreshed, navigated away from, or closed before we
            # finished responding (this happens routinely — e.g. the page's own 12-second
            # auto-refresh poll gets cut off mid-flight by a manual refresh). The socket is
            # already gone at that point, so there's no one left to send a response to.
            # Silently drop it instead of letting the write blow up as an unhandled error.
            pass

    def _cookie_header(self, token, clear=False):
        attrs = [f"{COOKIE_NAME}=" + ("" if clear else token), "Path=/", "HttpOnly", "SameSite=Lax"]
        if clear:
            attrs.append("Max-Age=0")
        else:
            attrs.append(f"Max-Age={int(SESSION_TTL_HOURS * 3600)}")
        if COOKIE_SECURE:
            attrs.append("Secure")
        return "; ".join(attrs)

    def _api(self):
        ip = self._client_ip()
        q = parse_qs(urlparse(self.path).query)
        action = (q.get("action") or [""])[0]

        # ----- SECURITY: the API is POST-only. GET used to work for every action
        #       (the action name comes from the query string), which meant an
        #       <img src="/api?action=delete_client&..."> style request, or simply a
        #       link, could trigger state changes and dump data into the browser
        #       cache/history. -----
        if self.command != "POST":
            return self._json({"error": "This endpoint only accepts POST."}, 405)

        # ----- CSRF: Origin check, plus a custom header that a cross-site form
        #       post cannot set (it forces a CORS preflight that is never granted). -----
        if not self._csrf_ok():
            return self._json({"error": "Request blocked: origin check failed."}, 403)
        if (self.headers.get("X-Requested-With") or "") != "matiz-app":
            return self._json({"error": "Request blocked: missing application header."}, 403)

        # ----- general abuse/rate limiting, per IP -----
        if _rate_limited(ip, "api", limit=180, window_seconds=60):
            return self._json({"error": "Too many requests. Please slow down and try again shortly."}, 429)

        data = {}
        if self.command == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                return self._json({"error": "That request is too large."}, 413)
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw or b"{}")
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                data = {}

        # ----- SECURITY: resolve the caller's real identity from the server-side session,
        #       and overwrite anything the client claims about its own role/identity with
        #       it. This is the core fix for the app's original design, where every action
        #       simply trusted a "role"/"empId"/"clientId"/"empName" field sent by the
        #       browser. Only a small, explicit allow-list of actions may be called without
        #       a valid session at all (login, invite/reset flows, etc). -----
        token = self._get_cookie(COOKIE_NAME)
        con = db()
        try:
            session = get_session(con, token)
        finally:
            con.close()
        data["_session_token"] = token

        # ----- AUTHORIZATION: deny-by-default role check before anything runs.
        #       Unmapped actions are rejected, so a new handler added without a
        #       matrix entry fails closed instead of being world-callable. -----
        try:
            authorize(action, session)
        except ApiError as e:
            return self._json({"error": e.msg}, e.code)

        # ----- per-session CSRF token. login/logout/session are exempt (there is no
        #       session yet, or it is being torn down); the custom header above still
        #       covers those. -----
        if session and action not in ("login", "logout", "session"):
            supplied = self.headers.get("X-CSRF-Token") or ""
            expected = session["csrf"] or ""
            if not expected or not hmac.compare_digest(supplied, expected):
                return self._json({"error": "Your session has expired. Please log in again."}, 401)

        # Bind the principal to this request thread so get_client() can enforce
        # object-level ownership centrally.
        set_principal(session)

        if action not in PUBLIC_ACTIONS:
            data["role"] = session["kind"] if session["kind"] == "employee" else session["role"]
            if session["kind"] == "employee":
                data["empId"] = session["emp_id"]
                data["empUid"] = session["emp_uid"]
                data["empName"] = session["emp_name"]
                data["empRole"] = session["emp_role"]
                data["empTeamType"] = session["emp_team_type"] or ""
            elif session["kind"] == "client":
                # A client may legitimately act on any record in their own CL-ID
                # family (the "same client, another service" grouping), so rather
                # than blindly forcing their login record — which would silently
                # redirect actions aimed at their second service — accept the
                # supplied id only when it is inside that family, and otherwise
                # fall back to their own. get_client() enforces the same rule for
                # every other path.
                claimed = (data.get("clientId") or "").strip()
                own = session["client_id"]
                if claimed and claimed != own:
                    con2 = db()
                    try:
                        allowed = claimed in client_family_ids(con2, own)
                    finally:
                        con2.close()
                    data["clientId"] = claimed if allowed else own
                else:
                    data["clientId"] = own

            # ----- SECURITY: every remaining self-asserted identity field is
            #       overwritten from the session too. Previously only role/empId
            #       were bound, so `myKey` still came from the request body and
            #       any logged-in user could read another pair's private DM
            #       thread, or post chat/history entries under someone else's
            #       name. These are the keys the DM and audit code trusts. -----
            ident = session_identity(session)
            data["myKey"] = ident["key"]
            data["viewerKey"] = ident["key"]
            data["senderKey"] = ident["key"]
            data["senderName"] = ident["label"]
            data["actorLabel"] = ident["label"]
            data["actorName"] = ident["label"]
            data["author"] = ident["label"]
            data["_principal_key"] = ident["key"]
            data["_principal_label"] = ident["label"]

        set_cookie = None
        clear_cookie = False
        try:
            result = handle_action(action, data, ip=ip)
            if isinstance(result, dict):
                new_token = result.pop("_session_token", None)
                if new_token:
                    set_cookie = new_token
                if result.pop("_clear_cookie", False):
                    clear_cookie = True
            extra = []
            if set_cookie:
                extra.append(("Set-Cookie", self._cookie_header(set_cookie)))
            if clear_cookie:
                extra.append(("Set-Cookie", self._cookie_header("", clear=True)))
            self._json(result, extra_headers=extra or None)
        except ApiError as e:
            self._json({"error": e.msg}, e.code)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client disconnected while handle_action() was still running — there's no
            # connection left to report an error to, so just stop here quietly.
            pass
        except Exception as e:
            # SECURITY: never leak internal exception details/stack traces to the client
            # in production. Full detail still goes to the server's own console.
            ref = secrets.token_hex(4)
            print("Server error [%s]:" % ref, repr(e), file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            if DEBUG:
                self._json({"error": "Server error: " + str(e)}, 500)
            else:
                self._json({"error": "Something went wrong on our end. Please try again. "
                                      "(reference %s)" % ref}, 500)
        finally:
            set_principal(None)

    def _cors_headers_if_allowed(self):
        origin = self.headers.get("Origin")
        if self._origin_allowed_for_cors(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Credentials", "true")

    def do_OPTIONS(self):
        # CORS preflight — only answered for explicitly configured origins (ALLOWED_ORIGINS).
        # By default (no origins configured) this app is same-origin only, which is the
        # most restrictive/secure setting and matches how it ships out of the box.
        self.send_response(204)
        self._cors_headers_if_allowed()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            # Render health check. Deliberately says nothing about versions,
            # configuration or database contents.
            body = b'{"status": "ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api":
            return self._api()
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(ROOT, "index.html"), "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self._security_headers()
                self.end_headers()
                self.wfile.write(body)
            except FileNotFoundError:
                self._json({"error": "index.html not found next to server.py"}, 500)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
                pass  # tab closed/refreshed mid-load — nothing left to send to
            return
        self.send_response(404)
        self._security_headers()
        self.end_headers()

    def do_POST(self):
        if urlparse(self.path).path == "/api":
            return self._api()
        self.send_response(404)
        self._security_headers()
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # keep the terminal clean


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # A client (browser tab) disconnecting mid-request — e.g. a page refresh cutting
        # off the auto-refresh poll — is expected, routine behaviour, not a real server
        # error. Our request handler already swallows this in the common cases; this is
        # just a backstop for the rare case where the disconnect happens even earlier
        # (e.g. while the request headers themselves are still being read), so it doesn't
        # get dumped to the terminal as a scary traceback.
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError)):
            return
        super().handle_error(request, client_address)


def lan_ip():
    """Best-effort guess at this machine's LAN IP address (the one other
    devices on the same WiFi/network would use to reach this server)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # doesn't actually send anything
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


# =====================================================================
# WSGI ENTRY POINT (gunicorn on Render: `gunicorn server:app`)
# ---------------------------------------------------------------------
# Rather than reimplementing routing, cookies, CSRF and the security
# headers for a second HTTP stack — which is exactly how the two paths
# drift apart and one of them quietly loses a check — this adapter feeds
# the WSGI request through the very same Handler used by the standalone
# server, and parses the response back out. One code path, one set of
# security decisions.
# =====================================================================
class _AdapterSocket:
    def __init__(self, data):
        self._in = io.BytesIO(data)
        self.out = io.BytesIO()

    def makefile(self, mode="rb", *args, **kwargs):
        return self._in if "r" in mode else self.out

    def sendall(self, data):
        self.out.write(data)

    def close(self):
        pass


class _WSGIRequestHandler(Handler):
    """Same Handler, driven from a buffer instead of a live socket."""

    protocol_version = "HTTP/1.0"      # no keep-alive over the adapter

    def __init__(self, sock, client_address):
        self.connection = sock
        super().__init__(sock, client_address, None)

    def log_message(self, fmt, *args):
        pass


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/") or "/"
    if environ.get("QUERY_STRING"):
        path += "?" + environ["QUERY_STRING"]

    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length > MAX_BODY_BYTES:
        start_response("413 Payload Too Large",
                       [("Content-Type", "application/json")])
        return [b'{"error": "That request is too large."}']
    body = environ["wsgi.input"].read(length) if length else b""

    # Behind Render's proxy the real client IP is in X-Forwarded-For. Only the
    # last hop is trusted, and only when TRUST_PROXY is on.
    remote = environ.get("REMOTE_ADDR", "") or ""
    if TRUST_PROXY:
        fwd = environ.get("HTTP_X_FORWARDED_FOR", "")
        if fwd:
            remote = fwd.split(",")[-1].strip() or remote

    lines = ["%s %s HTTP/1.0" % (method, path)]
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").title()
            lines.append("%s: %s" % (name, value))
    if environ.get("CONTENT_TYPE"):
        lines.append("Content-Type: %s" % environ["CONTENT_TYPE"])
    if length:
        lines.append("Content-Length: %d" % length)
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + body

    sock = _AdapterSocket(raw)
    _WSGIRequestHandler(sock, (remote, 0))
    out = sock.out.getvalue()

    head, _, payload = out.partition(b"\r\n\r\n")
    head_lines = head.split(b"\r\n")
    status_line = head_lines[0].decode("latin-1") if head_lines else "HTTP/1.0 500 Internal Server Error"
    status = status_line.split(" ", 1)[1] if " " in status_line else "500 Internal Server Error"

    headers = []
    for line in head_lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            k = k.decode("latin-1").strip()
            # Hop-by-hop headers are the WSGI server's business, not ours.
            if k.lower() in ("connection", "keep-alive", "transfer-encoding", "server", "date"):
                continue
            headers.append((k, v.decode("latin-1").strip()))

    start_response(status, headers)
    return [payload]


# Under a WSGI server (gunicorn) there is no __main__ block, so the schema
# creation / column migrations / password hashing would never run and every
# login would fail against an unmigrated database. Initialise on import.
if __name__ != "__main__":
    init_db()


def _serve_forever():
    init_db()
    ip = lan_ip()
    print("=" * 56)
    print("  MATIZ TECHNOLOGY is running!")
    print("  On THIS computer, open:      http://localhost:%d" % PORT)
    if ip and ip != "127.0.0.1":
        print("  On the SAME WIFI, employees / team members open:")
        print("      http://%s:%d" % (ip, PORT))
    else:
        print("  Could not detect a network IP automatically.")
        print("  Run 'ipconfig' (Windows) or 'ifconfig' (Mac/Linux) to find it.")
    print("  Data is stored in PostgreSQL (DATABASE_URL).")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 56)
    QuietThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    _serve_forever()
