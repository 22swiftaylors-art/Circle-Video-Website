import os, re, sqlite3, secrets, hashlib, uuid, threading, time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from functools import wraps
import click
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, abort, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from twilio.rest import Client
from twilio.request_validator import RequestValidator

load_dotenv()
ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(ROOT))).resolve()
UPLOADS = DATA_DIR / "uploads"
DB = DATA_DIR / "circle.db"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", ""),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
)
if len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError("Set SECRET_KEY in .env to a random string of at least 32 characters.")
csrf = CSRFProtect(app)
login = LoginManager(app)
login.login_view = "login"
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
PHONE = re.compile(r"^\+[1-9]\d{7,14}$")
ALLOWED = {".mp4", ".3gp"}
FINAL = {"delivered", "read", "failed", "undelivered"}

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL, admin INTEGER DEFAULT 0, active INTEGER DEFAULT 1, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS invites(id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
          expires TEXT NOT NULL, used TEXT);
        CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL,
          sid TEXT, user_id INTEGER NOT NULL, recipient TEXT NOT NULL, filename TEXT NOT NULL,
          status TEXT NOT NULL, error TEXT, created TEXT NOT NULL, completed TEXT);
        """)

class User(UserMixin):
    def __init__(self, row):
        self.id, self.username = str(row["id"]), row["username"]
        self.admin, self.active = bool(row["admin"]), bool(row["active"])

@login.user_loader
def load_user(uid):
    with db() as c: row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return User(row) if row else None

def admin_only(fn):
    @wraps(fn)
    @login_required
    def inner(*a, **kw):
        if not current_user.admin: abort(403)
        return fn(*a, **kw)
    return inner

def public_url(path):
    base = os.getenv("APP_BASE_URL", "").rstrip("/")
    if not base.startswith("https://"): raise RuntimeError("APP_BASE_URL must be a public HTTPS URL.")
    return base + path

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    r.headers["Cache-Control"] = "no-store"
    return r

@app.route("/")
def home(): return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))

@app.route("/login", methods=["GET","POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        with db() as c:
            u = c.execute("SELECT * FROM users WHERE username=?", (request.form.get("username","").strip(),)).fetchone()
        if u and u["active"] and check_password_hash(u["password_hash"], request.form.get("password","")):
            login_user(User(u), remember=True)
            return redirect(url_for("dashboard"))
        flash("Login failed, or this account is disabled.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/join/<token>", methods=["GET","POST"])
@limiter.limit("8 per hour", methods=["POST"])
def join(token):
    th = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        inv = c.execute("SELECT * FROM invites WHERE token_hash=? AND used IS NULL AND expires>?", (th,now())).fetchone()
    if not inv: abort(404)
    if request.method == "POST":
        name, pw = request.form.get("username","").strip(), request.form.get("password","")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", name): flash("Username must be 3–30 letters, numbers, dots, _ or -.", "error")
        elif len(pw) < 12: flash("Choose a password with at least 12 characters.", "error")
        else:
            try:
                with db() as c:
                    cur = c.execute("INSERT INTO users(username,password_hash,created) VALUES(?,?,?)",
                                    (name,generate_password_hash(pw),now()))
                    c.execute("UPDATE invites SET used=? WHERE id=?", (now(),inv["id"]))
                    u = c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
                login_user(User(u), remember=True)
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError: flash("That username is already taken.", "error")
    return render_template("join.html")

@app.route("/dashboard")
@login_required
def dashboard(): return render_template("dashboard.html")

@app.route("/admin", methods=["GET","POST"])
@admin_only
def admin():
    invite_link = None
    if request.method == "POST" and request.form.get("action") == "invite":
        token = secrets.token_urlsafe(32)
        with db() as c:
            c.execute("INSERT INTO invites(token_hash,expires) VALUES(?,?)",
                      (hashlib.sha256(token.encode()).hexdigest(),(datetime.now(timezone.utc)+timedelta(days=7)).isoformat()))
        invite_link = public_url(url_for("join",token=token))
    elif request.method == "POST" and request.form.get("action") == "toggle":
        uid = request.form.get("user_id")
        if uid and uid != current_user.id:
            with db() as c: c.execute("UPDATE users SET active=1-active WHERE id=? AND admin=0",(uid,))
        return redirect(url_for("admin"))
    with db() as c: users = c.execute("SELECT id,username,admin,active FROM users ORDER BY id").fetchall()
    return render_template("admin.html", users=users, invite_link=invite_link)

@app.route("/upload", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def upload():
    recipient = request.form.get("whatsapp_number","").strip()
    f = request.files.get("video")
    if not PHONE.fullmatch(recipient): return jsonify(error="Use international format, e.g. +2348012345678."),400
    if not f or not f.filename: return jsonify(error="Choose a video first."),400
    ext = Path(secure_filename(f.filename)).suffix.lower()
    if ext not in ALLOWED: return jsonify(error="MP4 and 3GP videos only."),400
    if f.mimetype not in {"video/mp4","video/3gpp","application/octet-stream"}:
        return jsonify(error="Unsupported video content type."),400
    filename, token = uuid.uuid4().hex+ext, secrets.token_urlsafe(32)
    path = UPLOADS / filename
    f.save(path)
    job = uuid.uuid4().hex
    try:
        sid, auth, sender = (os.getenv(k,"") for k in ("TWILIO_ACCOUNT_SID","TWILIO_AUTH_TOKEN","TWILIO_WHATSAPP_NUMBER"))
        if not all([sid,auth,sender]): raise RuntimeError("Twilio is not configured.")

        # Create the row before Twilio can fetch the media or send a callback.
        with db() as c:
            c.execute("""INSERT INTO messages(id,token,sid,user_id,recipient,filename,status,created)
              VALUES(?,?,NULL,?,?,?,?,?)""",(job,token,int(current_user.id),recipient,filename,"submitting",now()))

        media = public_url(url_for("media",token=token))
        callback = public_url(url_for("status_callback",job=job))
        msg = Client(sid,auth).messages.create(
            body="Here is your video.", from_=f"whatsapp:{sender}",
            to=f"whatsapp:{recipient}", media_url=[media], status_callback=callback)
        # Do not overwrite a status callback that may already have arrived.
        with db() as c:
            c.execute("""UPDATE messages SET sid=?,
              status=CASE WHEN status='submitting' THEN ? ELSE status END WHERE id=?""",
              (msg.sid,msg.status or "queued",job))
        return jsonify(job_id=job,status=msg.status or "queued")
    except Exception:
        with db() as c: c.execute("DELETE FROM messages WHERE id=?",(job,))
        path.unlink(missing_ok=True)
        app.logger.exception("Twilio send failed")
        return jsonify(error="Could not submit the video. Check Twilio configuration and logs."),500

@app.route("/status/<job>")
@login_required
def message_status(job):
    with db() as c:
        row=c.execute("SELECT status,error FROM messages WHERE id=? AND user_id=?",(job,int(current_user.id))).fetchone()
    return (jsonify(status=row["status"],error=row["error"]) if row else (jsonify(error="Not found"),404))

@app.route("/media/<token>")
def media(token):
    # Public to Twilio; the long random token is a secret bearer URL.
    with db() as c: row=c.execute("SELECT filename FROM messages WHERE token=?",(token,)).fetchone()
    if not row: abort(404)
    return send_from_directory(UPLOADS,row["filename"],as_attachment=False)

@app.route("/twilio/status/<job>",methods=["POST"])
@csrf.exempt
def status_callback(job):
    auth=os.getenv("TWILIO_AUTH_TOKEN","")
    signature=request.headers.get("X-Twilio-Signature","")
    callback_url=public_url(url_for("status_callback",job=job))
    if not auth or not RequestValidator(auth).validate(callback_url,request.form,signature):
        abort(403)
    status=request.form.get("MessageStatus","unknown").lower()
    done=now() if status in FINAL else None
    with db() as c:
        c.execute("""UPDATE messages SET sid=COALESCE(sid,?),status=?,error=?,
          completed=COALESCE(?,completed) WHERE id=?""",
          (request.form.get("MessageSid"),status,request.form.get("ErrorCode"),done,job))
    return "",204

@app.cli.command("create-admin")
def create_admin():
    name=click.prompt("Admin username")
    pw=click.prompt("Admin password",hide_input=True,confirmation_prompt=True)
    if len(pw)<12: raise click.ClickException("Password must be at least 12 characters.")
    try:
        with db() as c: c.execute("INSERT INTO users(username,password_hash,admin,created) VALUES(?,?,1,?)",
                                  (name,generate_password_hash(pw),now()))
    except sqlite3.IntegrityError: raise click.ClickException("Username already exists.")
    click.echo("Admin created.")

def cleanup_expired_uploads():
    # Final delivery states: delete after one hour. Stuck jobs: delete after 24h.
    current=datetime.now(timezone.utc); count=0
    with db() as c:
        rows=c.execute("SELECT id,filename,status,created,completed FROM messages").fetchall()
        for r in rows:
            created=datetime.fromisoformat(r["created"])
            completed=datetime.fromisoformat(r["completed"]) if r["completed"] else None
            expired=(completed and r["status"] in FINAL and current-completed>=timedelta(hours=1))
            expired=expired or (current-created>=timedelta(hours=24))
            if expired:
                (UPLOADS/r["filename"]).unlink(missing_ok=True)
                c.execute("DELETE FROM messages WHERE id=?",(r["id"],)); count+=1
    return count

@app.cli.command("cleanup-uploads")
def cleanup_uploads():
    click.echo(f"Deleted {cleanup_expired_uploads()} expired video(s).")

def cleanup_loop():
    while True:
        time.sleep(300)
        try:
            cleanup_expired_uploads()
        except Exception:
            app.logger.exception("Scheduled upload cleanup failed")

# Enable on the single production web worker so cleanup uses the same persistent disk.
if os.getenv("ENABLE_CLEANUP_THREAD", "false").lower() == "true":
    threading.Thread(target=cleanup_loop, name="upload-cleanup", daemon=True).start()

@app.errorhandler(413)
def too_large(_): return jsonify(error="Maximum video size is 16 MB."),413

init_db()
if __name__=="__main__": app.run(host="127.0.0.1",port=5000,debug=False)
