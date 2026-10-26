import os, csv, io, sqlite3, secrets, smtplib, time, hmac
from datetime import datetime, timedelta
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import jsonify
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "campus_faults.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-development-secret")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"  # Set to 1 behind HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
TOKEN_SALT = "campusfix-account-v2"

def token_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt=TOKEN_SALT)

def send_email(to_address, subject, body):
    """Send mail only when SMTP settings are configured; local development works without SMTP."""
    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        app.logger.info("Email not sent because SMTP_HOST is not configured (recipient hidden).")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "campusfix@localhost"))
    msg["To"] = to_address
    msg.set_content(body)
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=12) as server:
        server.starttls()
        username = os.environ.get("SMTP_USER", "")
        password = os.environ.get("SMTP_PASSWORD", "")
        if username:
            server.login(username, password)
        server.send_message(msg)
    return True

def notify_user(email, subject, body):
    try:
        send_email(email, subject, body)
    except Exception:
        app.logger.exception("Email notification failed")


CATEGORIES = ["Electrical", "Computer / IT", "Furniture", "Plumbing", "Classroom", "Laboratory", "Cleaning", "Other"]
LOCATIONS = ["Academic Block", "Library", "Computer Lab", "Laboratory", "Hostel", "Canteen", "Auditorium", "Sports Area", "Office", "Other"]
STATUSES = ["Reported", "Acknowledged", "In Progress", "Resolved", "Rejected"]

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student',
          email_verified INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS faults (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL, description TEXT NOT NULL,
          category TEXT NOT NULL, location TEXT NOT NULL,
          room TEXT DEFAULT '', reporter_id INTEGER NOT NULL,
          priority TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Reported',
          photo TEXT DEFAULT '', photo_review_status TEXT NOT NULL DEFAULT 'Not required', ai_flag INTEGER NOT NULL DEFAULT 0, ai_reason TEXT DEFAULT '', assigned_to TEXT DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          resolution_note TEXT DEFAULT '',
          FOREIGN KEY(reporter_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          fault_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
          message TEXT NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(fault_id) REFERENCES faults(id) ON DELETE CASCADE,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS abuse_flags (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          fault_id INTEGER NOT NULL UNIQUE,
          student_id INTEGER NOT NULL,
          reason TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Pending review',
          created_at TEXT NOT NULL,
          reviewed_by INTEGER,
          review_note TEXT DEFAULT '',
          FOREIGN KEY(fault_id) REFERENCES faults(id) ON DELETE CASCADE,
          FOREIGN KEY(student_id) REFERENCES users(id),
          FOREIGN KEY(reviewed_by) REFERENCES users(id)
        );
        """)
        user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)").fetchall()}
        if "email_verified" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
        # Safe migration for databases created by an earlier version.
        columns = {row[1] for row in con.execute("PRAGMA table_info(faults)").fetchall()}
        if "photo_review_status" not in columns:
            con.execute("ALTER TABLE faults ADD COLUMN photo_review_status TEXT NOT NULL DEFAULT 'Not required'")
            con.execute("UPDATE faults SET photo_review_status='Pending review' WHERE photo IS NOT NULL AND photo != ''")
        if "ai_flag" not in columns:
            con.execute("ALTER TABLE faults ADD COLUMN ai_flag INTEGER NOT NULL DEFAULT 0")
        if "ai_reason" not in columns:
            con.execute("ALTER TABLE faults ADD COLUMN ai_reason TEXT DEFAULT ''")
        # Demo admin: change password after first login.
        admin = con.execute("SELECT id FROM users WHERE email=?", ("admin@campus.local",)).fetchone()
        if not admin:
            con.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                        ("Campus Admin", "admin@campus.local", generate_password_hash("Admin@123"), "admin", now()))
        con.commit()

@app.before_request
def protect_post_requests():
    # Simple session-bound CSRF defense for every browser POST endpoint.
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not supplied or not hmac.compare_digest(supplied, expected):
            abort(400, description="Security token missing or expired. Refresh the page and try again.")

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
    return response

@app.context_processor
def inject_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Offline photo screening: no Transformers, PyTorch, API key, or model download needed.
# This can detect invalid/blank/very low-detail images, but cannot semantically prove
# that an image is relevant or inappropriate. Staff review remains mandatory.
def inspect_image_with_ai(image_path, category, title, description):
    try:
        with Image.open(image_path) as original:
            image = original.convert("RGB")
            width, height = image.size
            if width < 120 or height < 120:
                return True, f"Automatic screening flagged a very small image ({width}x{height}). Please upload a clearer photo; staff must verify."
            # Sample a small grayscale thumbnail and estimate image variation.
            sample = image.convert("L").resize((64, 64))
            pixels = list(sample.getdata())
            mean = sum(pixels) / len(pixels)
            variance = sum((p - mean) ** 2 for p in pixels) / len(pixels)
            if variance < 18:
                return True, "Automatic screening flagged an almost blank or nearly uniform image. Please upload a clear photo of the fault; staff must verify."
            # Very narrow/tall or wide/short images are not automatically rejected, just reviewed.
            ratio = max(width / height, height / width)
            if ratio > 5.5:
                return True, "Automatic screening flagged an unusually stretched image. Staff must verify that it clearly shows the reported fault."
            return False, "Offline photo checks passed (valid image with visible variation). This does not confirm fault relevance or appropriateness; staff must review the photo."
    except Exception as exc:
        return True, f"Automatic photo check failed ({type(exc).__name__}). Staff must manually review this photo."

def current_user():
    if "user_id" not in session:
        return None
    with db() as con:
        return con.execute("SELECT id,name,email,role FROM users WHERE id=?", (session["user_id"],)).fetchone()

@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "categories": CATEGORIES, "locations": LOCATIONS, "statuses": STATUSES}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def staff_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please sign in first.", "warning")
            return redirect(url_for("login"))
        if user["role"] not in ("admin", "staff"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def auto_priority(category, title, description):
    text = f"{category} {title} {description}".lower()
    urgent = ["sparking", "electric shock", "fire", "smoke", "exposed wire", "water leak near", "danger", "injury", "short circuit"]
    high = ["not working", "broken", "leak", "power", "projector", "server", "computer lab", "blocked"]
    if any(word in text for word in urgent):
        return "Critical"
    if any(word in text for word in high) or category in ("Electrical", "Plumbing", "Computer / IT", "Laboratory"):
        return "High"
    if category in ("Classroom", "Furniture"):
        return "Medium"
    return "Low"

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_photo(filename):
    """Serve only files from the configured upload directory."""
    safe_name = os.path.basename(filename)
    full_path = os.path.join(UPLOAD_DIR, safe_name)
    if not os.path.isfile(full_path):
        abort(404)
    return send_from_directory(UPLOAD_DIR, safe_name, conditional=True)

@app.route("/")
def index():
    with db() as con:
        stats = {
            "total": con.execute("SELECT COUNT(*) FROM faults").fetchone()[0],
            "open": con.execute("SELECT COUNT(*) FROM faults WHERE status NOT IN ('Resolved','Rejected')").fetchone()[0],
            "resolved": con.execute("SELECT COUNT(*) FROM faults WHERE status='Resolved'").fetchone()[0],
            "critical": con.execute("SELECT COUNT(*) FROM faults WHERE priority='Critical' AND status NOT IN ('Resolved','Rejected')").fetchone()[0]
        }
        latest = con.execute("""SELECT f.*, u.name reporter_name FROM faults f
                               JOIN users u ON u.id=f.reporter_id ORDER BY f.created_at DESC LIMIT 5""").fetchall()
    return render_template("index.html", stats=stats, latest=latest)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Account not created. Enter your name and email, and use a password with at least 8 characters.", "danger")
        else:
            try:
                with db() as con:
                    existing = con.execute("SELECT id FROM users WHERE lower(email)=lower(?)", (email,)).fetchone()
                    if existing:
                        flash("That email is already registered. Sign in instead, or use a different email address.", "danger")
                        return render_template("register.html", form_name=name, form_email=email)
                    mail_enabled = bool(os.environ.get("SMTP_HOST", "").strip())
                    con.execute("INSERT INTO users(name,email,password_hash,role,email_verified,created_at) VALUES(?,?,?,?,?,?)",
                                (name, email, generate_password_hash(password), "student", 0 if mail_enabled else 1, now()))
                    con.commit()
                if mail_enabled:
                    token = token_serializer().dumps(email, salt="verify-email")
                    verify_url = url_for("verify_email", token=token, _external=True)
                    notify_user(email, "Verify your CampusFix email", f"Welcome to CampusFix. Verify your CampusFix email with this link (valid for 24 hours):\n\n{verify_url}\n")
                    flash("Account created successfully. Check your email for the verification link, then sign in.", "success")
                else:
                    flash("Account created successfully. You can now sign in with your new email and password.", "success")
                return redirect(url_for("login"), code=303)
            except sqlite3.IntegrityError:
                flash("That email is already registered. Sign in instead, or use a different email address.", "danger")
            except sqlite3.Error:
                flash("We couldn't create the account because of a database error. Check the server terminal for details.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        attempts = session.get("login_attempts", 0)
        last_attempt = session.get("last_login_attempt", 0)
        if attempts >= 8 and time.time() - last_attempt < 300:
            flash("Too many sign-in attempts. Wait five minutes and try again.", "danger")
            return render_template("login.html"), 429
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            if not user["email_verified"]:
                flash("Verify your email before signing in. Use the link sent to your inbox.", "warning")
                return render_template("login.html"), 403
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for("dashboard"))
        session["login_attempts"] = attempts + 1
        session["last_login_attempt"] = time.time()
        flash("Incorrect email or password.", "danger")
    return render_template("login.html")

@app.route("/admin/staff", methods=["GET", "POST"])
@login_required
def manage_staff():
    user = current_user()
    if user["role"] != "admin":
        abort(403)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "staff")
        if role not in ("staff", "admin"):
            role = "staff"
        if not name or not email or len(password) < 8:
            flash("Enter a name, email, and password with at least 8 characters.", "danger")
        else:
            try:
                with db() as con:
                    con.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                                (name, email, generate_password_hash(password), role, now()))
                    con.commit()
                flash(f"{role.title()} account created. Share credentials securely with that person.", "success")
                return redirect(url_for("manage_staff"))
            except sqlite3.IntegrityError:
                flash("That email is already registered. Use a unique email address.", "danger")
    with db() as con:
        staff_members = con.execute("SELECT id,name,email,role,created_at FROM users WHERE role IN ('staff','admin') ORDER BY role,name").fetchall()
    return render_template("manage_staff.html", staff_members=staff_members)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have signed out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    filters = request.args
    clauses, params = [], []
    if user["role"] not in ("admin", "staff"):
        clauses.append("f.reporter_id=?"); params.append(user["id"])
    if filters.get("status"):
        clauses.append("f.status=?"); params.append(filters["status"])
    if filters.get("priority"):
        clauses.append("f.priority=?"); params.append(filters["priority"])
    if filters.get("category"):
        clauses.append("f.category=?"); params.append(filters["category"])
    if filters.get("q"):
        clauses.append("(f.title LIKE ? OR f.description LIKE ? OR f.location LIKE ?)")
        term = "%" + filters["q"].strip() + "%"
        params.extend([term, term, term])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with db() as con:
        faults = con.execute("""SELECT f.*, u.name reporter_name FROM faults f
                               JOIN users u ON u.id=f.reporter_id""" + where +
                              " ORDER BY CASE f.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, f.created_at DESC",
                              params).fetchall()
    return render_template("dashboard.html", faults=faults, filters=filters, is_staff=user["role"] in ("admin", "staff"))

@app.route("/report", methods=["GET", "POST"])
@login_required
def report_fault():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "")
        location = request.form.get("location", "")
        room = request.form.get("room", "").strip()
        if not title or not description or category not in CATEGORIES or location not in LOCATIONS:
            flash("Please complete all required fields using the available options.", "danger")
            return render_template("report.html")
        photo_name = ""
        ai_flag = 0
        ai_reason = ""
        file = request.files.get("photo")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Photo must be PNG, JPG, JPEG, or WEBP.", "danger")
                return render_template("report.html")
            try:
                # Verify the file's real contents, not only its extension.
                image = Image.open(file.stream)
                image.verify()
                file.stream.seek(0)
                image = Image.open(file.stream)
                if image.format not in {"PNG", "JPEG", "WEBP"}:
                    raise ValueError("Unsupported image format")
                if image.width * image.height > 25_000_000:
                    flash("This image has too many pixels. Please upload a smaller image.", "danger")
                    return render_template("report.html")
            except (UnidentifiedImageError, OSError, ValueError):
                flash("The uploaded file is not a valid PNG, JPG, or WEBP image. Please choose a genuine image.", "danger")
                return render_template("report.html")
            photo_name = secrets.token_hex(8) + "_" + secure_filename(file.filename)
            saved_path = os.path.join(UPLOAD_DIR, photo_name)
            # Pillow may leave the upload stream positioned after reading image headers.
            # Rewind it before saving so the complete original image is written to disk.
            file.stream.seek(0)
            file.save(saved_path)
            # Confirm the saved file is a readable image before storing its name in the DB.
            try:
                with Image.open(saved_path) as saved_image:
                    saved_image.verify()
            except (UnidentifiedImageError, OSError, ValueError):
                try:
                    os.remove(saved_path)
                except OSError:
                    pass
                flash("The uploaded photo could not be saved correctly. Please choose the image again.", "danger")
                return render_template("report.html")
            flagged, ai_reason = inspect_image_with_ai(saved_path, category, title, description)
            ai_flag = 1 if flagged else 0
        photo_review_status = "Pending review" if photo_name else "Not required"
        priority = auto_priority(category, title, description)
        stamp = now()
        with db() as con:
            con.execute("""INSERT INTO faults(title,description,category,location,room,reporter_id,priority,status,photo,photo_review_status,ai_flag,ai_reason,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,'Reported',?,?,?,?,?,?)""",
                        (title, description, category, location, room, session["user_id"], priority, photo_name, photo_review_status, ai_flag, ai_reason, stamp, stamp))
            con.commit()
            fault_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
            # A screening flag is a review signal, not proof of deliberate abuse.
            if ai_flag:
                con.execute("INSERT OR IGNORE INTO abuse_flags(fault_id,student_id,reason,created_at) VALUES(?,?,?,?)",
                            (fault_id, session["user_id"], ai_reason or "Photo flagged by automated screening", stamp))
                con.commit()
        flash(f"Fault #{fault_id} submitted. Suggested priority: {priority}.", "success")
        with db() as con:
            reporter = con.execute("SELECT email,name FROM users WHERE id=?", (session["user_id"],)).fetchone()
            staff_emails = con.execute("SELECT email FROM users WHERE role IN ('admin','staff') AND email_verified=1").fetchall()
        body = f"Hello {reporter['name']},\n\nYour campus fault report #{fault_id} was submitted.\nTitle: {title}\nPriority: {priority}\nStatus: Reported\n\nSign in to CampusFix to follow updates."
        notify_user(reporter["email"], f"CampusFix report #{fault_id} received", body)
        for staff_row in staff_emails:
            notify_user(staff_row["email"], f"New campus fault #{fault_id}: {title}", f"A new fault was reported.\nLocation: {location}\nPriority: {priority}\nPlease sign in to CampusFix to review it.")
        if photo_name and ai_flag:
            flash("AI flagged the uploaded photo for staff review. It has not been automatically deleted.", "warning")
        elif photo_name and ai_reason:
            flash("Photo screening result: " + ai_reason, "info")
        return redirect(url_for("fault_detail", fault_id=fault_id))
    return render_template("report.html")

@app.route("/fault/<int:fault_id>", methods=["GET", "POST"])
@login_required
def fault_detail(fault_id):
    user = current_user()
    with db() as con:
        fault = con.execute("""SELECT f.*, u.name reporter_name, u.email reporter_email
                              FROM faults f JOIN users u ON u.id=f.reporter_id WHERE f.id=?""", (fault_id,)).fetchone()
        if not fault:
            abort(404)
        if request.method == "POST":
            message = request.form.get("message", "").strip()
            if message:
                con.execute("INSERT INTO comments(fault_id,user_id,message,created_at) VALUES(?,?,?,?)",
                            (fault_id, user["id"], message, now()))
                con.commit()
                flash("Comment added.", "success")
                return redirect(url_for("fault_detail", fault_id=fault_id))
        comments = con.execute("""SELECT c.*, u.name, u.role FROM comments c JOIN users u ON u.id=c.user_id
                                  WHERE c.fault_id=? ORDER BY c.created_at""", (fault_id,)).fetchall()
    return render_template("fault_detail.html", fault=fault, comments=comments, is_staff=user["role"] in ("admin", "staff"))

@app.route("/fault/<int:fault_id>/flag-photo", methods=["POST"])
@login_required
def flag_invalid_photo(fault_id):
    """Let the reporter or staff flag an irrelevant/inappropriate photo for admin review."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user["role"] not in ("admin", "staff"):
        abort(403)
    reason = request.form.get("reason", "").strip()
    details = request.form.get("details", "").strip()[:500]
    allowed_reasons = {
        "Irrelevant image", "Meme or joke image", "Inappropriate image",
        "Duplicate or misleading evidence", "Other concern"
    }
    if reason not in allowed_reasons:
        flash("Choose a valid reason for flagging this photo.", "danger")
        return redirect(url_for("fault_detail", fault_id=fault_id))
    with db() as con:
        fault = con.execute("SELECT id, reporter_id, photo FROM faults WHERE id=?", (fault_id,)).fetchone()
        if not fault:
            abort(404)
        if user["role"] not in ("admin", "staff") and fault["reporter_id"] != user["id"]:
            abort(403)
        if not fault["photo"]:
            flash("This report has no attached photo to flag.", "warning")
            return redirect(url_for("fault_detail", fault_id=fault_id))
        existing = con.execute("SELECT id FROM abuse_flags WHERE fault_id=?", (fault_id,)).fetchone()
        if existing:
            con.execute("UPDATE abuse_flags SET reason=? WHERE fault_id=? AND status='Pending review'",
                        (reason + (": " + details if details else ""), fault_id))
            flash("This report is already flagged. Its pending review has been updated if it was still pending.", "info")
        else:
            con.execute("INSERT INTO abuse_flags(fault_id,student_id,reason,created_at) VALUES(?,?,?,?)",
                        (fault_id, fault["reporter_id"], reason + (": " + details if details else ""), now()))
            flash("Photo flagged for administrator review. The student account has not been penalized automatically.", "success")
        con.commit()
    return redirect(url_for("fault_detail", fault_id=fault_id))


@app.route("/fault/<int:fault_id>/update", methods=["POST"])
@staff_required
def update_fault(fault_id):
    status = request.form.get("status", "")
    priority = request.form.get("priority", "")
    assigned_to = request.form.get("assigned_to", "").strip()
    resolution_note = request.form.get("resolution_note", "").strip()
    photo_review_status = request.form.get("photo_review_status", "Pending review")
    if photo_review_status not in ("Pending review", "Approved", "Rejected - replace photo", "Not required"):
        flash("Invalid photo review status.", "danger")
        return redirect(url_for("fault_detail", fault_id=fault_id))
    if status not in STATUSES or priority not in ("Critical", "High", "Medium", "Low"):
        flash("Invalid status or priority.", "danger")
        return redirect(url_for("fault_detail", fault_id=fault_id))
    with db() as con:
        exists = con.execute("SELECT id, photo FROM faults WHERE id=?", (fault_id,)).fetchone()
        if not exists:
            abort(404)
        if not exists["photo"]:
            photo_review_status = "Not required"
        con.execute("""UPDATE faults SET status=?, priority=?, assigned_to=?, resolution_note=?, photo_review_status=?, updated_at=? WHERE id=?""",
                    (status, priority, assigned_to, resolution_note, photo_review_status, now(), fault_id))
        con.commit()
        notify_row = con.execute("SELECT f.id,f.title,f.status,f.priority,u.email,u.name FROM faults f JOIN users u ON u.id=f.reporter_id WHERE f.id=?", (fault_id,)).fetchone()
    notify_user(notify_row["email"], f"CampusFix report #{fault_id} updated", f"Hello {notify_row['name']},\n\nYour report #{fault_id} ({notify_row['title']}) has been updated.\nStatus: {notify_row['status']}\nPriority: {notify_row['priority']}\nSign in to CampusFix for details.")
    flash("Fault record updated.", "success")
    return redirect(url_for("fault_detail", fault_id=fault_id))

@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = token_serializer().loads(token, salt="verify-email", max_age=86400)
    except SignatureExpired:
        flash("Verification link expired. Register again or request a fresh link.", "danger")
        return redirect(url_for("login"))
    except BadSignature:
        abort(400, description="Invalid verification link.")
    with db() as con:
        con.execute("UPDATE users SET email_verified=1 WHERE email=?", (email,))
        con.commit()
    flash("Email verified. You can now sign in.", "success")
    return redirect(url_for("login"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        with db() as con:
            user = con.execute("SELECT email FROM users WHERE email=?", (email,)).fetchone()
        # Same response regardless of whether an account exists, to avoid account enumeration.
        if user and os.environ.get("SMTP_HOST", "").strip():
            token = token_serializer().dumps(email, salt="reset-password")
            reset_url = url_for("reset_password", token=token, _external=True)
            notify_user(email, "Reset your CampusFix password", f"Use this link to reset your password (valid for 30 minutes):\n\n{reset_url}\n")
        flash("If that email belongs to an account and email is configured, a reset link will arrive shortly.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = token_serializer().loads(token, salt="reset-password", max_age=1800)
    except SignatureExpired:
        flash("Password reset link expired. Request a new one.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        abort(400, description="Invalid password reset link.")
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 10:
            flash("Use at least 10 characters for your new password.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            with db() as con:
                con.execute("UPDATE users SET password_hash=? WHERE email=?", (generate_password_hash(password), email))
                con.commit()
            flash("Password changed. Please sign in again.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html")

@app.route("/api/updates")
@login_required
def api_updates():
    user = current_user()
    with db() as con:
        if user["role"] in ("admin", "staff"):
            rows = con.execute("SELECT id,status,priority,updated_at FROM faults ORDER BY id DESC LIMIT 100").fetchall()
        else:
            rows = con.execute("SELECT id,status,priority,updated_at FROM faults WHERE reporter_id=? ORDER BY id DESC LIMIT 100", (user["id"],)).fetchall()
    return jsonify({"reports": [dict(r) for r in rows], "checked_at": now()})

@app.route("/analytics")
@staff_required
def analytics():
    with db() as con:
        by_status = con.execute("SELECT status, COUNT(*) count FROM faults GROUP BY status").fetchall()
        by_priority = con.execute("SELECT priority, COUNT(*) count FROM faults GROUP BY priority").fetchall()
        by_category = con.execute("SELECT category, COUNT(*) count FROM faults GROUP BY category ORDER BY count DESC").fetchall()
        by_location = con.execute("SELECT location, COUNT(*) count FROM faults GROUP BY location ORDER BY count DESC LIMIT 8").fetchall()
        recent = con.execute("SELECT substr(created_at,1,7) month, COUNT(*) count FROM faults GROUP BY month ORDER BY month DESC LIMIT 6").fetchall()
    return render_template("analytics.html", by_status=by_status, by_priority=by_priority,
                           by_category=by_category, by_location=by_location, recent=list(reversed(recent)))

@app.route("/admin/abuse", methods=["GET", "POST"])
@login_required
def abuse_reports():
    user = current_user()
    if user["role"] != "admin":
        abort(403)
    if request.method == "POST":
        flag_id = request.form.get("flag_id", type=int)
        status = request.form.get("status", "Pending review")
        note = request.form.get("review_note", "").strip()[:1000]
        if status not in ("Pending review", "Confirmed misuse", "No abuse found", "Warning issued", "Closed"):
            abort(400)
        with db() as con:
            con.execute("UPDATE abuse_flags SET status=?, reviewed_by=?, review_note=? WHERE id=?",
                        (status, user["id"], note, flag_id))
            con.commit()
        flash("Abuse review updated. No automatic account penalty was applied.", "success")
        return redirect(url_for("abuse_reports"))
    with db() as con:
        flags = con.execute("""SELECT af.*, f.title, f.description, f.category, f.photo, f.ai_flag,
                u.name AS student_name, u.email AS student_email,
                (SELECT COUNT(*) FROM abuse_flags x WHERE x.student_id=af.student_id) AS flagged_count
            FROM abuse_flags af JOIN faults f ON f.id=af.fault_id
            JOIN users u ON u.id=af.student_id ORDER BY
            CASE WHEN af.status='Pending review' THEN 0 ELSE 1 END, af.created_at DESC""").fetchall()
    return render_template("abuse_reports.html", flags=flags)


@app.route("/export.csv")
@staff_required
def export_csv():
    with db() as con:
        rows = con.execute("""SELECT f.id, f.title, f.description, f.category, f.location, f.room,
            f.priority, f.status, f.assigned_to, f.created_at, f.updated_at, u.name reporter, u.email
            FROM faults f JOIN users u ON u.id=f.reporter_id ORDER BY f.created_at DESC""").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Title","Description","Category","Location","Room","Priority","Status","Assigned To","Created","Updated","Reporter","Reporter Email"])
    for row in rows:
        writer.writerow(list(row))
    mem = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="campus_faults.csv")

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You don't have permission to view this page."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The page or fault report could not be found."), 404

@app.errorhandler(413)
def too_large(_):
    flash("Image is too large. Maximum upload size is 5 MB.", "danger")
    return redirect(url_for("report_fault"))

init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
