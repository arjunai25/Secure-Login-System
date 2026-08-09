import os
import re
import sqlite3
import secrets
import time
from functools import wraps
from datetime import timedelta

import pyotp
import qrcode

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

# In production, set this using an environment variable.
app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Set True when using HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

DATABASE = "users.db"


# ============================================================
# DATABASE
# ============================================================

def get_db():
    """
    Create a SQLite connection.

    Row factory allows us to access columns by name.
    """

    connection = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_database():
    """
    Create the users table if it doesn't exist.
    """

    db = get_db()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            email TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            two_factor_enabled INTEGER DEFAULT 0,

            two_factor_secret TEXT,

            failed_attempts INTEGER DEFAULT 0,

            locked_until REAL DEFAULT 0,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    db.commit()

    db.close()


# ============================================================
# CSRF PROTECTION
# ============================================================

def get_csrf_token():
    """
    Generate or retrieve a CSRF token for the current session.
    """

    if "csrf_token" not in session:

        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def validate_csrf():
    """
    Validate CSRF token on POST requests.
    """

    token = request.form.get("csrf_token")

    stored_token = session.get(
        "csrf_token"
    )

    if not token or not stored_token:
        return False

    return secrets.compare_digest(
        token,
        stored_token
    )


# ============================================================
# INPUT VALIDATION
# ============================================================

def valid_username(username):

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9_]{3,30}",
            username
        )
    )


def valid_email(email):

    return bool(
        re.fullmatch(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            email
        )
    )


def validate_password(password):

    errors = []

    if len(password) < 8:
        errors.append(
            "Password must contain at least 8 characters."
        )

    if len(password) > 128:
        errors.append(
            "Password cannot exceed 128 characters."
        )

    if not re.search(r"[A-Z]", password):
        errors.append(
            "Password must contain an uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        errors.append(
            "Password must contain a lowercase letter."
        )

    if not re.search(r"\d", password):
        errors.append(
            "Password must contain a number."
        )

    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append(
            "Password must contain a special character."
        )

    return errors


# ============================================================
# AUTHENTICATION DECORATOR
# ============================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please log in to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# LOGIN RATE LIMITING
# ============================================================

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def is_account_locked(user):

    locked_until = user["locked_until"] or 0

    return time.time() < locked_until


def register_failed_attempt(user_id):

    db = get_db()

    user = db.execute(
        """
        SELECT failed_attempts
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    attempts = user["failed_attempts"] + 1

    if attempts >= MAX_FAILED_ATTEMPTS:

        locked_until = (
            time.time()
            + LOCKOUT_SECONDS
        )

        db.execute(
            """
            UPDATE users
            SET failed_attempts = 0,
                locked_until = ?
            WHERE id = ?
            """,
            (
                locked_until,
                user_id
            )
        )

    else:

        db.execute(
            """
            UPDATE users
            SET failed_attempts = ?
            WHERE id = ?
            """,
            (
                attempts,
                user_id
            )
        )

    db.commit()

    db.close()


def reset_failed_attempts(user_id):

    db = get_db()

    db.execute(
        """
        UPDATE users
        SET failed_attempts = 0,
            locked_until = 0
        WHERE id = ?
        """,
        (user_id,)
    )

    db.commit()

    db.close()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        if not validate_csrf():

            flash(
                "Invalid security token.",
                "danger"
            )

            return redirect(
                url_for("register")
            )


        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )


        # --------------------------------------------
        # Validate username
        # --------------------------------------------

        if not valid_username(username):

            flash(
                "Username must contain 3-30 letters, "
                "numbers, or underscores.",
                "danger"
            )

            return render_template(
                "register.html"
            )


        # --------------------------------------------
        # Validate email
        # --------------------------------------------

        if not valid_email(email):

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return render_template(
                "register.html"
            )


        # --------------------------------------------
        # Validate password
        # --------------------------------------------

        password_errors = validate_password(
            password
        )

        if password_errors:

            for error in password_errors:

                flash(
                    error,
                    "danger"
                )

            return render_template(
                "register.html"
            )


        # --------------------------------------------
        # Hash password
        # --------------------------------------------

        password_hash = generate_password_hash(
            password,
            method="scrypt"
        )


        # --------------------------------------------
        # Insert user
        #
        # Parameterized SQL prevents SQL injection.
        # --------------------------------------------

        db = get_db()

        try:

            db.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )

            db.commit()

        except sqlite3.IntegrityError:

            db.close()

            flash(
                "Username or email already exists.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        db.close()


        flash(
            "Registration successful. Please log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )


    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        if not validate_csrf():

            flash(
                "Invalid security token.",
                "danger"
            )

            return redirect(
                url_for("login")
            )


        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )


        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        db.close()


        if not user:

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )


        # --------------------------------------------
        # Account lock check
        # --------------------------------------------

        if is_account_locked(user):

            remaining = int(
                user["locked_until"]
                - time.time()
            )

            flash(
                f"Account temporarily locked. "
                f"Try again in about {remaining} seconds.",
                "danger"
            )

            return render_template(
                "login.html"
            )


        # --------------------------------------------
        # Password verification
        # --------------------------------------------

        if not check_password_hash(
            user["password_hash"],
            password
        ):

            register_failed_attempt(
                user["id"]
            )

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )


        # --------------------------------------------
        # Successful authentication
        # --------------------------------------------

        reset_failed_attempts(
            user["id"]
        )


        # Clear old session data
        session.clear()

        session["user_id"] = user["id"]

        session["username"] = user["username"]

        session["csrf_token"] = secrets.token_urlsafe(32)

        session.permanent = True


        # --------------------------------------------
        # 2FA
        # --------------------------------------------

        if user["two_factor_enabled"]:

            session["requires_2fa"] = True

            return redirect(
                url_for("verify_2fa")
            )


        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "login.html"
    )


# ============================================================
# 2FA VERIFICATION
# ============================================================

@app.route(
    "/verify-2fa",
    methods=["GET", "POST"]
)
def verify_2fa():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    if not session.get(
        "requires_2fa"
    ):

        return redirect(
            url_for("dashboard")
        )


    if request.method == "POST":

        if not validate_csrf():

            flash(
                "Invalid security token.",
                "danger"
            )

            return redirect(
                url_for("verify_2fa")
            )


        code = request.form.get(
            "code",
            ""
        ).strip()


        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],)
        ).fetchone()

        db.close()


        if not user:

            session.clear()

            return redirect(
                url_for("login")
            )


        totp = pyotp.TOTP(
            user["two_factor_secret"]
        )


        if not totp.verify(
            code,
            valid_window=1
        ):

            flash(
                "Invalid authentication code.",
                "danger"
            )

            return render_template(
                "login.html",
                two_factor=True
            )


        session.pop(
            "requires_2fa",
            None
        )

        session["authenticated"] = True


        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "login.html",
        two_factor=True
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    if session.get(
        "requires_2fa"
    ):

        return redirect(
            url_for("verify_2fa")
        )


    db = get_db()

    user = db.execute(
        """
        SELECT username,
               email,
               two_factor_enabled,
               created_at
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    db.close()


    return render_template(
        "dashboard.html",
        user=user
    )


# ============================================================
# 2FA SETUP
# ============================================================

@app.route(
    "/setup-2fa",
    methods=["GET", "POST"]
)
@login_required
def setup_2fa():

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()


    if request.method == "POST":

        if not validate_csrf():

            db.close()

            flash(
                "Invalid security token.",
                "danger"
            )

            return redirect(
                url_for("setup_2fa")
            )


        code = request.form.get(
            "code",
            ""
        ).strip()


        if not user["two_factor_secret"]:

            db.close()

            flash(
                "Please generate your 2FA setup first.",
                "danger"
            )

            return redirect(
                url_for("setup_2fa")
            )


        totp = pyotp.TOTP(
            user["two_factor_secret"]
        )


        if not totp.verify(
            code,
            valid_window=1
        ):

            db.close()

            flash(
                "Invalid authentication code.",
                "danger"
            )

            return redirect(
                url_for("setup_2fa")
            )


        db.execute(
            """
            UPDATE users
            SET two_factor_enabled = 1
            WHERE id = ?
            """,
            (user["id"],)
        )

        db.commit()

        db.close()


        flash(
            "Two-factor authentication enabled.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )


    # --------------------------------------------
    # Generate secret
    # --------------------------------------------

    if not user["two_factor_secret"]:

        secret = pyotp.random_base32()

        db.execute(
            """
            UPDATE users
            SET two_factor_secret = ?
            WHERE id = ?
            """,
            (
                secret,
                user["id"]
            )
        )

        db.commit()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (user["id"],)
        ).fetchone()


    db.close()


    issuer = "Secure Login System"

    account_name = (
        f"{issuer}:{user['email']}"
    )


    uri = pyotp.TOTP(
        user["two_factor_secret"]
    ).provisioning_uri(
        name=account_name,
        issuer_name=issuer
    )


    return render_template(
        "setup_2fa.html",
        secret=user["two_factor_secret"],
        uri=uri
    )


# ============================================================
# 2FA QR CODE
# ============================================================

@app.route("/2fa-qr")
@login_required
def two_factor_qr():

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    db.close()


    if not user or not user["two_factor_secret"]:

        return "2FA is not configured.", 404


    uri = pyotp.TOTP(
        user["two_factor_secret"]
    ).provisioning_uri(
        name=user["email"],
        issuer_name="Secure Login System"
    )


    image = qrcode.make(uri)


    path = "temp_2fa.png"

    image.save(path)


    return send_file(
        path,
        mimetype="image/png"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout",
    methods=["POST"]
)
@login_required
def logout():

    if not validate_csrf():

        flash(
            "Invalid security token.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    session.clear()


    flash(
        "You have been logged out.",
        "success"
    )


    return redirect(
        url_for("index")
    )


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "style-src 'self' "
        "https://cdn.jsdelivr.net; "
        "script-src 'self' "
        "https://cdn.jsdelivr.net; "
        "img-src 'self' data:;"
    )

    return response


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return (
        render_template(
            "index.html"
        ),
        404
    )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
