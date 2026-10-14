"""Flask app: registration, login (JWT), token refresh, logout and protected profile routes."""
from datetime import timedelta

import jwt
from flask import Flask, g, jsonify, render_template, request

import security
from config import Config
from models import LoginLog, RefreshToken, User, db, utcnow


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    with app.app_context():
        db.create_all()

    # ------------------------------------------------------------ helpers
    def get_text(data, key):
        value = data.get(key)
        return value.strip() if isinstance(value, str) else ""

    def log_attempt(email, success, user=None):
        db.session.add(LoginLog(user_id=user.id if user else None, email=email[:120],
                                success=success, ip_address=request.remote_addr))
        db.session.commit()

    def issue_tokens(user):
        access = security.create_access_token(user.id)
        refresh = security.create_refresh_token(user.id)
        RefreshToken.query.filter(RefreshToken.user_id == user.id,
                                  RefreshToken.expires_at < utcnow()).delete()  # cleanup
        db.session.add(RefreshToken(
            user_id=user.id,
            token_hash=security.hash_token(refresh),
            expires_at=utcnow() + timedelta(days=Config.REFRESH_TOKEN_DAYS),
        ))
        db.session.commit()
        return {"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
                "expires_in": Config.ACCESS_TOKEN_MINUTES * 60}

    def revoke_all(user_id):
        RefreshToken.query.filter_by(user_id=user_id, revoked=False).update({"revoked": True})
        db.session.commit()

    def profile_json(user):
        return {"id": user.id, "username": user.username, "email": user.email,
                "phone": security.decrypt(user.phone_encrypted),
                "created_at": user.created_at.isoformat() + "Z"}

    # ------------------------------------------------------------ security headers
    @app.after_request
    def add_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------ pages
    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/health")
    def health():
        return jsonify(status="ok")

    # ------------------------------------------------------------ auth API
    @app.route("/api/register", methods=["POST"])
    def register():
        data = request.get_json(silent=True) or {}
        username = get_text(data, "username")
        email = get_text(data, "email").lower()
        password = data.get("password") if isinstance(data.get("password"), str) else ""

        errors = []
        if not security.USERNAME_RE.match(username):
            errors.append("Username must be 3-30 characters (letters, numbers, underscore).")
        if not security.EMAIL_RE.match(email) or len(email) > 120:
            errors.append("Enter a valid email address.")
        missing = security.password_errors(password)
        if missing:
            errors.append("Password needs: " + ", ".join(missing) + ".")
        if errors:
            return jsonify(error=" ".join(errors)), 400

        if User.query.filter_by(email=email).first():
            return jsonify(error="This email is already registered."), 409

        user = User(username=username, email=email, password_hash=security.hash_password(password))
        db.session.add(user)
        db.session.commit()
        return jsonify(message="Registration successful. You can log in now.", user=profile_json(user)), 201

    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        email = get_text(data, "email").lower()
        password = data.get("password") if isinstance(data.get("password"), str) else ""
        invalid = (jsonify(error="Invalid email or password."), 401)

        user = User.query.filter_by(email=email).first()
        if not user:
            security.check_password(password, security.DUMMY_HASH.decode())  # constant-time-ish
            log_attempt(email, False)
            return invalid

        if user.locked_until and user.locked_until > utcnow():
            log_attempt(email, False, user)
            return jsonify(error=f"Account locked for {Config.LOCKOUT_MINUTES} minutes "
                                 "after too many failed attempts. Try again later."), 429

        if not security.check_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= Config.MAX_FAILED_ATTEMPTS:
                user.locked_until = utcnow() + timedelta(minutes=Config.LOCKOUT_MINUTES)
                user.failed_attempts = 0
            db.session.commit()
            log_attempt(email, False, user)
            return invalid

        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()
        log_attempt(email, True, user)
        return jsonify(message="Login successful.", **issue_tokens(user), user=profile_json(user))

    @app.route("/api/refresh", methods=["POST"])
    def refresh():
        data = request.get_json(silent=True) or {}
        token = data.get("refresh_token") if isinstance(data.get("refresh_token"), str) else ""
        try:
            payload = security.decode_token(token, "refresh")
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid or expired refresh token."), 401

        record = RefreshToken.query.filter_by(token_hash=security.hash_token(token)).first()
        if not record:
            return jsonify(error="Invalid or expired refresh token."), 401
        if record.revoked:
            # An already-used token came back -> it may be stolen. Kill every session of this user.
            revoke_all(record.user_id)
            return jsonify(error="Refresh token reuse detected. Please log in again."), 401
        if record.expires_at < utcnow():
            return jsonify(error="Invalid or expired refresh token."), 401

        user = db.session.get(User, int(payload["sub"]))
        record.revoked = True  # rotation: every refresh token can be used only once
        db.session.commit()
        return jsonify(**issue_tokens(user))

    @app.route("/api/logout", methods=["POST"])
    def logout():
        data = request.get_json(silent=True) or {}
        token = data.get("refresh_token") if isinstance(data.get("refresh_token"), str) else ""
        record = RefreshToken.query.filter_by(token_hash=security.hash_token(token)).first()
        if record:
            record.revoked = True
            db.session.commit()
        return jsonify(message="Logged out.")

    @app.route("/api/logout-all", methods=["POST"])
    @security.token_required
    def logout_all():
        revoke_all(g.user.id)
        return jsonify(message="Logged out from all devices.")

    # ------------------------------------------------------------ protected API
    @app.route("/api/profile", methods=["GET"])
    @security.token_required
    def get_profile():
        return jsonify(profile_json(g.user))

    @app.route("/api/profile", methods=["PUT"])
    @security.token_required
    def update_profile():
        data = request.get_json(silent=True) or {}
        phone = get_text(data, "phone")
        if phone and not security.PHONE_RE.match(phone):
            return jsonify(error="Enter a valid phone number."), 400
        g.user.phone_encrypted = security.encrypt(phone)  # stored encrypted
        db.session.commit()
        return jsonify(message="Profile updated.", user=profile_json(g.user))

    @app.route("/api/change-password", methods=["POST"])
    @security.token_required
    def change_password():
        data = request.get_json(silent=True) or {}
        old = data.get("old_password") if isinstance(data.get("old_password"), str) else ""
        new = data.get("new_password") if isinstance(data.get("new_password"), str) else ""
        if not security.check_password(old, g.user.password_hash):
            return jsonify(error="Current password is incorrect."), 400
        missing = security.password_errors(new)
        if missing:
            return jsonify(error="New password needs: " + ", ".join(missing) + "."), 400
        g.user.password_hash = security.hash_password(new)
        db.session.commit()
        revoke_all(g.user.id)  # force login again on every device
        return jsonify(message="Password changed. Please log in again.")

    @app.route("/api/login-history", methods=["GET"])
    @security.token_required
    def login_history():
        logs = (LoginLog.query.filter_by(user_id=g.user.id)
                .order_by(LoginLog.id.desc()).limit(10).all())
        return jsonify([{"success": l.success, "ip": l.ip_address,
                         "time": l.created_at.isoformat() + "Z"} for l in logs])

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
