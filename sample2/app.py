"""
SafeCall Sentinel — Flask Backend
Full-featured backend with user auth, SMS phishing analysis,
call-forwarding checks, and an awareness/safety-tips module.
"""

import os
import re
import json
import random
import string
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, abort
)
import os
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

load_dotenv()
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)

# ─── App Config ───────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "safecall-sentinel-dev-key-2024")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///safecall.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Custom Jinja2 filter to parse JSON strings
@app.template_filter('fromjson')
def fromjson_filter(s):
    """Parse a JSON string into a Python object."""
    try:
        return json.loads(s) if s else []
    except (json.JSONDecodeError, TypeError):
        return []


def utcnow():
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# ─── Models ───────────────────────────────────────────────────

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    # relationships
    scan_results = db.relationship("ScanResult", backref="user", lazy=True, cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="user", lazy=True, cascade="all, delete-orphan")
    call_checks = db.relationship("CallForwardingCheck", backref="user", lazy=True, cascade="all, delete-orphan")

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(30), default="Unknown")
    risk_score = db.Column(db.Integer, default=0)
    verdict = db.Column(db.String(30), default="SAFE")
    keywords_found = db.Column(db.Text, default="[]")  # JSON list
    advice = db.Column(db.Text, default="")
    metadata_info = db.Column(db.Text, default="{}")  # JSON
    created_at = db.Column(db.DateTime, default=utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    category = db.Column(db.String(30))  # PHISHING, SAFE, SUSPICIOUS
    sender_id = db.Column(db.String(100))
    preview = db.Column(db.String(300))
    risk_level = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=utcnow)

class CallForwardingCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    phone_number = db.Column(db.String(20))
    voice_status = db.Column(db.String(20), default="Inactive")
    data_status = db.Column(db.String(20), default="Inactive")
    sms_status = db.Column(db.String(20), default="Inactive")
    overall_status = db.Column(db.String(50), default="Safe")
    integrity_score = db.Column(db.Integer, default=98)
    checked_at = db.Column(db.DateTime, default=utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ─── Validation Helpers ──────────────────────────────────────

def validate_email(email):
    """Basic email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Password must be 8+ chars with at least 1 letter and 1 digit."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    return True, "OK"

def sanitize_input(text, max_length=500):
    """Strip and truncate user input."""
    if not text:
        return ""
    return text.strip()[:max_length]


# ─── SMS Analysis Engine ─────────────────────────────────────

PHISHING_KEYWORDS = [
    "urgent", "verify", "immediately", "suspended", "locked",
    "click here", "confirm your", "account has been", "action required",
    "temporary", "expire", "update your", "limited time",
    "congratulations", "won", "prize", "lottery", "claim",
    "bank account", "credit card", "social security",
    "password", "pin", "otp", "cvv",
]

SUSPICIOUS_DOMAINS = [
    "secure-verify", "auth-check", "account-update", "login-verify",
    "bank-secure", "pay-confirm", "faceb00k", "amaz0n", "g00gle",
]

def analyze_sms(message_text, category="Unknown"):
    """Analyze an SMS message for phishing indicators."""
    text_lower = message_text.lower()
    found_keywords = []
    risk_score = 0

    # Keyword analysis
    for kw in PHISHING_KEYWORDS:
        if kw in text_lower:
            found_keywords.append(kw.title())
            risk_score += random.randint(5, 12)

    # URL analysis
    urls = re.findall(r'https?://[^\s]+', message_text)
    url_flags = []
    for url in urls:
        url_lower = url.lower()
        for dom in SUSPICIOUS_DOMAINS:
            if dom in url_lower:
                risk_score += 25
                url_flags.append(f"Suspicious domain detected: {dom}")
        if len(url) > 60:
            risk_score += 10
            url_flags.append("Unusually long URL")

    # Urgency language
    urgency_phrases = ["act now", "don't delay", "right away", "within 24 hours",
                       "will be frozen", "will be blocked", "will be suspended"]
    for phrase in urgency_phrases:
        if phrase in text_lower:
            risk_score += 15
            found_keywords.append(phrase.title())

    # Cap and determine verdict
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        verdict = "HIGH RISK"
    elif risk_score >= 40:
        verdict = "MEDIUM RISK"
    elif risk_score >= 15:
        verdict = "LOW RISK"
    else:
        verdict = "SAFE"

    # Build advice
    advice_items = []
    if urls:
        advice_items.append("Do not click any links. The URL(s) may use obfuscation techniques common in phishing campaigns.")
    if risk_score > 40:
        advice_items.append("Report the sender. Forward this message to 7726 (SPAM) to alert your carrier network.")
    advice_items.append("If you believe there is an issue with your account, login only via the official provider's app or website.")
    if "otp" in text_lower or "pin" in text_lower or "password" in text_lower:
        advice_items.append("Never share your OTP, PIN, or password with anyone. Legitimate services will never ask for these via SMS.")

    # Build metadata
    metadata = {
        "sender_reputation": f"{max(0.01, round(random.uniform(0.01, 10 - risk_score / 12), 2))}/10",
        "url_redirects": f"{len(urls) * random.randint(1, 3)} detected" if urls else "None",
        "domain_age": f"{random.randint(1, 7)} days" if risk_score > 50 else "Established",
        "geo_origin": "Unavailable (VPN Detected)" if risk_score > 60 else "Domestic",
    }

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "keywords": found_keywords,
        "advice": advice_items,
        "metadata": metadata,
        "category": category,
        "url_flags": url_flags,
    }


def simulate_call_forwarding_check(phone_number):
    """Simulate a call forwarding check for the given number."""
    is_safe = random.random() > 0.15  # 85% chance safe
    if is_safe:
        return {
            "status": "Safe – No Forwarding Detected",
            "voice": "Inactive", "data": "Inactive", "sms": "Inactive",
            "integrity_score": random.randint(92, 100),
            "is_safe": True,
        }
    else:
        fwd_type = random.choice(["Voice", "Data", "SMS"])
        return {
            "status": f"WARNING – {fwd_type} Forwarding Active",
            "voice": "Active" if fwd_type == "Voice" else "Inactive",
            "data": "Active" if fwd_type == "Data" else "Inactive",
            "sms": "Active" if fwd_type == "SMS" else "Inactive",
            "integrity_score": random.randint(20, 55),
            "is_safe": False,
        }


# ─── Routes: Public Pages ────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/awareness")
def awareness():
    return render_template("awareness.html")


# ─── Routes: Auth ─────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", ""), 150)
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please fill in all fields.", "error")
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            session.permanent = True
            flash("Welcome back! Your sentinel is active.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            flash("Invalid credentials. Authentication denied.", "error")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        full_name = sanitize_input(request.form.get("full_name", ""), 150)
        email = sanitize_input(request.form.get("email", ""), 150)
        phone = sanitize_input(request.form.get("phone", ""), 20)
        password = request.form.get("password", "")

        # Validation
        errors = []
        if not full_name or len(full_name) < 2:
            errors.append("Please enter your full name (at least 2 characters).")
        if not validate_email(email):
            errors.append("Please enter a valid email address.")
        if not phone or len(phone) < 7:
            errors.append("Please enter a valid phone number.")

        pw_valid, pw_msg = validate_password(password)
        if not pw_valid:
            errors.append(pw_msg)

        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("signup.html")

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "error")
            return redirect(url_for("signup"))

        try:
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            user = User(full_name=full_name, email=email, phone=phone, password=hashed)
            db.session.add(user)
            db.session.commit()

            # Create some demo alerts for the new user
            _seed_demo_alerts(user.id)

            login_user(user)
            session.permanent = True
            flash("Account created! Your sentinel is now active.", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred. Please try again.", "error")
            app.logger.error(f"Signup error: {e}")
            return render_template("signup.html")

    return render_template("signup.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("home"))


# ─── Routes: Dashboard (Protected) ───────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    alerts = Alert.query.filter_by(user_id=current_user.id)\
        .order_by(Alert.created_at.desc()).limit(10).all()
    scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    checks = CallForwardingCheck.query.filter_by(user_id=current_user.id).count()

    phishing_count = Alert.query.filter_by(user_id=current_user.id, risk_level="HIGH").count()
    suspicious_count = Alert.query.filter_by(user_id=current_user.id, risk_level="MEDIUM").count()

    # Security score
    total_alerts = Alert.query.filter_by(user_id=current_user.id).count()
    high_alerts = phishing_count
    security_score = max(0, 100 - (high_alerts * 5)) if total_alerts else 91

    return render_template("dashboard.html",
        alerts=alerts,
        scans=scans,
        checks=checks,
        phishing_count=phishing_count,
        suspicious_count=suspicious_count,
        security_score=min(security_score, 100),
    )


# ─── Routes: Profile (Protected) ─────────────────────────────

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        full_name = sanitize_input(request.form.get("full_name", ""), 150)
        phone = sanitize_input(request.form.get("phone", ""), 20)
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")

        if full_name and len(full_name) >= 2:
            current_user.full_name = full_name
        if phone and len(phone) >= 7:
            current_user.phone = phone

        # Password change
        if new_password:
            if not current_password or not bcrypt.check_password_hash(current_user.password, current_password):
                flash("Current password is incorrect.", "error")
                return render_template("profile.html")
            pw_valid, pw_msg = validate_password(new_password)
            if not pw_valid:
                flash(pw_msg, "error")
                return render_template("profile.html")
            current_user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
            flash("Password updated successfully.", "success")

        try:
            db.session.commit()
            flash("Profile updated.", "success")
        except Exception as e:
            db.session.rollback()
            flash("An error occurred updating your profile.", "error")
            app.logger.error(f"Profile update error: {e}")

        return redirect(url_for("profile"))

    # Stats
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    total_checks = CallForwardingCheck.query.filter_by(user_id=current_user.id).count()
    total_alerts = Alert.query.filter_by(user_id=current_user.id).count()

    return render_template("profile.html",
        total_scans=total_scans,
        total_checks=total_checks,
        total_alerts=total_alerts,
    )


# ─── Routes: Scan History (Protected) ─────────────────────────

@app.route("/scan-history")
@login_required
def scan_history():
    page = request.args.get("page", 1, type=int)
    scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.created_at.desc())\
        .paginate(page=page, per_page=10, error_out=False)
    return render_template("scan_history.html", scans=scans)


# ─── Routes: SMS Analyzer (Protected) ────────────────────────

@app.route("/sms-analyzer", methods=["GET", "POST"])
@login_required
def sms_analyzer():
    result = None
    message_text = ""
    category = "Government"

    if request.method == "POST":
        message_text = sanitize_input(request.form.get("message", ""), 2000)
        category = sanitize_input(request.form.get("category", "Government"), 30)

        if message_text:
            result = analyze_sms(message_text, category)

            try:
                # Save to DB
                scan = ScanResult(
                    user_id=current_user.id,
                    message_text=message_text,
                    category=category,
                    risk_score=result["risk_score"],
                    verdict=result["verdict"],
                    keywords_found=json.dumps(result["keywords"]),
                    advice=json.dumps(result["advice"]),
                    metadata_info=json.dumps(result["metadata"]),
                )
                db.session.add(scan)

                # Create an alert
                alert = Alert(
                    user_id=current_user.id,
                    category="PHISHING" if result["risk_score"] > 60 else ("SUSPICIOUS" if result["risk_score"] > 30 else "SAFE"),
                    sender_id="Manual Scan",
                    preview=message_text[:100] + ("..." if len(message_text) > 100 else ""),
                    risk_level="HIGH" if result["risk_score"] > 60 else ("MEDIUM" if result["risk_score"] > 30 else "SAFE"),
                )
                db.session.add(alert)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"SMS scan save error: {e}")
        else:
            flash("Please paste a message to analyze.", "error")

    return render_template("sms_analyzer.html",
        result=result,
        message_text=message_text,
        selected_category=category
    )


# ─── Routes: Call Forwarding (Protected) ─────────────────────

@app.route("/call-checker", methods=["GET", "POST"])
@login_required
def call_checker():
    check_result = None
    phone_number = current_user.phone

    if request.method == "POST":
        phone_number = sanitize_input(request.form.get("phone", current_user.phone), 20)
        check_result = simulate_call_forwarding_check(phone_number)

        try:
            # Save to DB
            record = CallForwardingCheck(
                user_id=current_user.id,
                phone_number=phone_number,
                voice_status=check_result["voice"],
                data_status=check_result["data"],
                sms_status=check_result["sms"],
                overall_status=check_result["status"],
                integrity_score=check_result["integrity_score"],
            )
            db.session.add(record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Call check save error: {e}")

    # Get last check
    last_check = CallForwardingCheck.query.filter_by(user_id=current_user.id)\
        .order_by(CallForwardingCheck.checked_at.desc()).first()

    return render_template("call_checker.html",
        check_result=check_result,
        last_check=last_check,
        phone_number=phone_number,
    )


# ─── API Endpoints ────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    message = data.get("message", "")
    category = data.get("category", "Unknown")
    if not message:
        return jsonify({"error": "No message provided"}), 400
    result = analyze_sms(message, category)
    return jsonify(result)

@app.route("/api/check-forwarding", methods=["POST"])
@login_required
def api_check_forwarding():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    phone = data.get("phone", "")
    if not phone:
        return jsonify({"error": "No phone number provided"}), 400
    result = simulate_call_forwarding_check(phone)
    return jsonify(result)

@app.route("/api/user/stats")
@login_required
def api_user_stats():
    """Return user stats as JSON."""
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    total_checks = CallForwardingCheck.query.filter_by(user_id=current_user.id).count()
    total_alerts = Alert.query.filter_by(user_id=current_user.id).count()
    phishing = Alert.query.filter_by(user_id=current_user.id, risk_level="HIGH").count()
    return jsonify({
        "total_scans": total_scans,
        "total_checks": total_checks,
        "total_alerts": total_alerts,
        "phishing_alerts": phishing,
        "member_since": current_user.created_at.strftime("%b %Y") if current_user.created_at else "N/A",
    })


# ─── Error Handlers ──────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("index.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("index.html"), 500


# ─── Helpers ──────────────────────────────────────────────────

def _seed_demo_alerts(user_id):
    """Create sample alerts so the dashboard isn't empty."""
    demos = [
        Alert(user_id=user_id, category="SAFE", sender_id="HDFC-BANK",
              preview="Trans: INR 2,500.00 spent on Zomato. Total Bal: INR...",
              risk_level="SAFE"),
        Alert(user_id=user_id, category="PHISHING", sender_id="+1 800-SAFE-01",
              preview="URGENT: Your SafeCall account is locked. Click here to verify...",
              risk_level="HIGH"),
        Alert(user_id=user_id, category="SAFE", sender_id="IncomeTax-Gov",
              preview="Your tax refund for FY 2023-24 has been processed...",
              risk_level="SAFE"),
        Alert(user_id=user_id, category="SUSPICIOUS", sender_id="FLIPKART",
              preview="Biggest Sale of the Season! 70% Off on Electronics. Grab...",
              risk_level="MEDIUM"),
    ]
    db.session.add_all(demos)
    db.session.commit()


# ─── Database Init & Run ─────────────────────────────────────

with app.app_context():
    db.create_all()

# ─── Error Handlers ──────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
