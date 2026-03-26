import os
import sqlite3
import datetime
import random
import jwt
import hashlib
import smtplib
import ssl
from email.message import EmailMessage
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

def load_local_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value

load_local_env()

app = Flask(__name__)
CORS(app)

DB_NAME = "privacy_activater.db"
SECRET_KEY = "my_super_secret_jwt_key"

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
APP_ENV = os.getenv("APP_ENV", "dev").lower()

HOST_EMAIL = os.getenv("HOST_EMAIL", "host@example.com")
HOST_PASSWORD = os.getenv("HOST_PASSWORD", "host123")

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        # Create Tables
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(100) NOT NULL,
            phone VARCHAR(15) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255),
            biometric_enabled BOOLEAN DEFAULT 0,
            pin_hash VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token VARCHAR(512) UNIQUE NOT NULL,
            device_info VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS otp_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            otp_hash VARCHAR(255) NOT NULL,
            sent_to_email VARCHAR(255) NOT NULL,
            purpose VARCHAR(50),
            verified BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sender VARCHAR(50) NOT NULL,
            body TEXT NOT NULL,
            category VARCHAR(10),
            is_phishing BOOLEAN DEFAULT 0,
            phishing_reason VARCHAR(255),
            is_read BOOLEAN DEFAULT 0,
            is_locked BOOLEAN DEFAULT 0,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS forwarding_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            status VARCHAR(50),
            forwarded_to VARCHAR(15),
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS phishing_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword VARCHAR(100) NOT NULL,
            severity VARCHAR(20),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS login_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email VARCHAR(255) NOT NULL,
            ip_address VARCHAR(64),
            user_agent VARCHAR(255),
            logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        db.commit()

        # Seed Keywords
        c.execute("SELECT count(*) FROM phishing_keywords")
        if c.fetchone()[0] == 0:
            keywords = [
                ("kyc expiring", "HIGH"),
                ("verify your account", "MEDIUM"),
                ("click this link", "HIGH"),
                ("update pan", "CRITICAL"),
                ("lottery winner", "LOW"),
                ("free gift", "LOW")
            ]
            c.executemany("INSERT INTO phishing_keywords (keyword, severity) VALUES (?, ?)", keywords)
            db.commit()

def hash_string(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def send_otp_email(to_email, otp, purpose):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS or not SMTP_FROM:
        if APP_ENV == "prod":
            raise RuntimeError("SMTP is not configured")
        # Dev mode: keep flow working without external email provider.
        print(f"[DEV MODE] OTP for {to_email} ({purpose}): {otp}")
        return {"delivery": "dev_console", "otp_preview": otp}

    msg = EmailMessage()
    msg["Subject"] = f"Your OTP for {purpose}" 
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(f"Your OTP is {otp}. It expires in 10 minutes.")

    context = ssl.create_default_context()
    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    return {"delivery": "email"}

def log_login(user_id, email):
    db = get_db()
    c = db.cursor()
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    c.execute(
        "INSERT INTO login_audit (user_id, email, ip_address, user_agent) VALUES (?, ?, ?, ?)",
        (user_id, email, ip_address, user_agent)
    )
    db.commit()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith("Bearer "):
            return jsonify({'message': 'Token is missing!'}), 401
        token = token.split(" ")[1]
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            db = get_db()
            user = db.cursor().execute("SELECT * FROM users WHERE id = ?", (data['user_id'],)).fetchone()
            if not user:
                raise Exception("User not found")
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(user, *args, **kwargs)
    return decorated

@app.route('/api/auth/otp/send', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')
    purpose = data.get('purpose', 'LOGIN') # LOGIN or SIGNUP
    name = data.get('name')
    phone = data.get('phone')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    db = get_db()
    c = db.cursor()

    user = c.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    user_id = user['id'] if user else None

    if purpose == 'SIGNUP' and user_id is not None:
        return jsonify({"error": "User already exists with this email"}), 400
    if purpose == 'LOGIN' and user_id is None:
        return jsonify({"error": "No user found with this email"}), 404

    otp = str(random.randint(100000, 999999))
    # Hack for demo/testing so we don't have to guess
    if email == 'test@example.com':
        otp = '123456'
        
    otp_hash = hash_string(otp)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    
    # Store registration details temporarily in the purpose field if SIGNUP, or we can just sendOTP to an unverified entry.
    # We will just pass them to verify via client.
    
    c.execute("INSERT INTO otp_logs (user_id, otp_hash, sent_to_email, purpose, expires_at) VALUES (?, ?, ?, ?, ?)",
              (user_id, otp_hash, email, purpose, expires_at.strftime('%Y-%m-%d %H:%M:%S')))
    db.commit()
    
    try:
        delivery = send_otp_email(email, otp, purpose)
    except Exception as exc:
        return jsonify({"error": f"Failed to send OTP email: {exc}"}), 500

    response = {
        "message": f"OTP sent to {email}",
        "delivery": delivery.get("delivery", "unknown")
    }
    if response["delivery"] == "dev_console":
        response["message"] = f"OTP generated for {email}. Check server console in dev mode."
        response["otp_preview"] = delivery.get("otp_preview")
    return jsonify(response)

@app.route('/api/auth/otp/verify', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    purpose = data.get('purpose', 'LOGIN')
    name = data.get('name')
    phone = data.get('phone')

    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400

    otp_hash = hash_string(otp)
    db = get_db()
    c = db.cursor()

    log = c.execute("""SELECT * FROM otp_logs 
                       WHERE sent_to_email = ? AND otp_hash = ? AND purpose = ? AND verified = 0 
                       ORDER BY created_at DESC LIMIT 1""", 
                    (email, otp_hash, purpose)).fetchone()

    if not log:
        return jsonify({"error": "Invalid or expired OTP"}), 400
        
    c.execute("UPDATE otp_logs SET verified = 1 WHERE id = ?", (log['id'],))

    if purpose == 'SIGNUP':
        if not name or not phone:
            return jsonify({"error": "Name and phone required for signup"}), 400
        c.execute("INSERT INTO users (name, phone, email) VALUES (?, ?, ?)", (name, phone, email))
        user_id = c.lastrowid
        db.commit()
        
        # Seed some messages for demo
        seed_messages(user_id)
        
    elif purpose == 'LOGIN':
        user = c.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        user_id = user['id']
        log_login(user_id, email)

    token = jwt.encode({
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")
    
    db.commit()
    return jsonify({"token": token, "message": "Verification successful"})

@app.route('/api/host/login', methods=['POST'])
def host_login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")
    if email != HOST_EMAIL or password != HOST_PASSWORD:
        return jsonify({"error": "Invalid host credentials"}), 401

    token = jwt.encode({
        "host": True,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)
    }, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

def host_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith("Bearer "):
            return jsonify({'message': 'Token is missing!'}), 401
        token = token.split(" ")[1]
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if not data.get("host"):
                raise Exception("Not host token")
        except Exception:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/host/logins', methods=['GET'])
@host_token_required
def host_logins():
    db = get_db()
    c = db.cursor()
    rows = c.execute(
        "SELECT id, email, ip_address, user_agent, logged_at FROM login_audit ORDER BY id DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/host/users', methods=['GET'])
@host_token_required
def host_users():
    db = get_db()
    c = db.cursor()
    rows = c.execute(
        "SELECT id, name, phone, email, created_at FROM users ORDER BY id DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

def seed_messages(user_id):
    db = get_db()
    c = db.cursor()
    msgs = [
        (user_id, 'AD-ZOMATO', 'Get 50% flat discount on your next order! Use code CRRAVE.', 'P', 0, None, 0, 0),
        (user_id, 'DM-MYNTRA', 'End of reason sale is LIVE! Shop now.', 'P', 0, None, 0, 0),
        (user_id, 'AM-JIO', 'Your data plan is about to expire. Recharge now.', 'S', 0, None, 0, 0),
        (user_id, 'BZ-HDFCBK', 'Your OTP for transaction of Rs. 4,999 is 482109. Never share it.', 'T', 0, None, 0, 1),
        (user_id, 'AX-AXISBK', 'Payment of Rs. 2,000 made to Amazon India.', 'T', 0, None, 0, 0),
        (user_id, 'UIDAI', 'Your Aadhaar is linked with +91-XXXXX1234. Ignore if not done by you.', 'G', 1, 'Suspicious Link detected', 0, 1)
    ]
    c.executemany("INSERT INTO messages (user_id, sender, body, category, is_phishing, phishing_reason, is_read, is_locked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", msgs)
    db.commit()

@app.route('/api/user/messages', methods=['GET'])
@token_required
def get_messages(user):
    db = get_db()
    c = db.cursor()
    msgs = c.execute("SELECT * FROM messages WHERE user_id = ? ORDER BY id DESC", (user['id'],)).fetchall()
    return jsonify([dict(m) for m in msgs])

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_stats(user):
    return jsonify({
        "secure_percentage": 98,
        "last_scan": "2 mins ago",
        "threats_blocked": 12,
        "email_shield_active": True,
        "sms_monitor_active": True
    })

@app.route('/api/call-forwarding/check', methods=['POST'])
@token_required
def check_forwarding(user):
    # Simulate compromise
    db = get_db()
    c = db.cursor()
    c.execute("INSERT INTO forwarding_checks (user_id, status, forwarded_to) VALUES (?, ?, ?)", 
              (user['id'], 'COMPROMISED', '+919800000001'))
    db.commit()
    return jsonify({"status": "COMPROMISED", "forwarded_to": "+919800000001"})

@app.route('/api/call-forwarding/disable', methods=['POST'])
@token_required
def disable_forwarding(user):
    db = get_db()
    c = db.cursor()
    c.execute("INSERT INTO forwarding_checks (user_id, status) VALUES (?, ?)", 
              (user['id'], 'SAFE'))
    db.commit()
    return jsonify({"status": "SAFE", "message": "Forwarding disabled successfully"})

@app.route('/')
def serve_home():
    from flask import send_from_directory
    import os
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'landingpage.html')

@app.route('/<path:path>')
def serve_static(path):
    from flask import send_from_directory
    import os
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(base_dir, path)):
        return send_from_directory(base_dir, path)
    if os.path.exists(os.path.join(base_dir, path + '.html')):
        return send_from_directory(base_dir, path + '.html')
    return "Not Found", 404

if __name__ == '__main__':
    if not os.path.exists(DB_NAME):
        with app.app_context():
            get_db()
    init_db()
    app.run(debug=True, port=8000)
