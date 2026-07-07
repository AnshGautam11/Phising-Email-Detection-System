from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
import pickle
import os
import re
import sqlite3
import json
import hashlib
import warnings
from datetime import datetime

warnings.filterwarnings("ignore")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phishing-detector-secret-2024")

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "instance", "history.db")

# ─── Load Model ───────────────────────────────────────────────────────────────
with open(os.path.join(BASE_DIR, "model", "spam_model.pkl"), "rb") as f:
    model = pickle.load(f)
with open(os.path.join(BASE_DIR, "model", "vectorizer.pkl"), "rb") as f:
    vectorizer = pickle.load(f)

print("✅ Model loaded")

# ─── Phishing Patterns ────────────────────────────────────────────────────────
URGENCY_WORDS = [
    "urgent", "immediately", "act now", "limited time", "expires", "deadline",
    "final notice", "last chance", "don't delay", "respond now", "time sensitive",
    "account suspended", "verify now", "confirm immediately", "action required",
    "alert", "warning", "critical", "important notice"
]

PHISHING_KEYWORDS = [
    "lottery", "winner", "prize", "claim", "won", "congratulations",
    "free gift", "click here", "verify your account", "update your information",
    "bank account", "credit card", "ssn", "social security", "password",
    "login credentials", "unusual activity", "suspicious activity",
    "wire transfer", "western union", "money order", "inheritance",
    "nigerian prince", "million dollars", "investment opportunity"
]

URL_PATTERN = re.compile(
    r'(https?://[^\s]+|www\.[^\s]+|\b[a-z0-9-]+\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|click|loan|win|download|stream)\b)',
    re.IGNORECASE
)

SUSPICIOUS_DOMAINS = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'short.link',
                       '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email_text TEXT NOT NULL,
        prediction TEXT NOT NULL,
        confidence REAL NOT NULL,
        risk_level TEXT NOT NULL,
        suspicious_words TEXT,
        suspicious_urls TEXT,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

init_db()

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ─── ML Utilities ─────────────────────────────────────────────────────────────
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def find_suspicious_words(text):
    text_lower = text.lower()
    found = []
    for w in URGENCY_WORDS + PHISHING_KEYWORDS:
        if w in text_lower:
            found.append(w)
    return list(set(found))

def find_suspicious_urls(text):
    urls = URL_PATTERN.findall(text)
    result = []
    for u in urls:
        url = u[0] if isinstance(u, tuple) else u
        is_suspicious = any(d in url.lower() for d in SUSPICIOUS_DOMAINS)
        result.append({"url": url, "suspicious": is_suspicious})
    return result

def compute_risk_level(confidence, is_phishing, sus_words, sus_urls):
    if not is_phishing:
        if confidence > 0.9:
            return "Low"
        return "Low"
    
    score = 0
    score += min(len(sus_words) * 10, 40)
    score += min(len([u for u in sus_urls if u["suspicious"]]) * 15, 30)
    score += confidence * 30

    if score < 30:
        return "Low"
    elif score < 60:
        return "Medium"
    else:
        return "High"

def rule_based_score(text):
    text_lower = text.lower()
    score = 0
    hits = []
    for w in URGENCY_WORDS:
        if w in text_lower:
            score += 5
            hits.append(w)
    for w in PHISHING_KEYWORDS:
        if w in text_lower:
            score += 8
            hits.append(w)
    urls = URL_PATTERN.findall(text)
    for u in urls:
        url = u[0] if isinstance(u, tuple) else u
        if any(d in url.lower() for d in SUSPICIOUS_DOMAINS):
            score += 15
    return min(score / 100, 1.0), hits

def analyze_email(text):
    cleaned = clean_text(text)
    vector = vectorizer.transform([cleaned])
    prediction = model.predict(vector)[0]
    proba = model.predict_proba(vector)[0]

    phishing_idx = list(model.classes_).index("Phishing Email")
    ml_confidence = float(proba[phishing_idx])

    rule_score, _ = rule_based_score(text)
    hybrid_confidence = ml_confidence * 0.7 + rule_score * 0.3

    is_phishing = hybrid_confidence > 0.5
    final_label = "Phishing Email" if is_phishing else "Safe Email"
    final_confidence = hybrid_confidence if is_phishing else (1 - hybrid_confidence)

    sus_words = find_suspicious_words(text)
    sus_urls = find_suspicious_urls(text)
    risk_level = compute_risk_level(hybrid_confidence, is_phishing, sus_words, sus_urls)

    return {
        "prediction": final_label,
        "is_phishing": is_phishing,
        "confidence": round(final_confidence * 100, 2),
        "ml_confidence": round(ml_confidence * 100, 2),
        "risk_level": risk_level,
        "suspicious_words": sus_words,
        "suspicious_urls": sus_urls,
    }

def save_scan(user_id, text, result):
    conn = get_db()
    conn.execute(
        '''INSERT INTO scan_history (user_id, email_text, prediction, confidence, risk_level, suspicious_words, suspicious_urls)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (user_id, text[:2000], result["prediction"], result["confidence"],
         result["risk_level"], json.dumps(result["suspicious_words"]),
         json.dumps(result["suspicious_urls"]))
    )
    conn.commit()
    conn.close()

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND password=?",
                            (username, hash_password(password))).fetchone()
        conn.close()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required")
            return render_template("signup.html")
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                         (username, hash_password(password)))
            conn.commit()
            flash("Account created! Please login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists")
        finally:
            conn.close()
    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    history = conn.execute(
        "SELECT * FROM scan_history WHERE user_id=? ORDER BY scanned_at DESC LIMIT 20",
        (session["user_id"],)
    ).fetchall()
    stats = conn.execute(
        '''SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN prediction='Phishing Email' THEN 1 ELSE 0 END) as phishing,
            SUM(CASE WHEN prediction='Safe Email' THEN 1 ELSE 0 END) as safe
           FROM scan_history WHERE user_id=?''',
        (session["user_id"],)
    ).fetchone()
    conn.close()
    return render_template("dashboard.html", history=history, stats=stats)

# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    result = analyze_email(text)
    user_id = session.get("user_id")
    save_scan(user_id, text, result)

    return jsonify({
        "input": text[:200],
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "risk_level": result["risk_level"],
    })

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    result = analyze_email(text)
    user_id = session.get("user_id")
    save_scan(user_id, text, result)

    return jsonify(result)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file provided"}), 400
    text = file.read().decode("utf-8", errors="ignore")
    result = analyze_email(text)
    user_id = session.get("user_id")
    save_scan(user_id, text, result)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
