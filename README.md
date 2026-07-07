# 🛡️ PhishGuard — Email Phishing Detection System

A full-stack ML-powered phishing email detector with a cyberpunk UI, real-time analysis, and user authentication.

---

## 📁 Folder Structure

```
phishing-detector/
├── app.py                  # Flask backend
├── requirements.txt
├── README.md
├── model/
│   ├── spam_model.pkl      # Trained Naive Bayes model
│   └── vectorizer.pkl      # TF-IDF vectorizer
├── instance/
│   └── history.db          # SQLite DB (auto-created)
├── templates/
│   ├── index.html          # Main analyzer UI
│   ├── login.html
│   ├── signup.html
│   └── dashboard.html
└── static/
    ├── css/style.css
    └── js/main.js
```

---

## 🚀 Run Locally

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
python app.py
```

Visit: http://localhost:5000

---

## 🌐 Deploy to Render

1. Push your project to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your repo
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `gunicorn app:app`
6. Add environment variable: `SECRET_KEY=your-secret-key-here`
7. Deploy!

## 🌐 Deploy to Railway

1. Install Railway CLI: `npm install -g @railway/cli`
2. Login: `railway login`
3. Init: `railway init`
4. Deploy: `railway up`

---

## 🔌 API Endpoints

### POST /predict
Basic prediction endpoint.

**Request:**
```json
{ "text": "Congratulations! You won a lottery..." }
```

**Response:**
```json
{
  "prediction": "Phishing Email",
  "confidence": 92.4,
  "risk_level": "High"
}
```

### POST /analyze
Detailed analysis with keyword and URL extraction.

**Request:**
```json
{ "text": "..." }
```

**Response:**
```json
{
  "prediction": "Phishing Email",
  "is_phishing": true,
  "confidence": 92.4,
  "ml_confidence": 88.1,
  "risk_level": "High",
  "suspicious_words": ["lottery", "won", "claim", "urgent"],
  "suspicious_urls": [
    { "url": "http://claim-prize.tk/win", "suspicious": true }
  ]
}
```

### POST /upload
Upload a .txt email file for analysis.

---

## ⚙️ Environment Variables

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Flask session secret | `phishing-detector-secret-2024` |

---

## 🧠 How It Works

The system uses a **hybrid approach**:

1. **ML Model** (70% weight): Multinomial Naive Bayes trained on TF-IDF features
2. **Rule-based** (30% weight): Pattern matching for urgency words, phishing keywords, and suspicious URLs/domains

Final confidence = `ML score × 0.7 + Rule score × 0.3`

Risk levels:
- **High**: Confidence > 60% phishing + multiple suspicious indicators
- **Medium**: Moderate suspicion
- **Low**: Clean or likely safe

---

## 🔐 User Features

- Sign up / login (passwords hashed with SHA-256)
- Scan history saved per user in SQLite
- Analytics dashboard showing total / phishing / safe counts
- Dark/light mode toggle (persisted in localStorage)
