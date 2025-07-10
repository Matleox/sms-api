from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
import sqlite3
import jwt
import requests
import time
from datetime import datetime, timedelta

app = FastAPI()
SECRET_KEY = "super-secret-key"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
LIMIT_FILE = "limits.json"
SETTINGS_DB = "settings.db"

def get_db():
    conn = sqlite3.connect(SETTINGS_DB)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with sqlite3.connect(SETTINGS_DB) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                key TEXT PRIMARY KEY,
                user_id TEXT,
                expiry_date TEXT,
                is_admin BOOLEAN
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sms_limits (
                user_id TEXT,
                date TEXT,
                count INTEGER
            )
        ''')

init_db()

@app.post("/login")
async def login(data: dict, db: sqlite3.Connection = Depends(get_db)):
    key = data.get("key")
    cursor = db.execute("SELECT * FROM users WHERE key = ?", (key,))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Geçersiz key!")
    if user["expiry_date"] and datetime.fromisoformat(user["expiry_date"]) < datetime.now():
        raise HTTPException(status_code=401, detail="Key süresi dolmuş!")
    token = jwt.encode({"user_id": user["user_id"], "is_admin": user["is_admin"]}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "is_admin": user["is_admin"]}

@app.post("/admin/set-api-url")
async def set_api_url(data: dict, token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    if not payload["is_admin"]:
        raise HTTPException(status_code=403, detail="Sadece admin API URL’si ayarlayabilir!")
    api_url = data.get("api_url")
    if not api_url:
        raise HTTPException(status_code=400, detail="API URL’si eksik!")
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("api_url", api_url))
    db.commit()
    return {"status": "success", "message": "API URL’si kaydedildi"}

@app.get("/get-api-url")
async def get_api_url(db: sqlite3.Connection = Depends(get_db)):
    cursor = db.execute("SELECT value FROM settings WHERE key = ?", ("api_url",))
    result = cursor.fetchone()
    return {"api_url": result["value"] if result else ""}

@app.post("/send-sms")
async def send_sms(data: dict, token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    user_id = payload["user_id"]
    is_admin = payload["is_admin"]
    count = data.get("count", 100)
    mode = data.get("mode", 1)
    phone = data.get("phone")
    today = datetime.now().strftime("%Y-%m-%d")

    if not phone:
        raise HTTPException(status_code=400, detail="Telefon numarası eksik!")

    if not is_admin:
        cursor = db.execute("SELECT count FROM sms_limits WHERE user_id = ? AND date = ?", (user_id, today))
        user_limit = cursor.fetchone()
        user_limit = user_limit["count"] if user_limit else 0
        if user_limit >= 500:
            raise HTTPException(status_code=403, detail="Günlük 500 SMS limiti!")

    sent_count = 0
    delay = 0 if mode == 2 else 0.5
    for _ in range(count):
        if sent_count >= count or (not is_admin and user_limit + sent_count >= 500):
            break
        try:
            response = requests.post("https://api.bulksms.com/...", json=data)
            response.raise_for_status()
            sent_count += 1
            if not is_admin:
                db.execute("INSERT OR REPLACE INTO sms_limits (user_id, date, count) VALUES (?, ?, ?)",
                          (user_id, today, user_limit + sent_count))
                db.commit()
            if mode == 1:
                time.sleep(delay)
        except Exception as e:
            print(f"Hata: {e}")
            continue
    return {"status": "success", "success": sent_count, "failed": count - sent_count}

@app.post("/admin/add-key")
async def add_key(data: dict, token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    if not payload["is_admin"]:
        raise HTTPException(status_code=403, detail="Sadece admin key ekleyebilir!")
    key = data.get("key")
    user_id = data.get("user_id")
    expiry_days = data.get("expiry_days", 30)
    expiry_date = (datetime.now() + timedelta(days=expiry_days)).isoformat()
    db.execute("INSERT INTO users (key, user_id, expiry_date, is_admin) VALUES (?, ?, ?, ?)",
              (key, user_id, expiry_date, False))
    db.commit()
    return {"status": "success", "message": f"Key {key} eklendi, süre: {expiry_days} gün"}
