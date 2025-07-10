from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import jwt
import requests
import time
from datetime import datetime, timedelta

app = FastAPI()
SECRET_KEY = "gizli_anahtar"  # Render’da environment variable olarak ekle
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# cPanel MySQL bağlantısı
DATABASE_URL = "mysql+mysqlconnector://leozzo:bA6Ce59B45067_@cpanel.boyleiyi.xyz/leozzo_sms_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app.add_middleware(CORSMiddleware, allow_origins=["http://boyleiyi.xyz"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    with engine.connect() as conn:
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS settings (
                `key` VARCHAR(255) PRIMARY KEY,
                value TEXT
            )
        '''))
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS users (
                `key` VARCHAR(255) PRIMARY KEY,
                user_id TEXT,
                expiry_date TEXT,
                is_admin BOOLEAN
            )
        '''))
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS sms_limits (
                user_id TEXT,
                `date` TEXT,
                `count` INTEGER
            )
        '''))
        # Admin key’i ekle
        conn.execute(text('''
            INSERT IGNORE INTO users (`key`, user_id, expiry_date, is_admin)
            VALUES (:key, :user_id, :expiry_date, :is_admin)
        '''), {"key": "admin123", "user_id": "admin", "expiry_date": "2099-12-31T23:59:59", "is_admin": True})
        conn.commit()

init_db()

@app.post("/login")
async def login(data: dict, db: SessionLocal = Depends(get_db)):
    key = data.get("key")
    result = db.execute(text("SELECT * FROM users WHERE `key` = :key"), {"key": key}).fetchone()
    if not result:
        raise HTTPException(status_code=401, detail="Geçersiz key!")
    if result.expiry_date and datetime.fromisoformat(result.expiry_date) < datetime.now():
        raise HTTPException(status_code=401, detail="Key süresi dolmuş!")
    token = jwt.encode({"user_id": result.user_id, "is_admin": result.is_admin}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "is_admin": result.is_admin}

@app.post("/admin/set-api-url")
async def set_api_url(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    if not payload["is_admin"]:
        raise HTTPException(status_code=403, detail="Sadece admin API URL’si ayarlayabilir!")
    api_url = data.get("api_url")
    if not api_url:
        raise HTTPException(status_code=400, detail="API URL’si eksik!")
    db.execute(text("INSERT INTO settings (`key`, value) VALUES (:key, :value) ON DUPLICATE KEY UPDATE value = :value"),
              {"key": "api_url", "value": api_url})
    db.commit()
    return {"status": "success", "message": "API URL’si kaydedildi"}

@app.get("/get-api-url")
async def get_api_url(db: SessionLocal = Depends(get_db)):
    result = db.execute(text("SELECT value FROM settings WHERE `key` = :key"), {"key": "api_url"}).fetchone()
    return {"api_url": result.value if result else ""}

@app.post("/send-sms")
async def send_sms(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
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
        result = db.execute(text("SELECT `count` FROM sms_limits WHERE user_id = :user_id AND `date` = :date"),
                           {"user_id": user_id, "date": today}).fetchone()
        user_limit = result.count if result else 0
        if user_limit >= 500:
            raise HTTPException(status_code=403, detail="Günlük 500 SMS limiti!")

    sent_count = 0
    delay = 0 if mode == 2 else 0.5
    for _ in range(count):
        if sent_count >= count or (not is_admin and user_limit + sent_count >= 500):
            break
        try:
            response = requests.post("https://api.bulksms.com/...", json=data)  # BulkSMS URL’sini güncelle
            response.raise_for_status()
            sent_count += 1
            if not is_admin:
                db.execute(text('''
                    INSERT INTO sms_limits (user_id, `date`, `count`)
                    VALUES (:user_id, :date, :count)
                    ON DUPLICATE KEY UPDATE `count` = :count
                '''), {"user_id": user_id, "date": today, "count": user_limit + sent_count})
                db.commit()
            if mode == 1:
                time.sleep(delay)
        except Exception as e:
            print(f"Hata: {e}")
            continue
    return {"status": "success", "success": sent_count, "failed": count - sent_count}

@app.post("/admin/add-key")
async def add_key(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    if not payload["is_admin"]:
        raise HTTPException(status_code=403, detail="Sadece admin key ekleyebilir!")
    key = data.get("key")
    user_id = data.get("user_id")
    expiry_days = data.get("expiry_days", 0)
    is_admin = data.get("is_admin", 0)
    expiry_date = None if is_admin else (datetime.now() + timedelta(days=expiry_days)).isoformat() if expiry_days > 0 else None
    db.execute(text('''
        INSERT INTO users (`key`, user_id, expiry_date, is_admin)
        VALUES (:key, :user_id, :expiry_date, :is_admin)
    '''), {"key": key, "user_id": user_id, "expiry_date": expiry_date, "is_admin": bool(is_admin)})
    db.commit()
    return {"status": "success", "message": f"Key {key} eklendi, admin: {is_admin}, süre: {expiry_days if not is_admin else 'süresiz'}"}
