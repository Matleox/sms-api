from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import jwt
import os
import time
from datetime import datetime, timedelta
import importlib
import enough  # Güncellenmiş enough.py ile uyumlu

# .env dosyasını yükle
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
if not DATABASE_URL:
    raise Exception("DATABASE_URL environment variable not set!")

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# CORS (frontend domainini buraya ekle)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://boyleiyi.xyz", "https://boyleiyi.xyz"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS settings (
                `key` VARCHAR(255) PRIMARY KEY,
                value TEXT
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                `key` VARCHAR(255) PRIMARY KEY,
                user_id TEXT,
                expiry_date TEXT,
                is_admin BOOLEAN
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sms_limits (
                user_id TEXT,
                `date` TEXT,
                `count` INTEGER
            );
        """))
        conn.execute(text("""
            INSERT IGNORE INTO users (`key`, user_id, expiry_date, is_admin)
            VALUES (:key, :user_id, :expiry_date, :is_admin);
        """), {
            "key": "admin123",
            "user_id": "admin",
            "expiry_date": "2099-12-31T23:59:59",
            "is_admin": True
        })
        conn.execute(text("""
            INSERT IGNORE INTO settings (`key`, value)
            VALUES (:key, :value)
        """), {
            "key": "backend_url",
            "value": "https://sms-api-qb7q.onrender.com"
        })
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
    token = jwt.encode({
        "user_id": result.user_id,
        "is_admin": result.is_admin
    }, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "is_admin": result.is_admin}

@app.get("/get-api-url")
async def get_api_url(db: SessionLocal = Depends(get_db)):
    result = db.execute(text("SELECT value FROM settings WHERE `key` = 'api_url'")).fetchone()
    return {"api_url": result.value if result else ""}

@app.post("/admin/set-api-url")
async def set_api_url(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    if not payload["is_admin"]:
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    api_url = data.get("api_url")
    db.execute(text("""
        INSERT INTO settings (`key`, value)
        VALUES ('api_url', :value)
        ON DUPLICATE KEY UPDATE value = :value
    """), {"value": api_url})
    db.commit()
    return {"status": "success", "message": "API URL kaydedildi"}

@app.post("/send-sms")
async def send_sms(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    user_id = payload["user_id"]
    is_admin = payload["is_admin"]
    count = data.get("count", 100)
    mode = data.get("mode", 1)  # 1 = normal, 2 = turbo
    phone = data.get("phone")
    today = datetime.now().strftime("%Y-%m-%d")

    if not phone:
        raise HTTPException(status_code=400, detail="Telefon eksik!")

    if not is_admin:
        result = db.execute(text("SELECT `count` FROM sms_limits WHERE user_id = :user_id AND `date` = :date"),
                            {"user_id": user_id, "date": today}).fetchone()
        user_limit = result.count if result else 0
        if user_limit >= 500:
            raise HTTPException(status_code=403, detail="Günlük 500 SMS sınırı!")

    email = "mehmetyilmaz24121@gmail.com"  # Sabit mail

    # enough modülünü kontrol et
    try:
        enough_module = importlib.import_module("enough")
        if not hasattr(enough_module, "is_enough"):
            raise AttributeError("enough modülünde is_enough fonksiyonu bulunamadı!")
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"enough modülü yüklenemedi: {str(e)}")
    except AttributeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        print(f"SMS gönderiliyor - Phone: {phone}, Email: {email}, Count: {count}")
        # enough.is_enough üzerinden tek seferde tüm SMS’leri gönder
        sent_count, failed_count = enough.is_enough(phone=phone, email=email, count=count, mode="turbo" if mode == 2 else "normal")
        print(f"SMS sonucu - Başarılı: {sent_count}, Başarısız: {failed_count}, Toplam: {sent_count + failed_count}")
    except Exception as e:
        print(f"SMS Hatası: {e}")
        sent_count, failed_count = 0, count  # Hata durumunda başarısız say

    if not is_admin:
        db.execute(text("""
            INSERT INTO sms_limits (user_id, `date`, `count`)
            VALUES (:user_id, :date, :count)
            ON DUPLICATE KEY UPDATE `count` = :count
        """), {"user_id": user_id, "date": today, "count": user_limit + sent_count})
        db.commit()

    return {"status": "success", "success": sent_count, "failed": failed_count}

@app.post("/admin/add-key")
async def add_key(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    if not payload["is_admin"]:
        raise HTTPException(status_code=403, detail="Yetkisiz!")
    key = data.get("key")
    user_id = data.get("user_id")
    expiry_days = data.get("expiry_days", 0)
    is_admin = data.get("is_admin", False)
    expiry_date = None if is_admin else (datetime.now() + timedelta(days=expiry_days)).isoformat()
    db.execute(text("""
        INSERT INTO users (`key`, user_id, expiry_date, is_admin)
        VALUES (:key, :user_id, :expiry_date, :is_admin)
    """), {
        "key": key,
        "user_id": user_id,
        "expiry_date": expiry_date,
        "is_admin": is_admin
    })
    db.commit()
    return {"status": "success", "message": f"{key} eklendi"}

@app.get("/test-db")
async def test_db(db: SessionLocal = Depends(get_db)):
    try:
        result = db.execute(text("SELECT 1")).fetchone()
        return {"status": "DB connected"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/admin/set-backend-url")
async def set_backend_url(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    if not payload["is_admin"]:
        raise HTTPException(status_code=403, detail="Sadece admin backend URL’si ayarlayabilir!")
    backend_url = data.get("backend_url")
    if not backend_url:
        raise HTTPException(status_code=400, detail="Backend URL’si eksik!")
    db.execute(text("INSERT INTO settings (`key`, value) VALUES (:key, :value) ON DUPLICATE KEY UPDATE value = :value"),
              {"key": "backend_url", "value": backend_url})
    db.commit()
    return {"status": "success", "message": "Backend URL’si kaydedildi"}

@app.get("/get-backend-url")
async def get_backend_url(db: SessionLocal = Depends(get_db)):
    result = db.execute(text("SELECT value FROM settings WHERE `key` = :key"), {"key": "backend_url"}).fetchone()
    return {"backend_url": result.value if result else "https://sms-api-qb7q.onrender.com"}
