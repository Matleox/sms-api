from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import jwt
import os
import time
import requests
from datetime import datetime, timedelta
import importlib
import enough
import base64
import pyotp
import qrcode
from io import BytesIO
import secrets

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
SMS_API_URL = os.getenv("SMS_API_URL")
BACKEND_URL = os.getenv("BACKEND_URL", "https://sms-api-qb7q.onrender.com")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "0x4AAAAAABm3w5qo-VCyb97HtS-uaxypPmE")

if not DATABASE_URL:
    raise Exception("DATABASE_URL environment variable not set!")

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
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
            CREATE TABLE IF NOT EXISTS sms_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_key VARCHAR(255) NOT NULL,
                user_id VARCHAR(255) NOT NULL,
                phone_number VARCHAR(20) NOT NULL,
                sms_count INT NOT NULL,
                success_count INT DEFAULT 0,
                failed_count INT DEFAULT 0,
                mode ENUM('normal', 'turbo') NOT NULL,
                status ENUM('pending', 'sending', 'completed', 'failed') NOT NULL,
                ip_address VARCHAR(45),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_key (user_key),
                INDEX idx_timestamp (timestamp),
                INDEX idx_status (status)
            );
        """))
        conn.execute(text("""
            INSERT IGNORE INTO settings (`key`, value)
            VALUES (:key, :value)
        """), {
            "key": "backend_url",
            "value": "https://sms-api-qb7q.onrender.com"
        })
        conn.commit()

init_db()

# --- YENİ GÜNLÜK KULLANIM FONKSİYONLARI ---
def get_today_sms_count(db, user_id):
    # Türkiye saat dilimini kullan (UTC+3)
    from datetime import timezone, timedelta
    turkey_tz = timezone(timedelta(hours=3))
    today = datetime.now(turkey_tz).strftime("%Y-%m-%d")
    result = db.execute(text("SELECT count FROM sms_limits WHERE user_id = :user_id AND date = :today"), {"user_id": user_id, "today": today}).fetchone()
    return result.count if result else 0

def increment_today_sms_count(db, user_id, count):
    # Türkiye saat dilimini kullan (UTC+3)
    from datetime import timezone, timedelta
    turkey_tz = timezone(timedelta(hours=3))
    today = datetime.now(turkey_tz).strftime("%Y-%m-%d")
    result = db.execute(text("SELECT count FROM sms_limits WHERE user_id = :user_id AND date = :today"), {"user_id": user_id, "today": today}).fetchone()
    if result:
        db.execute(text("UPDATE sms_limits SET count = count + :count WHERE user_id = :user_id AND date = :today"), {"count": count, "user_id": user_id, "today": today})
    else:
        db.execute(text("INSERT INTO sms_limits (user_id, date, count) VALUES (:user_id, :today, :count)"), {"user_id": user_id, "today": today, "count": count})
    db.commit()

def refresh_token(payload):
    """Token'ı yenile (30 dakika daha)"""
    return jwt.encode({
        "user_id": payload.get("user_id"),
        "is_admin": payload.get("is_admin"),
        "user_type": payload.get("user_type"),
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }, SECRET_KEY, algorithm="HS256")

# 2FA yardımcı fonksiyonları

def get_2fa_settings(db):
    row = db.execute(text("SELECT value FROM settings WHERE `key` = '2fa' ")).fetchone()
    if row and row.value:
        import json
        return json.loads(row.value)
    return {"enabled": False, "secret": None}

def set_2fa_settings(db, enabled, secret=None):
    import json
    value = json.dumps({"enabled": enabled, "secret": secret})
    db.execute(text("REPLACE INTO settings (`key`, value) VALUES ('2fa', :value)"), {"value": value})
    db.commit()

@app.get("/admin/2fa-status")
async def admin_2fa_status(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    settings = get_2fa_settings(db)
    return {"status": "success", "enabled": settings.get("enabled", False)}

@app.post("/admin/enable-2fa")
async def admin_enable_2fa(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    secret = pyotp.random_base32()
    set_2fa_settings(db, False, secret)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="Admin", issuer_name="SMS Panel")
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_b64 = base64.b64encode(buffered.getvalue()).decode()
    qr_url = f"data:image/png;base64,{qr_b64}"
    return {"status": "success", "qr_code": qr_url}

@app.post("/admin/confirm-2fa")
async def admin_confirm_2fa(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    code = data.get("code")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    settings = get_2fa_settings(db)
    secret = settings.get("secret")
    if not secret:
        raise HTTPException(status_code=400, detail="2FA kurulumu başlatılmamış!")
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        raise HTTPException(status_code=400, detail="Kod geçersiz!")
    set_2fa_settings(db, True, secret)
    # Token yenile
    new_token = refresh_token(payload)
    return {"status": "success", "new_token": new_token}

@app.post("/admin/disable-2fa")
async def admin_disable_2fa(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    set_2fa_settings(db, False, None)
    new_token = refresh_token(payload)
    return {"status": "success", "new_token": new_token}

# Girişte 2FA kontrolü ve temp_token üretimi
TEMP_TOKENS = {}

@app.post("/login")
async def login(data: dict, request: Request, db: SessionLocal = Depends(get_db)):
    # Turnstile token kontrolü
    turnstile_token = data.get("turnstile_token")
    if not turnstile_token:
        raise HTTPException(status_code=400, detail="Güvenlik doğrulaması eksik!")
    # Cloudflare Turnstile doğrulaması
    verify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    remoteip = request.client.host if request.client else None
    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": turnstile_token,
    }
    if remoteip:
        payload["remoteip"] = remoteip
    try:
        r = requests.post(verify_url, data=payload, timeout=5)
        result = r.json()
        if not result.get("success"):
            raise HTTPException(status_code=400, detail="Güvenlik doğrulaması başarısız! Lütfen tekrar deneyin.")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Güvenlik doğrulaması sırasında hata oluştu!")

    key = data.get("key")
    try:
        result = db.execute(text("SELECT * FROM users WHERE `key` = :key"), {"key": key}).fetchone()
    except Exception as e:
        print(f"Database error: {e}")
        raise HTTPException(status_code=401, detail="Geçersiz key!")
    if not result:
        raise HTTPException(status_code=401, detail="Geçersiz key!")
    if result.expiry_date and datetime.fromisoformat(result.expiry_date) < datetime.now():
        raise HTTPException(status_code=401, detail="Key süresi dolmuş!")
    user_type = getattr(result, 'user_type', None)
    if not user_type:
        user_type = 'admin' if result.is_admin else 'normal'
    # --- GÜNLÜK SMS HAKKI ---
    daily_used = get_today_sms_count(db, result.user_id)
    daily_limit = 0 if result.is_admin or user_type == 'premium' else 500
    # 2FA kontrolü
    if result.is_admin:
        settings = get_2fa_settings(db)
        if settings.get("enabled") and settings.get("secret"):
            # 2FA aktif, temp_token üret
            temp_token = secrets.token_urlsafe(32)
            TEMP_TOKENS[temp_token] = {
                "user_id": result.user_id,
                "is_admin": result.is_admin,
                "user_type": user_type,
                "exp": time.time() + 300, # 5 dakika geçerli
                "daily_limit": daily_limit,
                "daily_used": daily_used,
                "expiry_date": result.expiry_date
            }
            return {"requires_2fa": True, "temp_token": temp_token}
    token = jwt.encode({
        "user_id": result.user_id,
        "is_admin": result.is_admin,
        "user_type": user_type,
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }, SECRET_KEY, algorithm="HS256")
    return {
        "access_token": token, 
        "is_admin": result.is_admin,
        "user_type": user_type,
        "daily_limit": daily_limit,
        "daily_used": daily_used,
        "expiry_date": result.expiry_date
    }

@app.post("/verify-2fa")
async def verify_2fa(data: dict, db: SessionLocal = Depends(get_db)):
    temp_token = data.get("temp_token")
    code = data.get("code")
    if not temp_token or not code:
        raise HTTPException(status_code=400, detail="Eksik bilgi!")
    info = TEMP_TOKENS.get(temp_token)
    if not info or info["exp"] < time.time():
        raise HTTPException(status_code=401, detail="Temp token süresi doldu!")
    settings = get_2fa_settings(db)
    secret = settings.get("secret")
    if not secret:
        raise HTTPException(status_code=400, detail="2FA aktif değil!")
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        raise HTTPException(status_code=400, detail="Kod geçersiz!")
    # Başarılı, gerçek JWT üret
    token = jwt.encode({
        "user_id": info["user_id"],
        "is_admin": info["is_admin"],
        "user_type": info["user_type"],
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }, SECRET_KEY, algorithm="HS256")
    # Günlük limit ve used da ekle
    return {
        "access_token": token,
        "is_admin": info["is_admin"],
        "user_type": info["user_type"],
        "daily_limit": info["daily_limit"],
        "daily_used": info["daily_used"],
        "expiry_date": info.get("expiry_date")
    }

@app.get("/get-api-url")
async def get_api_url():
    return {"api_url": SMS_API_URL or ""}

@app.post("/admin/set-api-url")
async def set_api_url(data: dict, token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    api_url = data.get("api_url")
    if not api_url:
        raise HTTPException(status_code=400, detail="API URL'si eksik!")
    
    # .env dosyasını güncelle
    try:
        env_path = ".env"
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Mevcut SMS_API_URL satırını güncelle veya ekle
            api_url_updated = False
            
            for i, line in enumerate(lines):
                if line.startswith("SMS_API_URL="):
                    lines[i] = f"SMS_API_URL={api_url}\n"
                    api_url_updated = True
            
            # Eğer satır yoksa ekle
            if not api_url_updated:
                lines.append(f"SMS_API_URL={api_url}\n")
            
            with open(env_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Global değişkeni güncelle
            global SMS_API_URL
            SMS_API_URL = api_url
            
            return {"status": "success", "message": "SMS API URL kaydedildi"}
        else:
            raise HTTPException(status_code=500, detail="`.env` dosyası bulunamadı!")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Güncelleme hatası: {str(e)}")

@app.post("/send-sms")
async def send_sms(data: dict, request: Request, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    
    user_id = payload.get("user_id")
    is_admin = payload.get("is_admin", False)
    user_type = payload.get("user_type", "normal")
    count = data.get("count", 100)
    mode = data.get("mode", 1)
    phone = data.get("phone")

    if not phone:
        raise HTTPException(status_code=400, detail="Telefon eksik!")

    # Günlük limit kontrolü (sadece normal kullanıcılar için)
    if not is_admin and user_type == "normal":
        daily_used = get_today_sms_count(db, user_id)
        if daily_used + count > 500:
            raise HTTPException(status_code=403, detail="Günlük 500 SMS sınırı!")

    email = "mehmetyilmaz24121@gmail.com"

    # Kullanıcı bilgilerini al
    user_result = db.execute(text("SELECT `key` FROM users WHERE user_id = :user_id"), {"user_id": user_id}).fetchone()
    user_key = user_result.key if user_result else user_id

    # IP adresini al
    ip_address = request.client.host if request.client else "unknown"

    # SMS log kaydı oluştur (başlangıçta)
    db.execute(text("""
        INSERT INTO sms_logs (user_key, user_id, phone_number, sms_count, success_count, failed_count, mode, status, ip_address)
        VALUES (:user_key, :user_id, :phone_number, :sms_count, :success_count, :failed_count, :mode, :status, :ip_address)
    """), {
        "user_key": user_key,
        "user_id": user_id,
        "phone_number": phone,
        "sms_count": count,
        "success_count": 0,
        "failed_count": 0,
        "mode": "turbo" if mode == 2 else "normal",
        "status": "sending",
        "ip_address": ip_address
    })
    db.commit()

    try:
        print(f"SMS gönderiliyor - Phone: {phone}, Email: {email}, Count: {count}")
        sent_count, failed_count = enough.is_enough(phone=phone, email=email, count=count, mode="turbo" if mode == 2 else "normal")
        print(f"SMS sonucu - Başarılı: {sent_count}, Başarısız: {failed_count}, Toplam: {sent_count + failed_count}")
        
        # Log kaydını güncelle
        db.execute(text("""
            UPDATE sms_logs 
            SET success_count = :success_count, failed_count = :failed_count, status = :status
            WHERE id = (
                SELECT id FROM (
                    SELECT id FROM sms_logs 
                    WHERE user_key = :user_key AND phone_number = :phone_number
                    ORDER BY timestamp DESC LIMIT 1
                ) as temp
            )
        """), {
            "success_count": sent_count,
            "failed_count": failed_count,
            "status": "completed",
            "user_key": user_key,
            "phone_number": phone
        })
        db.commit()
        
    except Exception as e:
        print(f"SMS Hatası: {e}")
        sent_count, failed_count = 0, count
        
        # Hata durumunda log kaydını güncelle
        db.execute(text("""
            UPDATE sms_logs 
            SET success_count = :success_count, failed_count = :failed_count, status = :status
            WHERE id = (
                SELECT id FROM (
                    SELECT id FROM sms_logs 
                    WHERE user_key = :user_key AND phone_number = :phone_number
                    ORDER BY timestamp DESC LIMIT 1
                ) as temp
            )
        """), {
            "success_count": sent_count,
            "failed_count": failed_count,
            "status": "failed",
            "user_key": user_key,
            "phone_number": phone
        })
        db.commit()

    # Günlük kullanımı güncelle (sadece normal kullanıcılar için)
    if not is_admin and user_type == "normal":
        increment_today_sms_count(db, user_id, sent_count)

    # Token'ı yenile
    new_token = refresh_token(payload)

    return {
        "status": "success", 
        "success": sent_count, 
        "failed": failed_count,
        "new_token": new_token,
        # GÜNCEL KULLANIMI DA DÖNDÜR
        "daily_used": get_today_sms_count(db, user_id)
    }

@app.post("/admin/add-key")
async def add_key(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz!")
    
    key = data.get("key")
    user_id = data.get("user_id")
    expiry_days = data.get("expiry_days", 0)
    is_admin = data.get("is_admin", False)
    user_type = data.get("user_type", "normal")
    expiry_date = None if is_admin else (datetime.now() + timedelta(days=expiry_days)).isoformat()
    
    try:
        # Yeni kolonlarla ekle
        db.execute(text("""
            INSERT INTO users (`key`, user_id, expiry_date, created_at, is_admin, user_type, daily_used, last_reset_date)
            VALUES (:key, :user_id, :expiry_date, :created_at, :is_admin, :user_type, :daily_used, :last_reset_date)
        """), {
            "key": key,
            "user_id": user_id,
            "expiry_date": expiry_date,
            "created_at": datetime.now().isoformat(),
            "is_admin": is_admin,
            "user_type": user_type,
            "daily_used": 0,
            "last_reset_date": datetime.now().isoformat()
        })
    except Exception as e:
        # Eğer yeni kolonlar yoksa, eski yapıyla ekle
        try:
            db.execute(text("""
                INSERT INTO users (`key`, user_id, expiry_date, created_at, is_admin)
                VALUES (:key, :user_id, :expiry_date, :created_at, :is_admin)
            """), {
                "key": key,
                "user_id": user_id,
                "expiry_date": expiry_date,
                "created_at": datetime.now().isoformat(),
                "is_admin": is_admin
            })
        except Exception as e2:
            # Eğer created_at kolonu da yoksa, en eski yapıyla ekle
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
    
    # Token'ı yenile
    new_token = refresh_token(payload)
    
    return {
        "status": "success", 
        "message": "Kullanıcı eklendi",
        "new_token": new_token
    }

@app.get("/admin/users")
async def get_users(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    result = db.execute(text("SELECT * FROM users ORDER BY created_at DESC")).fetchall()
    users = []
    for row in result:
        # Kullanıcı türünü belirle
        user_type = getattr(row, 'user_type', None)
        if not user_type:
            user_type = 'admin' if row.is_admin else 'normal'
        
        # Günlük limiti belirle
        daily_limit = 0 if row.is_admin or user_type == 'premium' else 500
        
        # Günlük kullanımı sms_limits tablosundan al
        daily_used = get_today_sms_count(db, row.user_id)
        
        users.append({
            "id": row.key,  # key'i id olarak kullan
            "key": row.key,
            "user_id": row.user_id,
            "expiry_date": row.expiry_date,
            "is_admin": row.is_admin,
            "user_type": user_type,
            "daily_limit": daily_limit,
            "daily_used": daily_used,
            "created_at": getattr(row, 'created_at', row.expiry_date) if hasattr(row, 'created_at') else row.expiry_date
        })
    return users

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    # Önce kullanıcının var olup olmadığını kontrol et
    result = db.execute(text("SELECT * FROM users WHERE `key` = :user_id"), {"user_id": user_id}).fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı!")
    
    # Kullanıcıyı sil
    db.execute(text("DELETE FROM users WHERE `key` = :user_id"), {"user_id": user_id})
    db.commit()
    
    # Token'ı yenile
    new_token = refresh_token(payload)
    
    return {
        "status": "success", 
        "message": "Kullanıcı silindi",
        "new_token": new_token
    }

@app.get("/test-db")
async def test_db(db: SessionLocal = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/admin/set-backend-url")
async def set_backend_url(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    backend_url = data.get("backend_url")
    if not backend_url:
        raise HTTPException(status_code=400, detail="Backend URL eksik!")
    db.execute(text("""
        INSERT INTO settings (`key`, value)
        VALUES ('backend_url', :value)
        ON DUPLICATE KEY UPDATE value = :value
    """), {"value": backend_url})
    db.commit()
    
    # Token'ı yenile
    new_token = refresh_token(payload)
    
    return {
        "status": "success", 
        "message": "Backend URL kaydedildi",
        "new_token": new_token
    }

@app.get("/get-backend-url")
async def get_backend_url():
    return {"backend_url": BACKEND_URL}

@app.get("/user-stats")
async def get_user_stats(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    
    user_id = payload.get("user_id")
    is_admin = payload.get("is_admin", False)
    user_type = payload.get("user_type", "normal")
    
    # Debug için Türkiye saati
    from datetime import timezone, timedelta
    turkey_tz = timezone(timedelta(hours=3))
    today_turkey = datetime.now(turkey_tz).strftime("%Y-%m-%d")
    
    # Günlük kullanım verilerini al
    daily_used = get_today_sms_count(db, user_id)
    daily_limit = 0 if is_admin or user_type == 'premium' else 500
    
    return {
        "daily_used": daily_used,
        "daily_limit": daily_limit,
        "debug": {
            "user_id": user_id,
            "user_type": user_type,
            "today_turkey": today_turkey,
            "is_admin": is_admin
        }
    }



@app.get("/")
async def keep_alive():
    return {"status": "alive"}

@app.post("/admin/reset-user-limit")
async def reset_user_limit(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    user_id = data.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="User ID eksik!")
    
    # Türkiye saat dilimini kullan (UTC+3)
    from datetime import timezone, timedelta
    turkey_tz = timezone(timedelta(hours=3))
    today = datetime.now(turkey_tz).strftime("%Y-%m-%d")
    
    # Kullanıcının günlük limitini sıfırla
    db.execute(text("DELETE FROM sms_limits WHERE user_id = :user_id AND date = :today"), 
               {"user_id": user_id, "today": today})
    db.commit()
    
    return {"status": "success", "message": "Kullanıcı limiti sıfırlandı"}

@app.get("/admin/sms-logs")
async def get_sms_logs(
    token: str = Depends(oauth2_scheme), 
    db: SessionLocal = Depends(get_db),
    page: int = 1,
    limit: int = 10,
    user_key: str = None,
    user_id: str = None,
    user_type: str = None,
    status: str = None,
    start_date: str = None,
    end_date: str = None,
    sort_order: str = 'desc'
):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    # Base query with JOIN
    query = """
        SELECT sl.*, u.user_type, u.is_admin 
        FROM sms_logs sl 
        LEFT JOIN users u ON sl.user_key = u.key 
        WHERE 1=1
    """
    params = {}
    
    # Filtreler
    if user_key:
        query += " AND sl.user_key = :user_key"
        params["user_key"] = user_key
    
    if user_id:
        query += " AND sl.user_id LIKE :user_id"
        params["user_id"] = f"%{user_id}%"
    
    if user_type and user_type != 'all':
        if user_type == 'admin':
            query += " AND u.is_admin = 1"
        else:
            query += " AND u.user_type = :user_type AND u.is_admin = 0"
            params["user_type"] = user_type
    
    if status:
        query += " AND sl.status = :status"
        params["status"] = status
    
    if start_date:
        query += " AND DATE(sl.timestamp) >= :start_date"
        params["start_date"] = start_date
    
    if end_date:
        query += " AND DATE(sl.timestamp) <= :end_date"
        params["end_date"] = end_date
    
    # Toplam kayıt sayısı
    count_query = f"SELECT COUNT(*) as total FROM ({query}) as subquery"
    total_result = db.execute(text(count_query), params).fetchone()
    total_count = total_result.total if total_result else 0
    
    # Sayfalama ve sıralama
    offset = (page - 1) * limit
    query += f" ORDER BY sl.timestamp {sort_order.upper()} LIMIT :limit OFFSET :offset"
    params["limit"] = limit
    params["offset"] = offset
    
    # Logları çek
    result = db.execute(text(query), params).fetchall()
    logs = []
    
    for row in result:
        # Kullanıcı türünü belirle
        user_type = 'admin' if row.is_admin else (row.user_type or 'normal')
        
        logs.append({
            "id": row.id,
            "user_key": row.user_key,
            "user_id": row.user_id,
            "phone_number": row.phone_number,
            "sms_count": row.sms_count,
            "success_count": row.success_count,
            "failed_count": row.failed_count,
            "mode": row.mode,
            "status": row.status,
            "ip_address": row.ip_address,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "user_type": user_type
        })
    
    return {
        "logs": logs,
        "total": total_count,
        "page": page,
        "limit": limit,
        "total_pages": (total_count + limit - 1) // limit
    }

@app.post("/admin/sms-logs/add")
async def add_sms_log(data: dict, db: SessionLocal = Depends(get_db)):
    user_key = data.get("user_key")
    user_id = data.get("user_id")
    phone_number = data.get("phone_number")
    sms_count = data.get("sms_count")
    success_count = data.get("success_count", 0)
    failed_count = data.get("failed_count", 0)
    mode = data.get("mode")
    status = data.get("status")
    ip_address = data.get("ip_address")
    
    if not all([user_key, user_id, phone_number, sms_count, mode, status]):
        raise HTTPException(status_code=400, detail="Eksik parametreler!")
    
    db.execute(text("""
        INSERT INTO sms_logs (user_key, user_id, phone_number, sms_count, success_count, failed_count, mode, status, ip_address)
        VALUES (:user_key, :user_id, :phone_number, :sms_count, :success_count, :failed_count, :mode, :status, :ip_address)
    """), {
        "user_key": user_key,
        "user_id": user_id,
        "phone_number": phone_number,
        "sms_count": sms_count,
        "success_count": success_count,
        "failed_count": failed_count,
        "mode": mode,
        "status": status,
        "ip_address": ip_address
    })
    db.commit()
    
    return {"status": "success", "message": "SMS log kaydı eklendi"}

@app.delete("/admin/sms-logs/clear")
async def clear_sms_logs(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    # Tüm SMS loglarını sil
    db.execute(text("DELETE FROM sms_logs"))
    db.commit()
    
    return {"status": "success", "message": "Tüm SMS logları temizlendi"}

@app.on_event("startup")
async def startup_event():
    print("API Başlatıldı!") 

@app.api_route("/live", methods=["GET", "HEAD"])
async def live():
    print("API uyandırıldı!")
    return {"status": "alive"}
