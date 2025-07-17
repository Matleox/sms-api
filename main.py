from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import jwt
import os
import time
import requests
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import importlib
import enough

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
SMS_API_URL = os.getenv("SMS_API_URL")
BACKEND_URL = os.getenv("BACKEND_URL", "https://sms-api-qb7q.onrender.com")

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
                is_admin BOOLEAN,
                two_fa_secret TEXT,
                two_fa_enabled BOOLEAN DEFAULT FALSE
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
            INSERT IGNORE INTO settings (`key`, value)
            VALUES (:key, :value)
        """), {
            "key": "backend_url",
            "value": "https://sms-api-qb7q.onrender.com"
        })
        conn.commit()

init_db()

def reset_daily_usage_if_needed(db, user_key):
    """Günlük kullanımı sıfırla (eğer yeni günse)"""
    today = datetime.now().strftime("%Y-%m-%d")
    
    # Kullanıcının son sıfırlama tarihini kontrol et
    result = db.execute(text("SELECT last_reset_date FROM users WHERE `key` = :key"), {"key": user_key}).fetchone()
    if result and result.last_reset_date:
        last_reset = datetime.fromisoformat(result.last_reset_date).strftime("%Y-%m-%d")
        if last_reset != today:
            # Yeni gün, kullanımı sıfırla
            db.execute(text("""
                UPDATE users 
                SET daily_used = 0, last_reset_date = :today 
                WHERE `key` = :key
            """), {"today": datetime.now().isoformat(), "key": user_key})
            db.commit()
            return 0
        else:
            # Aynı gün, mevcut kullanımı döndür
            result = db.execute(text("SELECT daily_used FROM users WHERE `key` = :key"), {"key": user_key}).fetchone()
            return result.daily_used if result else 0
    else:
        # İlk kez kullanım, sıfırla
        db.execute(text("""
            UPDATE users 
            SET daily_used = 0, last_reset_date = :today 
            WHERE `key` = :key
        """), {"today": datetime.now().isoformat(), "key": user_key})
        db.commit()
        return 0

def refresh_token(payload):
    """Token'ı yenile (30 dakika daha)"""
    return jwt.encode({
        "user_id": payload.get("user_id"),
        "is_admin": payload.get("is_admin"),
        "user_type": payload.get("user_type"),
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }, SECRET_KEY, algorithm="HS256")



@app.post("/login")
async def login(data: dict, db: SessionLocal = Depends(get_db)):
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
    
    # Kullanıcı türünü belirle
    user_type = getattr(result, 'user_type', None)
    if not user_type:
        user_type = 'admin' if result.is_admin else 'normal'
    
    # Günlük kullanımı kontrol et ve sıfırla (gerekirse)
    daily_used = reset_daily_usage_if_needed(db, key)
    
    # Günlük limiti belirle
    daily_limit = 0 if result.is_admin or user_type == 'premium' else 500
    
    # 2FA kontrolü
    two_fa_enabled = getattr(result, 'two_fa_enabled', False)
    if result.is_admin and two_fa_enabled:
        # 2FA gerekli, geçici token oluştur
        temp_token = jwt.encode({
            "user_id": result.user_id,
            "is_admin": result.is_admin,
            "user_type": user_type,
            "temp": True,
            "exp": datetime.utcnow() + timedelta(minutes=5)  # 5 dakika geçerli
        }, SECRET_KEY, algorithm="HS256")
        
        return {
            "requires_2fa": True,
            "temp_token": temp_token
        }
    
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
        "daily_used": daily_used
    }

@app.post("/verify-2fa")
async def verify_2fa(data: dict, db: SessionLocal = Depends(get_db)):
    temp_token = data.get("temp_token")
    code = data.get("code")
    
    if not temp_token or not code:
        raise HTTPException(status_code=400, detail="Token ve kod gerekli!")
    
    try:
        payload = jwt.decode(temp_token, SECRET_KEY, algorithms=["HS256"])
        if not payload.get("temp"):
            raise HTTPException(status_code=401, detail="Geçersiz token!")
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    
    user_id = payload.get("user_id")
    result = db.execute(text("SELECT * FROM users WHERE user_id = :user_id"), {"user_id": user_id}).fetchone()
    
    if not result:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı!")
    
    # 2FA kodunu doğrula
    two_fa_secret = getattr(result, 'two_fa_secret', None)
    if not two_fa_secret:
        raise HTTPException(status_code=401, detail="2FA kurulmamış!")
    
    totp = pyotp.TOTP(two_fa_secret)
    if not totp.verify(code):
        raise HTTPException(status_code=401, detail="Geçersiz 2FA kodu!")
    
    # Günlük kullanımı kontrol et
    daily_used = reset_daily_usage_if_needed(db, result.key)
    
    # Kullanıcı türünü belirle
    user_type = getattr(result, 'user_type', None)
    if not user_type:
        user_type = 'admin' if result.is_admin else 'normal'
    
    # Günlük limiti belirle
    daily_limit = 0 if result.is_admin or user_type == 'premium' else 500
    
    # Gerçek token oluştur
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
        "daily_used": daily_used
    }

@app.get("/admin/2fa-status")
async def get_2fa_status(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    user_id = payload.get("user_id")
    result = db.execute(text("SELECT two_fa_enabled FROM users WHERE user_id = :user_id"), {"user_id": user_id}).fetchone()
    
    return {
        "status": "success",
        "enabled": getattr(result, 'two_fa_enabled', False) if result else False
    }

@app.post("/admin/enable-2fa")
async def enable_2fa(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    user_id = payload.get("user_id")
    
    # Secret oluştur
    secret = pyotp.random_base32()
    
    # QR kod oluştur
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_id,
        issuer_name="SMS Gönderim Sistemi"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    qr_code_url = f"data:image/png;base64,{qr_code_base64}"
    
    # Secret'i veritabanına kaydet (henüz aktif etme)
    try:
        db.execute(text("""
            UPDATE users 
            SET two_fa_secret = :secret 
            WHERE user_id = :user_id
        """), {"secret": secret, "user_id": user_id})
        db.commit()
    except Exception as e:
        # Eğer kolon yoksa, önce kolonu ekle
        try:
            db.execute(text("ALTER TABLE users ADD COLUMN two_fa_secret TEXT"))
            db.execute(text("ALTER TABLE users ADD COLUMN two_fa_enabled BOOLEAN DEFAULT FALSE"))
            db.commit()
            
            db.execute(text("""
                UPDATE users 
                SET two_fa_secret = :secret 
                WHERE user_id = :user_id
            """), {"secret": secret, "user_id": user_id})
            db.commit()
        except Exception as e2:
            raise HTTPException(status_code=500, detail="Veritabanı hatası!")
    
    return {
        "status": "success",
        "qr_code": qr_code_url
    }

@app.post("/admin/confirm-2fa")
async def confirm_2fa(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    user_id = payload.get("user_id")
    code = data.get("code")
    
    if not code:
        raise HTTPException(status_code=400, detail="Kod gerekli!")
    
    # Secret'i al
    result = db.execute(text("SELECT two_fa_secret FROM users WHERE user_id = :user_id"), {"user_id": user_id}).fetchone()
    
    if not result or not result.two_fa_secret:
        raise HTTPException(status_code=400, detail="2FA kurulumu başlatılmamış!")
    
    # Kodu doğrula
    totp = pyotp.TOTP(result.two_fa_secret)
    if not totp.verify(code):
        raise HTTPException(status_code=400, detail="Geçersiz kod!")
    
    # 2FA'yı aktif et
    db.execute(text("""
        UPDATE users 
        SET two_fa_enabled = TRUE 
        WHERE user_id = :user_id
    """), {"user_id": user_id})
    db.commit()
    
    # Token'ı yenile
    new_token = refresh_token(payload)
    
    return {
        "status": "success",
        "message": "2FA başarıyla aktif edildi!",
        "new_token": new_token
    }

@app.post("/admin/disable-2fa")
async def disable_2fa(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    user_id = payload.get("user_id")
    
    # 2FA'yı deaktif et ve secret'i sil
    db.execute(text("""
        UPDATE users 
        SET two_fa_enabled = FALSE, two_fa_secret = NULL 
        WHERE user_id = :user_id
    """), {"user_id": user_id})
    db.commit()
    
    # Token'ı yenile
    new_token = refresh_token(payload)
    
    return {
        "status": "success",
        "message": "2FA başarıyla deaktif edildi!",
        "new_token": new_token
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
async def send_sms(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
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
        daily_used = reset_daily_usage_if_needed(db, user_id)
        if daily_used >= 500:
            raise HTTPException(status_code=403, detail="Günlük 500 SMS sınırı!")

    email = "mehmetyilmaz24121@gmail.com"

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
        sent_count, failed_count = enough.is_enough(phone=phone, email=email, count=count, mode="turbo" if mode == 2 else "normal")
        print(f"SMS sonucu - Başarılı: {sent_count}, Başarısız: {failed_count}, Toplam: {sent_count + failed_count}")
    except Exception as e:
        print(f"SMS Hatası: {e}")
        sent_count, failed_count = 0, count

    # Günlük kullanımı güncelle (sadece normal kullanıcılar için)
    if not is_admin and user_type == "normal":
        current_used = reset_daily_usage_if_needed(db, user_id)
        db.execute(text("""
            UPDATE users 
            SET daily_used = :daily_used 
            WHERE `key` = :user_id
        """), {"daily_used": current_used + sent_count, "user_id": user_id})
        db.commit()

    # Token'ı yenile
    new_token = refresh_token(
