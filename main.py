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
from datetime import datetime, timedelta
import importlib
import enough

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
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
        
        # created_at kolonunu ekle (eğer yoksa)
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN created_at TEXT"))
            print("created_at kolonu eklendi")
        except Exception as e:
            print(f"created_at kolonu zaten var veya eklenemedi: {e}")
        
        # user_type kolonunu ekle (eğer yoksa)
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN user_type VARCHAR(20) DEFAULT 'normal'"))
            print("user_type kolonu eklendi")
        except Exception as e:
            print(f"user_type kolonu zaten var veya eklenemedi: {e}")
        
        # daily_used kolonunu ekle (eğer yoksa)
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN daily_used INTEGER DEFAULT 0"))
            print("daily_used kolonu eklendi")
        except Exception as e:
            print(f"daily_used kolonu zaten var veya eklenemedi: {e}")
        
        # last_reset_date kolonunu ekle (eğer yoksa)
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN last_reset_date TEXT"))
            print("last_reset_date kolonu eklendi")
        except Exception as e:
            print(f"last_reset_date kolonu zaten var veya eklenemedi: {e}")
        
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sms_limits (
                user_id TEXT,
                `date` TEXT,
                `count` INTEGER
            );
        """))
        
        # Admin kullanıcısını ekle (eğer yoksa)
        try:
            conn.execute(text("""
                INSERT IGNORE INTO users (`key`, user_id, expiry_date, created_at, is_admin, user_type)
                VALUES (:key, :user_id, :expiry_date, :created_at, :is_admin, :user_type);
            """), {
                "key": "admin123",
                "user_id": "admin",
                "expiry_date": "2099-12-31T23:59:59",
                "created_at": datetime.now().isoformat(),
                "is_admin": True,
                "user_type": "admin"
            })
        except Exception as e:
            # Eğer yeni kolonlar yoksa, eski yapıyla ekle
            try:
                conn.execute(text("""
                    INSERT IGNORE INTO users (`key`, user_id, expiry_date, created_at, is_admin)
                    VALUES (:key, :user_id, :expiry_date, :created_at, :is_admin);
                """), {
                    "key": "admin123",
                    "user_id": "admin",
                    "expiry_date": "2099-12-31T23:59:59",
                    "created_at": datetime.now().isoformat(),
                    "is_admin": True
                })
            except Exception as e2:
                # Eğer created_at kolonu da yoksa, en eski yapıyla ekle
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

def verify_recaptcha(recaptcha_response: str) -> bool:
    """reCAPTCHA doğrulama fonksiyonu"""
    if not RECAPTCHA_SECRET_KEY:
        return True  # Eğer secret key yoksa doğrulama yapma
    
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
        )
        result = response.json()
        return result.get('success', False)
    except Exception as e:
        print(f"reCAPTCHA doğrulama hatası: {e}")
        return False

@app.post("/login")
async def login(data: dict, db: SessionLocal = Depends(get_db)):
    key = data.get("key")
    recaptcha_response = data.get("recaptcha_response")
    
    # reCAPTCHA doğrulama (eğer secret key varsa)
    if RECAPTCHA_SECRET_KEY and not verify_recaptcha(recaptcha_response or ""):
        raise HTTPException(status_code=400, detail="reCAPTCHA doğrulaması başarısız!")
    
    result = db.execute(text("SELECT * FROM users WHERE `key` = :key"), {"key": key}).fetchone()
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
    
    token = jwt.encode({
        "user_id": result.user_id,
        "is_admin": result.is_admin,
        "user_type": user_type
    }, SECRET_KEY, algorithm="HS256")
    
    return {
        "access_token": token, 
        "is_admin": result.is_admin,
        "user_type": user_type,
        "daily_limit": daily_limit,
        "daily_used": daily_used
    }

@app.get("/get-api-url")
async def get_api_url(db: SessionLocal = Depends(get_db)):
    result = db.execute(text("SELECT value FROM settings WHERE `key` = 'api_url'")).fetchone()
    return {"api_url": result.value if result else ""}

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
        sent_count, failed_count = enough_module.is_enough(phone=phone, email=email, count=count, mode="turbo" if mode == 2 else "normal")
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

    return {"status": "success", "success": sent_count, "failed": failed_count}

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
    return {"status": "success", "message": "Kullanıcı eklendi"}

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
        
        # Günlük kullanımı al
        daily_used = getattr(row, 'daily_used', 0) or 0
        
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
    return {"status": "success", "message": "Kullanıcı silindi"}

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
    return {"status": "success", "message": "Backend URL kaydedildi"}

@app.get("/get-backend-url")
async def get_backend_url():
    return {"backend_url": BACKEND_URL}

@app.get("/get-recaptcha-site-key")
async def get_recaptcha_site_key():
    return {"site_key": RECAPTCHA_SITE_KEY or ""}

@app.post("/admin/set-recaptcha-keys")
async def set_recaptcha_keys(data: dict, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token eksik!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Geçersiz token!")
    if not payload.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Yetkisiz erişim!")
    
    site_key = data.get("site_key")
    secret_key = data.get("secret_key")
    
    if not site_key or not secret_key:
        raise HTTPException(status_code=400, detail="Site key ve Secret key gerekli!")
    
    # .env dosyasını güncelle
    try:
        env_path = ".env"
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Mevcut reCAPTCHA satırlarını güncelle veya ekle
            site_key_updated = False
            secret_key_updated = False
            
            for i, line in enumerate(lines):
                if line.startswith("RECAPTCHA_SITE_KEY="):
                    lines[i] = f"RECAPTCHA_SITE_KEY={site_key}\n"
                    site_key_updated = True
                elif line.startswith("RECAPTCHA_SECRET_KEY="):
                    lines[i] = f"RECAPTCHA_SECRET_KEY={secret_key}\n"
                    secret_key_updated = True
            
            # Eğer satırlar yoksa ekle
            if not site_key_updated:
                lines.append(f"RECAPTCHA_SITE_KEY={site_key}\n")
            if not secret_key_updated:
                lines.append(f"RECAPTCHA_SECRET_KEY={secret_key}\n")
            
            with open(env_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Global değişkenleri güncelle
            global RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY
            RECAPTCHA_SITE_KEY = site_key
            RECAPTCHA_SECRET_KEY = secret_key
            
            return {"status": "success", "message": "reCAPTCHA anahtarları güncellendi"}
        else:
            raise HTTPException(status_code=500, detail="`.env` dosyası bulunamadı!")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Güncelleme hatası: {str(e)}")

@app.get("/")
async def keep_alive():
    return {"status": "alive"}

@app.on_event("startup")
async def startup_event():
    print("API Başlatıldı!") 
