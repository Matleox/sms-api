from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid
import jwt
from pydantic import BaseModel
import os

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database setup
DATABASE_URL = os.environ.get("DATABASE_URL", "mysql+mysqlconnector://user:password@localhost/dbname")
engine = create_engine(DATABASE_URL)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

class UserCreate(BaseModel):
    key: str
    user_id: str
    expiry_days: int
    is_admin: bool

def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.execute(text("SELECT * FROM users WHERE user_id = :user_id"), {"user_id": user_id}).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/admin/add-key")
async def add_key(user: UserCreate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check if key already exists
    existing_key = db.execute(text("SELECT * FROM users WHERE `key` = :key"), {"key": user.key}).fetchone()
    if existing_key:
        raise HTTPException(status_code=400, detail="Key already exists")

    # Generate unique user_id if not provided
    unique_user_id = str(uuid.uuid4()) if not user.user_id else user.user_id
    expiry_date = datetime.utcnow() + timedelta(days=user.expiry_days)

    db.execute(
        text("""
            INSERT INTO users (`key`, user_id, expiry_date, is_admin)
            VALUES (:key, :user_id, :expiry_date, :is_admin)
        """),
        {
            "key": user.key,
            "user_id": unique_user_id,
            "expiry_date": expiry_date,
            "is_admin": user.is_admin
        }
    )
    db.commit()
    return {"message": "User added successfully", "user_id": unique_user_id}
