from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from pydantic import BaseModel
import os
from fastapi.middleware.cors import CORSMiddleware

# ────────────────────────────────────────────────
#  Config
# ────────────────────────────────────────────────

SECRET_KEY = os.getenv("SECRET_KEY", "this-is-only-for-local-testing-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Use SQLite for quick local testing – switch to postgresql:// in production
DATABASE_URL = "sqlite:///./test.db"

# ────────────────────────────────────────────────
#  Database
# ────────────────────────────────────────────────

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # SQLite only
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# ────────────────────────────────────────────────
#  Security
# ────────────────────────────────────────────────

# ─── Most reliable quick fix right now (2025) ───
# Use argon2 if you can install passlib[argon2]
# Otherwise keep bcrypt but pin bcrypt<4.1 in requirements
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],          # argon2 first = preferred
    deprecated="auto"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="FastAPI JWT Auth – Fixed 2025 Edition")










# Add this block
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",     # Vite default dev server
        "http://127.0.0.1:5173",
        "http://localhost:3000",     # if you ever use create-react-app
        "*"                          # ← for dev only; restrict in production!
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],  # explicitly include OPTIONS
    allow_headers=["Content-Type", "Authorization"],  # add more if needed (e.g. "X-Custom-Header")
    expose_headers=[],  # optional
    max_age=600,        # cache preflight for 10 min
)

# ────────────────────────────────────────────────
#  Schemas
# ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str
    

class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True

# ────────────────────────────────────────────────
#  Dependencies & Helpers
# ────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str | None = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = int(user_id_str)
    except (JWTError, ValueError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    return user

# ────────────────────────────────────────────────
#  Routes
# ────────────────────────────────────────────────

@app.post("/register", response_model=dict)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already taken")

    hashed = pwd_context.hash(data.password)

    user = User(username=data.username, hashed_password=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "User created", "username": user.username}


@app.post("/login", response_model=Token)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()

    if not user or not pwd_context.verify(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": str(user.id)})

    return {"access_token": token, "token_type": "bearer"}


@app.get("/me", response_model=UserOut)
def read_users_me(current_user = Depends(get_current_user)):
    return current_user


@app.get("/items")
def read_items(current_user = Depends(get_current_user)):
    return {
        "owner": current_user.username,
        "items": ["coffee", "laptop", "headphones"]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)