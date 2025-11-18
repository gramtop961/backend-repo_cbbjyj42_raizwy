import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Session, Credit, GeneratedImage, Order, BlogPost, ApiLog, Admin, PricingPlan, Setting

# Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret-change")
JWT_ALG = "HS256"
ACCESS_MINUTES = 30
REFRESH_DAYS = 30
FRONTEND_URL = os.getenv("FRONTEND_URL", "*")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Petify AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL] if FRONTEND_URL != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# Utilities
class TokenPair(BaseModel):
    access_token: str
    refresh_token: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def create_refresh_token(user_id: str):
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_DAYS)
    payload = {"sub": user_id, "type": "refresh", "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


def oid(id_str: Any) -> Any:
    try:
        return ObjectId(id_str)
    except Exception:
        return id_str


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = decode_token(creds.credentials)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        if db is None:
            raise HTTPException(status_code=500, detail="Database not configured")
        user = db["user"].find_one({"_id": oid(user_id)}) or db["user"].find_one({"_id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Schemas for requests
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


# Auth Routes
@app.post("/auth/register", response_model=TokenPair)
def register(req: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    existing = db["user"].find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=req.email, password_hash=hash_password(req.password), name=req.name)
    user_id = create_document("user", user)

    access = create_access_token({"sub": user_id})
    refresh = create_refresh_token(user_id)

    sess = Session(user_id=user_id, refresh_token=refresh, expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_DAYS))
    create_document("session", sess)

    return TokenPair(access_token=access, refresh_token=refresh)


@app.post("/auth/login", response_model=TokenPair)
def login(req: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["user"].find_one({"email": req.email})
    if not user or not user.get("password_hash"):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    user_id = str(user["_id"]) if "_id" in user else user.get("id")
    access = create_access_token({"sub": user_id})
    refresh = create_refresh_token(user_id)

    sess = Session(user_id=user_id, refresh_token=refresh, expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_DAYS))
    create_document("session", sess)

    return TokenPair(access_token=access, refresh_token=refresh)


@app.post("/auth/refresh", response_model=TokenPair)
def refresh_token(req: RefreshRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    try:
        payload = decode_token(req.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        user_id = payload.get("sub")
        # validate session exists
        sess = db["session"].find_one({"refresh_token": req.refresh_token})
        if not sess:
            raise HTTPException(status_code=401, detail="Session not found")
        access = create_access_token({"sub": user_id})
        new_refresh = create_refresh_token(user_id)
        db["session"].update_one({"_id": sess["_id"]}, {"$set": {"refresh_token": new_refresh, "expires_at": datetime.now(timezone.utc) + timedelta(days=REFRESH_DAYS)}})
        return TokenPair(access_token=access, refresh_token=new_refresh)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


# Credits endpoints
class PurchaseRequest(BaseModel):
    credits: int
    provider: str = "stripe"
    amount_cents: int
    currency: str = "usd"


@app.post("/credits/purchase")
def purchase_credits(req: PurchaseRequest, user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user_id = str(user["_id"]) if "_id" in user else user.get("id")
    order = Order(user_id=user_id, provider=req.provider, type="one_time", status="paid", amount=req.amount_cents, currency=req.currency, credits=req.credits)
    order_id = create_document("order", order)
    new_balance = (user.get("credits", 0) + req.credits)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"credits": new_balance}})
    credit = Credit(user_id=user_id, delta=req.credits, reason="purchase", balance_after=new_balance)
    create_document("credit", credit)
    return {"ok": True, "order_id": order_id, "balance": new_balance}


# AI generation stubs (provider-agnostic)
class GenerateRequest(BaseModel):
    prompt: Optional[str] = None
    style: Optional[str] = None
    mode: str = "text_to_image"  # text_to_image | image_to_image | bg_remove | bg_replace | upscale | variation
    source_image_url: Optional[str] = None
    hd: bool = False


def consume_credits(user_doc: dict, cost: int):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    balance = user_doc.get("credits", 0)
    if balance < cost:
        raise HTTPException(status_code=402, detail="Insufficient credits")
    new_balance = balance - cost
    db["user"].update_one({"_id": user_doc["_id"]}, {"$set": {"credits": new_balance}})
    credit = Credit(user_id=str(user_doc["_id"]), delta=-cost, reason="generation", balance_after=new_balance)
    create_document("credit", credit)


@app.post("/ai/generate")
def ai_generate(req: GenerateRequest, user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    # Simple cost model: base 1 credit, HD +2
    cost = 1 + (2 if req.hd else 0)
    consume_credits(user, cost)

    gen = GeneratedImage(
        user_id=str(user["_id"]),
        prompt=req.prompt,
        source_image_url=req.source_image_url,
        style=req.style,
        hd=req.hd,
        status="processing",
        provider="mock",
        meta={"note": "Replace with real provider integration"}
    )
    gen_id = create_document("generatedimage", gen)

    # Simulate processing
    time.sleep(0.2)
    output_url = f"https://picsum.photos/seed/{gen_id}/1024/1024"
    # Update by ObjectId if possible
    try:
        db["generatedimage"].update_one({"_id": oid(gen_id)}, {"$set": {"status": "completed", "output_url": output_url}})
    except Exception:
        db["generatedimage"].update_one({"_id": gen_id}, {"$set": {"status": "completed", "output_url": output_url}})

    return {"id": gen_id, "output_url": output_url}


@app.get("/ai/history")
def ai_history(limit: int = 20, user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    items = list(db["generatedimage"].find({"user_id": str(user["_id"]) }).sort("created_at", -1).limit(limit))
    for doc in items:
        doc["id"] = str(doc.get("_id"))
        doc.pop("_id", None)
    return {"items": items}


@app.post("/images/{image_id}/favorite")
def toggle_favorite(image_id: str, user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    img = db["generatedimage"].find_one({"_id": oid(image_id)}) or db["generatedimage"].find_one({"_id": image_id})
    if not img:
        raise HTTPException(status_code=404, detail="Image not found")
    new_val = not img.get("is_favorite", False)
    db["generatedimage"].update_one({"_id": img["_id"]}, {"$set": {"is_favorite": new_val}})
    return {"ok": True, "favorite": new_val}


# Blog
class BlogCreate(BaseModel):
    slug: str
    title: str
    content_md: str
    excerpt: Optional[str] = None
    cover_image_url: Optional[str] = None
    published: bool = False


@app.post("/blog")
def create_blog(post: BlogCreate, user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    # require admin
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    blog = BlogPost(**post.model_dump())
    blog_id = create_document("blogpost", blog)
    return {"id": blog_id}


@app.get("/blog")
def list_blogs(published_only: bool = True):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    query = {"published": True} if published_only else {}
    items = list(db["blogpost"].find(query).sort("created_at", -1))
    for doc in items:
        doc["id"] = str(doc.get("_id"))
        doc.pop("_id", None)
    return {"items": items}


@app.get("/blog/{slug}")
def get_blog(slug: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    post = db["blogpost"].find_one({"slug": slug, "published": True})
    if not post:
        raise HTTPException(status_code=404, detail="Not found")
    post["id"] = str(post.get("_id"))
    post.pop("_id", None)
    return post


# Public health checks
@app.get("/")
def root():
    return {"name": "Petify AI Backend", "ok": True}


@app.get("/test")
def test_database():
    try:
        cols = db.list_collection_names() if db is not None else []
        return {"ok": True, "collections": cols[:20], "db_configured": db is not None}
    except Exception as e:
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
