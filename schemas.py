"""
Database Schemas for Petify AI

Each Pydantic model corresponds to a MongoDB collection. The collection name is the
lowercased class name.

Collections:
- user
- session
- credit
- generatedimage
- order
- blogpost
- apilog
- admin
- pricingplan
- setting
- favorite
"""
from typing import Optional, List, Literal, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Auth / Users
class User(BaseModel):
    email: EmailStr
    password_hash: Optional[str] = Field(None, description="BCrypt hash, only for email/password accounts")
    name: Optional[str] = None
    image: Optional[str] = None
    provider: Literal["credentials", "google", "admin"] = "credentials"
    provider_id: Optional[str] = None
    role: Literal["user", "admin"] = "user"
    credits: int = 0
    is_active: bool = True
    last_login_at: Optional[datetime] = None

class Session(BaseModel):
    user_id: str
    refresh_token: str
    expires_at: datetime
    user_agent: Optional[str] = None
    ip: Optional[str] = None

# Credits and Orders
class Credit(BaseModel):
    user_id: str
    delta: int
    reason: Literal[
        "purchase", "subscription", "generation", "background", "upscale", "variation", "admin_adjust"
    ]
    balance_after: Optional[int] = None
    meta: Optional[Dict[str, Any]] = None

class Order(BaseModel):
    user_id: str
    provider: Literal["stripe", "razorpay", "paypal"] = "stripe"
    type: Literal["one_time", "subscription"] = "one_time"
    status: Literal["created", "paid", "failed", "refunded", "canceled"] = "created"
    amount: int = Field(..., description="Amount in smallest currency unit, e.g. cents")
    currency: str = "usd"
    credits: int = 0
    external_id: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

# Content
class GeneratedImage(BaseModel):
    user_id: str
    prompt: Optional[str] = None
    source_image_url: Optional[str] = None
    style: Optional[str] = None
    variant_of_id: Optional[str] = None
    hd: bool = False
    bg: Optional[str] = Field(None, description="background mode: remove|replace:<color/url>")
    output_url: Optional[str] = None
    output_urls: Optional[List[str]] = None
    status: Literal["queued", "processing", "completed", "failed"] = "queued"
    provider: Optional[str] = None
    provider_job_id: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
    is_public: bool = False
    is_favorite: bool = False

class Favorite(BaseModel):
    user_id: str
    image_id: str

class BlogPost(BaseModel):
    slug: str
    title: str
    excerpt: Optional[str] = None
    content_md: str
    cover_image_url: Optional[str] = None
    published: bool = False
    tags: Optional[List[str]] = None

class ApiLog(BaseModel):
    user_id: Optional[str] = None
    route: str
    status_code: int
    method: str
    latency_ms: int
    meta: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class Admin(BaseModel):
    user_id: str
    permissions: List[str] = []

class PricingPlan(BaseModel):
    key: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "usd"
    credits: int
    is_subscription: bool = False
    interval: Optional[Literal["month", "year"]] = None
    is_active: bool = True

class Setting(BaseModel):
    key: str
    value: Dict[str, Any]
