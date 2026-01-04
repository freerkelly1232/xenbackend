"""
Xen Notifier Backend - COMPLETE with Admin Panel Support
100% Python 3.13 Compatible
"""

import os
import asyncio
import hmac
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from motor import motor_asyncio
from pydantic import BaseModel
import jwt

# Environment Variables
MONGODB_URI = os.getenv("MONGODB_URI", "")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
DISCORD_CALLBACK_URL = os.getenv("DISCORD_CALLBACK_URL", "")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID_DELUXE = os.getenv("DISCORD_ROLE_ID_DELUXE", "")
DISCORD_ROLE_ID_PREMIUM = os.getenv("DISCORD_ROLE_ID_PREMIUM", "")
LUA_ARMOR_PROJECT_ID = os.getenv("LUA_ARMOR_PROJECT_ID", "")
LUA_ARMOR_API_KEY = os.getenv("LUA_ARMOR_API_KEY", "")
NOWPAYMENTS_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")
NOWPAYMENTS_IPN_SECRET = os.getenv("NOWPAYMENTS_IPN_SECRET", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://xenjoiner.com")
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me-in-production")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # Change this!
PORT = int(os.getenv("PORT", 8080))

# Global database connection
db = None

# FastAPI App
app = FastAPI(title="Xen Notifier API", version="2.0.7")

# CORS Configuration - ALLOW YOUR FRONTEND
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://xenjoiner.com",
        "https://www.xenjoiner.com",
        "http://xenjoiner.com",
        "http://www.xenjoiner.com",
        "http://localhost:5173",
        "http://localhost:3000",
        "*"  # TEMPORARY - Remove in production!
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Pydantic Models
class PurchaseRequest(BaseModel):
    plan: str
    hours: int

class TopUpRequest(BaseModel):
    amount: float
    currency: Optional[str] = "ltc"

class IPNCallback(BaseModel):
    payment_id: str
    payment_status: str
    order_id: str
    price_amount: Optional[float] = 0.0
    actually_paid: Optional[float] = 0.0
    outcome_amount: Optional[float] = None
    pay_currency: Optional[str] = None
    pay_address: Optional[str] = None
    pay_amount: Optional[float] = None
    
    class Config:
        extra = "allow"

class AdminLoginRequest(BaseModel):
    password: str

class AddBalanceRequest(BaseModel):
    discord_id: str
    amount: float

# Helper Functions
def format_est_time(dt: datetime) -> str:
    """Convert UTC datetime to EST string"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    est = dt.astimezone(ZoneInfo("America/New_York"))
    return est.isoformat()

def _parse_dt(value) -> datetime:
    """Parse datetime from various formats"""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    return value

def create_access_token(data: dict) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SESSION_SECRET, algorithm="HS256")

async def get_current_user(authorization: str = Header(None)):
    """Get current authenticated user"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
        discord_id = payload.get("discord_id")
        if not discord_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = await db.users.find_one({"discord_id": discord_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

async def verify_admin(admin_key: str = Header(None, alias="admin-key")):
    """Verify admin key"""
    if not admin_key or admin_key != SESSION_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin key")

# Startup & Background Tasks
@app.on_event("startup")
async def startup():
    """Initialize database and background tasks"""
    global db
    
    if not MONGODB_URI:
        print("⚠️ WARNING: MONGODB_URI not set!")
        raise RuntimeError("MONGODB_URI environment variable is required")
    
    # Connect to MongoDB
    client = motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
    db = client.xen_notifier
    
    # Create indexes
    await db.users.create_index("discord_id", unique=True)
    await db.subscriptions.create_index("key", unique=True)
    await db.transactions.create_index([("discord_id", 1), ("date", -1)])
    
    print("✅ Database initialized")
    print(f"✅ Admin password: {ADMIN_PASSWORD}")
    print(f"✅ Frontend URL: {FRONTEND_URL}")
    
    # Start background cleanup task
    asyncio.create_task(cleanup_expired_subscriptions())

async def cleanup_expired_subscriptions():
    """Cleanup expired subscriptions in background"""
    while True:
        try:
            await asyncio.sleep(300)  # Every 5 minutes
            
            now = datetime.utcnow()
            result = await db.users.update_many(
                {
                    "subscription_expiry": {"$lt": now},
                    "subscription_active": True
                },
                {
                    "$set": {"subscription_active": False}
                }
            )
            
            if result.modified_count > 0:
                print(f"🧹 Cleaned {result.modified_count} expired subscriptions")
        except Exception as e:
            print(f"❌ Cleanup error: {e}")

# Public Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        user_count = await db.users.count_documents({})
        active_subs = await db.users.count_documents({"subscription_active": True})
        
        return JSONResponse(
            content={
                "status": "ok",
                "python_version": "3.13",
                "users": user_count,
                "active_subscriptions": active_subs
            },
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/slots")
async def get_slots():
    """Get available subscription slots"""
    try:
        deluxe_count = await db.users.count_documents({
            "plan": "deluxe",
            "subscription_active": True
        })
        premium_count = await db.users.count_documents({
            "plan": "premium",
            "subscription_active": True
        })
        
        return JSONResponse(
            content={
                "deluxe": {"used": deluxe_count, "total": 6},
                "premium": {"used": premium_count, "total": 7}
            },
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
    except Exception as e:
        return {"deluxe": {"used": 0, "total": 6}, "premium": {"used": 0, "total": 7}}

# Discord OAuth
@app.get("/auth/discord")
async def discord_oauth():
    """Redirect to Discord OAuth"""
    discord_auth_url = (
        f"https://discord.com/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={DISCORD_CALLBACK_URL}"
        f"&scope=identify+email+guilds"
    )
    return RedirectResponse(discord_auth_url)

@app.get("/auth/discord/callback")
async def discord_callback(code: str, req: Request):
    """Handle Discord OAuth callback"""
    try:
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": DISCORD_CALLBACK_URL,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if token_response.status_code != 200:
                print(f"Token exchange failed: {token_response.text}")
                return RedirectResponse(f"{FRONTEND_URL}/login?error=auth_failed")
            
            token_data = token_response.json()
            access_token = token_data["access_token"]
            
            # Get user info
            user_response = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if user_response.status_code != 200:
                print(f"User fetch failed: {user_response.text}")
                return RedirectResponse(f"{FRONTEND_URL}/login?error=user_fetch_failed")
            
            user_data = user_response.json()
        
        # Create or update user
        discord_id = user_data["id"]
        username = user_data.get("username", "Unknown")
        email = user_data.get("email", "")
        
        existing_user = await db.users.find_one({"discord_id": discord_id})
        
        if existing_user:
            await db.users.update_one(
                {"discord_id": discord_id},
                {"$set": {"username": username, "email": email}}
            )
            user = await db.users.find_one({"discord_id": discord_id})
        else:
            new_user = {
                "discord_id": discord_id,
                "username": username,
                "email": email,
                "balance": 0.0,
                "subscription_active": False,
                "subscription_key": None,
                "subscription_expiry": None,
                "plan": None,
                "hwid_resets": 0,
                "created_at": datetime.utcnow()
            }
            await db.users.insert_one(new_user)
            user = new_user
        
        # Create JWT token
        jwt_token = create_access_token({"discord_id": discord_id})
        
        # Redirect to frontend with token
        return RedirectResponse(f"{FRONTEND_URL}?token={jwt_token}")
        
    except Exception as e:
        print(f"OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(f"{FRONTEND_URL}/login?error=server_error")

# Authenticated Endpoints
@app.get("/user")
async def get_user_info(user: dict = Depends(get_current_user)):
    """Get current user info with dashboard data"""
    try:
        subscription_expiry_est = None
        time_left = 0
        
        if user.get("subscription_expiry"):
            try:
                expiry_dt = _parse_dt(user["subscription_expiry"])
                subscription_expiry_est = format_est_time(expiry_dt)
                now = datetime.utcnow()
                if expiry_dt > now:
                    time_left = int((expiry_dt - now).total_seconds())
            except Exception as e:
                print(f"Error parsing expiry: {e}")
        
        transactions = []
        try:
            transactions = await db.transactions.find(
                {"discord_id": user["discord_id"]}
            ).sort("date", -1).limit(50).to_list(50)
            
            for txn in transactions:
                txn["id"] = str(txn.pop("_id"))
                if isinstance(txn.get("date"), datetime):
                    txn["date"] = format_est_time(txn["date"])
        except Exception as e:
            print(f"Error fetching transactions: {e}")
        
        response_data = {
            "user": {
                "discord_id": str(user["discord_id"]),
                "username": str(user.get("username", "Unknown")),
                "email": str(user.get("email", "")),
                "balance": float(user.get("balance", 0)),
                "subscription_active": bool(user.get("subscription_active", False)),
                "subscription_key": str(user.get("subscription_key")) if user.get("subscription_key") else None,
                "subscription_expiry": subscription_expiry_est,
                "plan": user.get("plan"),
                "hwid_resets": int(user.get("hwid_resets", 0)),
            },
            "transactions": transactions,
            "time_left": int(time_left)
        }
        
        return JSONResponse(
            content=response_data,
            status_code=200,
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )
    except Exception as e:
        print(f"❌ ERROR in /user endpoint: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            content={"detail": f"Error fetching user data: {str(e)}"},
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

@app.post("/user/reset-hwid")
async def reset_hwid(user: dict = Depends(get_current_user)):
    """Reset HWID via Lua Armor API"""
    
    if not user.get("subscription_active") or not user.get("subscription_key"):
        raise HTTPException(status_code=400, detail="No active subscription")
    
    key = user["subscription_key"]
    
    print(f"🔄 HWID Reset requested for {user['discord_id']}, key: {key}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://api.luarmor.net/v3/projects/{LUA_ARMOR_PROJECT_ID}/users/hwid/reset",
                headers={
                    "Authorization": LUA_ARMOR_API_KEY,
                    "Content-Type": "application/json",
                },
                json={"user_key": key}
            )
            
            print(f"Lua Armor HWID reset response ({response.status_code}): {response.text}")
            
            if response.status_code not in [200, 201]:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("message") or error_json.get("error") or error_detail
                except:
                    pass
                raise HTTPException(status_code=500, detail=f"HWID reset failed: {error_detail}")
            
            print(f"✅ HWID reset successful for {key}")
            
            return JSONResponse(
                content={"success": True},
                headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
            )
            
    except httpx.RequestError as e:
        print(f"❌ HWID reset network error: {e}")
        raise HTTPException(status_code=500, detail=f"Network error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ HWID reset error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"HWID reset failed: {str(e)}")

# Subscription Management
@app.post("/subscription/purchase")
async def purchase_subscription(request: PurchaseRequest, user: dict = Depends(get_current_user)):
    """Purchase or extend subscription"""
    
    plan = request.plan.lower()
    hours = request.hours
    
    if plan not in ["deluxe", "premium"]:
        raise HTTPException(status_code=400, detail="Invalid plan")
    if hours < 4:
        raise HTTPException(status_code=400, detail="Minimum 4 hours required")
    
    # Pricing
    hourly_rate = 6.0 if plan == "deluxe" else 3.0
    cost = hours * hourly_rate
    
    if user["balance"] < cost:
        raise HTTPException(status_code=400, detail=f"Insufficient balance. Required: ${cost}, Available: ${user['balance']}")
    
    # Check slots
    slots = await db.users.count_documents({"plan": plan, "subscription_active": True})
    max_slots = 6 if plan == "deluxe" else 7
    
    is_extending = user.get("subscription_active") and user.get("subscription_key")
    
    if not is_extending and slots >= max_slots:
        raise HTTPException(status_code=400, detail="No slots available")
    
    print(f"💰 Purchase: {user['discord_id']} - {plan} - {hours}h - ${cost}")
    
    try:
        # Calculate new expiry
        if is_extending:
            current_expiry = _parse_dt(user["subscription_expiry"])
            if current_expiry > datetime.utcnow():
                new_expiry = current_expiry + timedelta(hours=hours)
            else:
                new_expiry = datetime.utcnow() + timedelta(hours=hours)
            key = user["subscription_key"]
            print(f"🔄 Extending existing key: {key}")
        else:
            new_expiry = datetime.utcnow() + timedelta(hours=hours)
            
            existing_sub = await db.subscriptions.find_one({
                "discord_id": user["discord_id"],
                "expiry": {"$lt": datetime.utcnow()}
            })
            
            if existing_sub:
                key = existing_sub["key"]
                print(f"♻️ Reusing expired key: {key}")
            else:
                key = None
        
        # Create/update Lua Armor user
        async with httpx.AsyncClient() as client:
            lua_response = await client.patch(
                f"https://api.luarmor.net/v3/projects/{LUA_ARMOR_PROJECT_ID}/users",
                headers={
                    "Authorization": LUA_ARMOR_API_KEY,
                    "Content-Type": "application/json",
                },
                json={
                    "script": "default",
                    "identifier": user["discord_id"],
                    "identifier_type": "discord",
                    "discord_id": user["discord_id"],
                    "note": plan.capitalize(),
                    "expire": int(new_expiry.timestamp())
                },
                timeout=30.0
            )
            
            print(f"Lua Armor response ({lua_response.status_code}): {lua_response.text}")
            
            if lua_response.status_code not in [200, 201]:
                raise HTTPException(status_code=500, detail=f"Lua Armor error: {lua_response.text}")
            
            lua_data = lua_response.json()
            if not key:
                key = lua_data.get("user_key")
        
        # Deduct balance
        result = await db.users.update_one(
            {
                "discord_id": user["discord_id"],
                "balance": {"$gte": cost}
            },
            {
                "$inc": {"balance": -cost},
                "$set": {
                    "subscription_active": True,
                    "subscription_key": key,
                    "subscription_expiry": new_expiry,
                    "plan": plan
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=400, detail="Balance changed during purchase")
        
        # Update subscriptions collection
        await db.subscriptions.update_one(
            {"key": key},
            {
                "$set": {
                    "key": key,
                    "discord_id": user["discord_id"],
                    "username": user["username"],
                    "plan": plan,
                    "note": plan.capitalize(),
                    "expiry": new_expiry,
                    "updated_at": datetime.utcnow(),
                    "purchase_time": datetime.utcnow()
                },
                "$setOnInsert": {
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        # Create transaction
        await db.transactions.insert_one({
            "discord_id": user["discord_id"],
            "type": f"Purchase {plan.capitalize()} ({hours}h)",
            "amount": -cost,
            "status": "completed",
            "date": datetime.utcnow()
        })
        
        # Auto-assign Discord role
        try:
            role_id = DISCORD_ROLE_ID_DELUXE if plan == "deluxe" else DISCORD_ROLE_ID_PREMIUM
            if DISCORD_BOT_TOKEN and DISCORD_GUILD_ID and role_id:
                async with httpx.AsyncClient() as client:
                    await client.put(
                        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['discord_id']}/roles/{role_id}",
                        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
                    )
                print(f"✅ Auto-assigned Discord role")
        except Exception as e:
            print(f"⚠️ Discord role assignment failed (non-critical): {e}")
        
        print(f"✅ Purchase complete: {user['discord_id']} - {plan} - {hours}h")
        
        return JSONResponse(
            content={
                "success": True,
                "key": key,
                "plan": plan,
                "note": plan.capitalize(),
                "expiry": format_est_time(new_expiry),
                "message": f"Key active for {hours}h! Expiry: {format_est_time(new_expiry)}"
            },
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Purchase error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# Payment System
@app.post("/payment/create")
async def create_payment(request: TopUpRequest, user: dict = Depends(get_current_user)):
    """Create LTC payment via NOWPayments"""
    
    if request.amount < 1.0:
        raise HTTPException(status_code=400, detail="Minimum $1 required")
    
    order_id = f"{user['discord_id']}_{int(time.time())}"
    callback_url = DISCORD_CALLBACK_URL.rsplit("/auth/discord", 1)[0]
    pay_currency = request.currency if request.currency else "ltc"
    
    print(f"💳 Creating payment: {user['discord_id']} - ${request.amount} {pay_currency}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.nowpayments.io/v1/payment",
                headers={
                    "x-api-key": NOWPAYMENTS_API_KEY,
                    "Content-Type": "application/json",
                },
                json={
                    "price_amount": float(request.amount),
                    "price_currency": "usd",
                    "pay_currency": pay_currency,
                    "order_id": order_id,
                    "ipn_callback_url": f"{callback_url}/payment/callback",
                }
            )
            
            print(f"NowPayments response ({response.status_code}): {response.text}")
            
            if response.status_code != 201:
                raise HTTPException(status_code=500, detail=f"Failed to create payment: {response.text}")
            
            payment_data = response.json()
        
        # Store pending transaction
        await db.transactions.insert_one({
            "discord_id": user["discord_id"],
            "type": "Top Up",
            "amount": request.amount,
            "status": "pending",
            "date": datetime.utcnow(),
            "payment_id": payment_data.get("payment_id"),
            "order_id": order_id,
            "pay_currency": payment_data.get("pay_currency"),
            "pay_amount": payment_data.get("pay_amount"),
            "pay_address": payment_data.get("pay_address"),
        })
        
        currency_names = {
            "ltc": "Litecoin (LTC)",
            "sol": "Solana (SOL)",
            "btc": "Bitcoin (BTC)"
        }
        
        return JSONResponse(
            content={
                "payment_url": payment_data.get("invoice_url") or f"https://nowpayments.io/payment/?iid={payment_data.get('payment_id')}",
                "payment_id": payment_data.get("payment_id"),
                "pay_currency": payment_data.get("pay_currency"),
                "pay_currency_name": currency_names.get(payment_data.get("pay_currency", "").lower(), payment_data.get("pay_currency")),
                "pay_amount": payment_data.get("pay_amount"),
                "pay_address": payment_data.get("pay_address"),
            },
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Payment creation error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/payment/callback")
async def payment_callback(
    callback: IPNCallback,
    x_nowpayments_sig: str = Header(None, alias="x-nowpayments-sig")
):
    """Handle NOWPayments IPN callback"""
    
    print("=" * 80)
    print("💰 PAYMENT CALLBACK RECEIVED")
    print(f"Payment ID: {callback.payment_id}")
    print(f"Status: {callback.payment_status}")
    print(f"Order ID: {callback.order_id}")
    print(f"Outcome Amount: {callback.outcome_amount}")
    print("=" * 80)
    
    # Verify signature
    if NOWPAYMENTS_IPN_SECRET and x_nowpayments_sig:
        payload_dict = callback.dict()
        sorted_params = sorted(payload_dict.items())
        payload_str = json.dumps(dict(sorted_params), separators=(',', ':'))
        
        expected_sig = hmac.new(
            NOWPAYMENTS_IPN_SECRET.encode('utf-8'),
            payload_str.encode('utf-8'),
            hashlib.sha512
        ).hexdigest()
        
        if not hmac.compare_digest(x_nowpayments_sig, expected_sig):
            print(f"⚠️ WARNING: Invalid signature")
    
    if callback.payment_status not in ["finished", "partially_paid", "confirmed", "sending"]:
        print(f"⚠️ Ignoring status: {callback.payment_status}")
        return {"status": "ignored", "reason": f"Status '{callback.payment_status}' not processed"}
    
    parts = callback.order_id.split("_")
    if len(parts) != 2:
        print(f"❌ Invalid order_id format: {callback.order_id}")
        return {"status": "invalid order_id"}
    
    discord_id = parts[0]
    
    existing_txn = await db.transactions.find_one({
        "payment_id": str(callback.payment_id),
        "status": "completed"
    })
    
    if existing_txn:
        print(f"⚠️ Payment {callback.payment_id} already processed")
        return {"status": "already_processed"}
    
    credit_amount = 0
    if callback.outcome_amount and callback.outcome_amount > 0:
        credit_amount = callback.outcome_amount
    elif callback.actually_paid and callback.actually_paid > 0:
        credit_amount = callback.actually_paid
    elif callback.price_amount and callback.price_amount > 0:
        credit_amount = callback.price_amount
    else:
        print(f"❌ No valid credit amount found!")
        return {"status": "error", "reason": "No valid credit amount"}
    
    print(f"💰 Crediting ${credit_amount} to user {discord_id}")
    result = await db.users.update_one(
        {"discord_id": discord_id},
        {"$inc": {"balance": credit_amount}}
    )
    
    if result.matched_count == 0:
        print(f"⚠️ User {discord_id} not found - creating")
        await db.users.insert_one({
            "discord_id": discord_id,
            "balance": credit_amount,
            "created_at": datetime.utcnow(),
            "subscription_active": False,
        })
    
    await db.transactions.update_one(
        {"payment_id": str(callback.payment_id)},
        {
            "$set": {
                "status": "completed",
                "actually_paid": callback.actually_paid,
                "completed_at": datetime.utcnow(),
                "payment_status": callback.payment_status,
            }
        }
    )
    
    user = await db.users.find_one({"discord_id": discord_id})
    new_balance = user.get("balance", 0) if user else credit_amount
    
    print(f"✅ SUCCESS: Payment processed! New balance: ${new_balance}")
    print("=" * 80)
    
    return {
        "status": "ok",
        "credited": credit_amount,
        "new_balance": new_balance
    }

# Discord Role Assignment
@app.post("/discord/assign-role")
async def assign_discord_role(user: dict = Depends(get_current_user)):
    """Assign Discord role based on subscription plan"""
    
    if not DISCORD_BOT_TOKEN:
        raise HTTPException(status_code=500, detail="Discord bot not configured")
    if not DISCORD_GUILD_ID:
        raise HTTPException(status_code=500, detail="Discord guild not configured")
    
    plan = user.get("plan")
    if not user.get("subscription_active") or not plan:
        raise HTTPException(status_code=400, detail="No active subscription")
    
    role_id = DISCORD_ROLE_ID_DELUXE if plan == "deluxe" else DISCORD_ROLE_ID_PREMIUM
    
    if not role_id:
        raise HTTPException(status_code=500, detail=f"Role ID not configured for plan: {plan}")
    
    print(f"🎭 Assigning Discord role to {user['discord_id']}")
    
    try:
        async with httpx.AsyncClient() as client:
            url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['discord_id']}/roles/{role_id}"
            
            response = await client.put(
                url,
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            )
            
            print(f"Discord API response ({response.status_code}): {response.text}")
            
            if response.status_code not in [200, 204]:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_code = error_json.get("code")
                    
                    if error_code == 10004:
                        error_detail = "Bot is not in the Discord server. Please invite the bot first."
                    elif error_code == 10007:
                        error_detail = "You are not in the Discord server. Please join first."
                    elif error_code == 10011:
                        error_detail = "Role not found. Contact admin."
                    elif error_code == 50001:
                        error_detail = "Bot lacks permissions. Bot role must be above the role being assigned."
                    elif error_code == 50013:
                        error_detail = "Bot lacks 'Manage Roles' permission."
                    else:
                        error_detail = error_json.get("message") or error_detail
                except:
                    pass
                raise HTTPException(status_code=500, detail=f"Failed to assign role: {error_detail}")
        
        print(f"✅ Role assigned successfully")
        return JSONResponse(
            content={"success": True},
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Discord role error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ADMIN ENDPOINTS
@app.post("/admin/login")
async def admin_login(request: AdminLoginRequest):
    """Admin login endpoint"""
    if request.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Create admin token
    admin_token = create_access_token({"admin": True, "password": request.password})
    
    return {"token": admin_token}

@app.post("/admin/add-balance")
async def admin_add_balance(request: AddBalanceRequest, admin: None = Depends(verify_admin)):
    """Add balance to user (admin only)"""
    
    if not request.discord_id or request.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid input")
    
    print(f"👑 Admin adding ${request.amount} to {request.discord_id}")
    
    result = await db.users.update_one(
        {"discord_id": request.discord_id},
        {"$inc": {"balance": request.amount}}
    )
    
    if result.matched_count == 0:
        # Create user if doesn't exist
        await db.users.insert_one({
            "discord_id": request.discord_id,
            "balance": request.amount,
            "created_at": datetime.utcnow(),
            "subscription_active": False,
        })
    
    # Create transaction
    await db.transactions.insert_one({
        "discord_id": request.discord_id,
        "type": "Admin Credit",
        "amount": request.amount,
        "status": "completed",
        "date": datetime.utcnow()
    })
    
    user = await db.users.find_one({"discord_id": request.discord_id})
    new_balance = user.get("balance", 0) if user else request.amount
    
    return {"success": True, "new_balance": new_balance}

@app.get("/admin/subscribers")
async def get_subscribers(admin: None = Depends(verify_admin)):
    """Get real-time subscribers from Lua Armor"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.luarmor.net/v3/projects/{LUA_ARMOR_PROJECT_ID}/users",
                headers={"Authorization": LUA_ARMOR_API_KEY},
                params={"limit": 100}
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Lua Armor error: {response.text}")
            
            data = response.json()
            users = data.get("users", [])
            
            subscribers = []
            for lua_user in users:
                expiry_timestamp = lua_user.get("auth_expire")
                if expiry_timestamp:
                    expiry_dt = datetime.fromtimestamp(expiry_timestamp, tz=timezone.utc)
                    expiry_str = format_est_time(expiry_dt)
                else:
                    expiry_str = None
                
                subscribers.append({
                    "id": lua_user.get("id"),
                    "discord_id": lua_user.get("discord_id"),
                    "username": lua_user.get("note") or "Unknown",
                    "plan": lua_user.get("note", "").lower() if lua_user.get("note") else "unknown",
                    "note": lua_user.get("note"),
                    "key": lua_user.get("user_key"),
                    "expiry": expiry_str,
                    "created_at": lua_user.get("created_at")
                })
            
            return {
                "subscribers": subscribers,
                "count": len(subscribers)
            }
    except Exception as e:
        print(f"❌ Subscribers fetch error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Run Server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
