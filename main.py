"""
XenHub Backend - Cookie-Based Auth
FIXES 401 Unauthorized error!
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
from fastapi import FastAPI, HTTPException, Cookie, Depends, Response
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
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
PORT = int(os.getenv("PORT", 8080))

db = None
app = FastAPI(title="XenHub API", version="3.0.0")

# CORS with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://xenjoiner.com", "https://www.xenjoiner.com", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    
    class Config:
        extra = "allow"

class AdminLoginRequest(BaseModel):
    password: str

class AddBalanceRequest(BaseModel):
    discord_id: str
    amount: float

def format_est_time(dt: datetime) -> str:
    if not dt:
        return None
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ZoneInfo("America/New_York")).isoformat()

def _parse_dt(value) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    return value

def create_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(days=30)})
    return jwt.encode(to_encode, SESSION_SECRET, algorithm="HS256")

async def get_user(xen_session: str = Cookie(None)):
    if not xen_session:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(xen_session, SESSION_SECRET, algorithms=["HS256"])
        discord_id = payload.get("discord_id")
        if not discord_id:
            raise HTTPException(401, "Invalid session")
    except:
        raise HTTPException(401, "Invalid session")
    
    user = await db.users.find_one({"discord_id": discord_id})
    if not user:
        raise HTTPException(404, "User not found")
    return user

async def verify_admin(xen_session: str = Cookie(None)):
    if not xen_session:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(xen_session, SESSION_SECRET, algorithms=["HS256"])
        if not payload.get("admin"):
            raise HTTPException(403, "Admin only")
    except:
        raise HTTPException(401, "Invalid session")

@app.on_event("startup")
async def startup():
    global db
    client = motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
    db = client.xen_notifier
    await db.users.create_index("discord_id", unique=True)
    print("✅ DB ready (cookie auth)")

@app.get("/health")
async def health():
    return {"status": "ok", "auth": "cookie"}

@app.get("/slots")
async def get_slots():
    deluxe = await db.users.count_documents({"plan": "deluxe", "subscription_active": True})
    premium = await db.users.count_documents({"plan": "premium", "subscription_active": True})
    return {"deluxe": {"used": deluxe, "total": 6}, "premium": {"used": premium, "total": 7}}

@app.get("/auth/discord")
async def discord_oauth():
    url = (f"https://discord.com/oauth2/authorize?client_id={DISCORD_CLIENT_ID}"
           f"&response_type=code&redirect_uri={DISCORD_CALLBACK_URL}&scope=identify+email")
    return RedirectResponse(url)

@app.get("/auth/discord/callback")
async def discord_callback(code: str, response: Response):
    try:
        async with httpx.AsyncClient() as client:
            token_resp = await client.post("https://discord.com/api/oauth2/token", data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_CALLBACK_URL,
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            
            if token_resp.status_code != 200:
                return RedirectResponse(f"{FRONTEND_URL}?error=auth_failed")
            
            access_token = token_resp.json()["access_token"]
            
            user_resp = await client.get("https://discord.com/api/users/@me",
                                        headers={"Authorization": f"Bearer {access_token}"})
            
            if user_resp.status_code != 200:
                return RedirectResponse(f"{FRONTEND_URL}?error=user_failed")
            
            user_data = user_resp.json()
        
        discord_id = user_data["id"]
        username = user_data.get("username", "Unknown")
        
        existing = await db.users.find_one({"discord_id": discord_id})
        if not existing:
            await db.users.insert_one({
                "discord_id": discord_id,
                "username": username,
                "email": user_data.get("email"),
                "balance": 0.0,
                "subscription_active": False,
                "subscription_key": None,
                "subscription_expiry": None,
                "plan": None,
                "hwid_resets": 0,
                "created_at": datetime.utcnow()
            })
        
        token = create_token({"discord_id": discord_id})
        
        redirect = RedirectResponse(f"{FRONTEND_URL}/dashboard")
        redirect.set_cookie(
            key="xen_session",
            value=token,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=30 * 24 * 60 * 60
        )
        
        print(f"✅ Logged in: {discord_id}")
        return redirect
    except Exception as e:
        print(f"❌ OAuth error: {e}")
        return RedirectResponse(f"{FRONTEND_URL}?error=server_error")

@app.get("/user")
async def get_user_info(user: dict = Depends(get_user)):
    expiry_est = None
    time_left = 0
    
    if user.get("subscription_expiry"):
        expiry_dt = _parse_dt(user["subscription_expiry"])
        expiry_est = format_est_time(expiry_dt)
        if expiry_dt > datetime.utcnow():
            time_left = int((expiry_dt - datetime.utcnow()).total_seconds())
    
    txns = await db.transactions.find({"discord_id": user["discord_id"]}).sort("date", -1).limit(50).to_list(50)
    for t in txns:
        t["id"] = str(t.pop("_id"))
        if isinstance(t.get("date"), datetime):
            t["date"] = format_est_time(t["date"])
    
    # Return flat structure that frontend expects
    return {
        "discord_id": user["discord_id"],
        "username": user.get("username", "Unknown"),
        "email": user.get("email", ""),
        "balance": float(user.get("balance", 0)),
        "subscription_active": bool(user.get("subscription_active", False)),
        "subscription_key": user.get("subscription_key"),
        "subscription_expiry": expiry_est,
        "plan": user.get("plan"),
        "hwid_resets": int(user.get("hwid_resets", 0)),
        "transactions": txns,
        "timeLeft": time_left
    }

@app.post("/subscription/purchase")
async def purchase(req: PurchaseRequest, user: dict = Depends(get_user)):
    plan = req.plan.lower()
    hours = req.hours
    
    if plan not in ["deluxe", "premium"] or hours < 4:
        raise HTTPException(400, "Invalid input")
    
    cost = hours * (6.0 if plan == "deluxe" else 3.0)
    
    if user["balance"] < cost:
        raise HTTPException(400, "Insufficient balance")
    
    is_ext = user.get("subscription_active") and user.get("subscription_key")
    
    if is_ext:
        exp = _parse_dt(user["subscription_expiry"])
        new_exp = (exp if exp > datetime.utcnow() else datetime.utcnow()) + timedelta(hours=hours)
        key = user["subscription_key"]
    else:
        new_exp = datetime.utcnow() + timedelta(hours=hours)
        key = None
    
    async with httpx.AsyncClient() as client:
        lua = await client.patch(f"https://api.luarmor.net/v3/projects/{LUA_ARMOR_PROJECT_ID}/users",
            headers={"Authorization": LUA_ARMOR_API_KEY, "Content-Type": "application/json"},
            json={"script": "default", "identifier": user["discord_id"], "identifier_type": "discord",
                  "discord_id": user["discord_id"], "note": plan.capitalize(), "expire": int(new_exp.timestamp())})
        
        if lua.status_code not in [200, 201]:
            raise HTTPException(500, "Lua Armor error")
        
        if not key:
            key = lua.json().get("user_key")
    
    await db.users.update_one({"discord_id": user["discord_id"]}, {
        "$inc": {"balance": -cost},
        "$set": {"subscription_active": True, "subscription_key": key, "subscription_expiry": new_exp, "plan": plan}
    })
    
    await db.transactions.insert_one({
        "discord_id": user["discord_id"],
        "type": f"Purchase {plan.capitalize()} ({hours}h)",
        "amount": -cost,
        "status": "completed",
        "date": datetime.utcnow()
    })
    
    return {"success": True, "key": key, "expiry": format_est_time(new_exp)}

@app.post("/payment/create")
async def create_payment(req: TopUpRequest, user: dict = Depends(get_user)):
    if req.amount < 1:
        raise HTTPException(400, "Min $1")
    
    order_id = f"{user['discord_id']}_{int(time.time())}"
    
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://api.nowpayments.io/v1/payment",
            headers={"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"},
            json={"price_amount": req.amount, "price_currency": "usd", "pay_currency": req.currency or "ltc",
                  "order_id": order_id, "ipn_callback_url": f"{DISCORD_CALLBACK_URL.rsplit('/auth', 1)[0]}/payment/callback"})
        
        if resp.status_code != 201:
            raise HTTPException(500, "Payment failed")
        
        data = resp.json()
    
    await db.transactions.insert_one({
        "discord_id": user["discord_id"],
        "type": "Top Up",
        "amount": req.amount,
        "status": "pending",
        "date": datetime.utcnow(),
        "payment_id": data.get("payment_id"),
        "order_id": order_id
    })
    
    return {"payment_url": data.get("invoice_url"), "payment_id": data.get("payment_id"),
            "pay_currency": data.get("pay_currency"), "pay_amount": data.get("pay_amount"),
            "pay_address": data.get("pay_address")}

@app.post("/payment/callback")
async def payment_callback(cb: IPNCallback):
    if cb.payment_status not in ["finished", "confirmed"]:
        return {"status": "ignored"}
    
    discord_id = cb.order_id.split("_")[0]
    
    exists = await db.transactions.find_one({"payment_id": cb.payment_id, "status": "completed"})
    if exists:
        return {"status": "already_processed"}
    
    credit = cb.outcome_amount or cb.actually_paid or cb.price_amount or 0
    if credit <= 0:
        return {"status": "error"}
    
    await db.users.update_one({"discord_id": discord_id}, {"$inc": {"balance": credit}}, upsert=True)
    await db.transactions.update_one({"payment_id": cb.payment_id}, {"$set": {"status": "completed"}})
    
    print(f"✅ Credited ${credit} to {discord_id}")
    return {"status": "ok"}

@app.post("/user/reset-hwid")
async def reset_hwid(user: dict = Depends(get_user)):
    if not user.get("subscription_key"):
        raise HTTPException(400, "No subscription")
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"https://api.luarmor.net/v3/projects/{LUA_ARMOR_PROJECT_ID}/users/hwid/reset",
            headers={"Authorization": LUA_ARMOR_API_KEY, "Content-Type": "application/json"},
            json={"user_key": user["subscription_key"]})
        
        if resp.status_code not in [200, 201]:
            raise HTTPException(500, "Reset failed")
    
    return {"success": True}

@app.post("/discord/assign-role")
async def assign_role(user: dict = Depends(get_user)):
    plan = user.get("plan")
    if not user.get("subscription_active") or not plan:
        raise HTTPException(400, "No subscription")
    
    role_id = DISCORD_ROLE_ID_DELUXE if plan == "deluxe" else DISCORD_ROLE_ID_PREMIUM
    
    async with httpx.AsyncClient() as client:
        resp = await client.put(
            f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['discord_id']}/roles/{role_id}",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"})
        
        if resp.status_code not in [200, 204]:
            raise HTTPException(500, "Role failed")
    
    return {"success": True}

@app.post("/admin/login")
async def admin_login(req: AdminLoginRequest, response: Response):
    if req.password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid password")
    
    token = create_token({"admin": True})
    response.set_cookie(key="xen_session", value=token, httponly=True, secure=True, samesite="none", max_age=30*24*60*60)
    return {"token": token}

@app.post("/admin/add-balance")
async def add_balance(req: AddBalanceRequest, admin: None = Depends(verify_admin)):
    await db.users.update_one({"discord_id": req.discord_id}, {"$inc": {"balance": req.amount}}, upsert=True)
    await db.transactions.insert_one({"discord_id": req.discord_id, "type": "Admin Credit",
                                     "amount": req.amount, "status": "completed", "date": datetime.utcnow()})
    user = await db.users.find_one({"discord_id": req.discord_id})
    return {"success": True, "new_balance": user.get("balance", 0) if user else req.amount}

@app.get("/admin/subscribers")
async def get_subs(admin: None = Depends(verify_admin)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://api.luarmor.net/v3/projects/{LUA_ARMOR_PROJECT_ID}/users?limit=100",
                               headers={"Authorization": LUA_ARMOR_API_KEY})
        
        if resp.status_code != 200:
            raise HTTPException(500, "Lua error")
        
        users = resp.json().get("users", [])
        subs = []
        for u in users:
            exp = None
            if u.get("auth_expire"):
                exp = format_est_time(datetime.fromtimestamp(u["auth_expire"], tz=timezone.utc))
            subs.append({"id": u.get("id"), "discord_id": u.get("discord_id"), "username": u.get("note"),
                        "plan": u.get("note", "").lower(), "note": u.get("note"), "key": u.get("user_key"),
                        "expiry": exp})
        
        return {"subscribers": subs, "count": len(subs)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
