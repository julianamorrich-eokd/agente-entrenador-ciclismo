import os
import time
import json
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from dotenv import load_dotenv
from itsdangerous import URLSafeSerializer

# Vercel lee env vars del dashboard
load_dotenv()

STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")  # p.ej. https://agente-entrenador-ciclismo.vercel.app
STATE_SECRET = os.getenv("STATE_SECRET", "change-me")
AGENT_BEARER_TOKEN = os.getenv("AGENT_BEARER_TOKEN")

# Upstash Redis (persistencia)
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")
TOKENS_TTL = 30 * 24 * 3600  # 30 días

app = FastAPI(title="Agente Ciclismo Backend (Vercel)")
S = URLSafeSerializer(STATE_SECRET)

SCOPES = ["read", "activity:read_all"]
AUTHORIZE_URL = "https://www.strava.com/oauth/authorize"
TOKEN_URL = "https://www.strava.com/oauth/token"
API_BASE = "https://www.strava.com/api/v3"

async def redis_get(key: str):
    if not (UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN):
        return None
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(
            f"{UPSTASH_REDIS_REST_URL}/get/{key}",
            headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
        )
    res = r.json().get("result")
    return json.loads(res) if res else None

async def redis_set(key: str, value: dict, ex=TOKENS_TTL):
    if not (UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN):
        return
    payload = json.dumps(value)
    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(
            f"{UPSTASH_REDIS_REST_URL}/pipeline",
            headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
            json={"pipeline": [["SET", key, payload], ["EXPIRE", key, ex]]},
        )

def _bearer_ok(req: Request) -> bool:
    auth = req.headers.get("authorization") or req.headers.get("Authorization")
    return bool(auth and auth.split()[:1] == ["Bearer"] and auth.split()[1] == AGENT_BEARER_TOKEN)

@app.get("/")
def root():
    return {"status": "ok", "service": "agente-ciclismo-backend"}

@app.get("/auth/strava/login")
async def strava_login():
    if not BASE_URL:
        raise HTTPException(status_code=500, detail="BASE_URL not configured")
    state = S.dumps({"ts": int(time.time())})
    # Strava quiere scope separado por comas
    params = {
        "client_id": STRAVA_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/auth/strava/callback",
        "response_type": "code",
        "scope": ",".join(SCOPES),
        "state": state,
        "approval_prompt": "auto",
    }
    qp = httpx.QueryParams(params)
    return RedirectResponse(url=f"{AUTHORIZE_URL}?{qp}")

@app.get("/auth/strava/callback")
async def strava_callback(code: str, state: str):
    try:
        S.loads(state)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state")

    async with httpx.AsyncClient(timeout=20) as client:
        data = {
            "client_id": STRAVA_CLIENT_ID,
            "client_secret": STRAVA_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
        }
        r = await client.post(TOKEN_URL, data=data)
        r.raise_for_status()
        token = r.json()

    athlete_id = token.get("athlete", {}).get("id")
    if not athlete_id:
        raise HTTPException(status_code=400, detail="No athlete id in token response")

    t = {
        "access_token": token["access_token"],
        "refresh_token": token["refresh_token"],
        "expires_at": token["expires_at"],
    }
    await redis_set(f"strava:{athlete_id}", t)

    return JSONResponse({"message": "Strava conectado", "athlete_id": athlete_id})

async def _ensure_token(athlete_id: str) -> str:
    key = f"strava:{athlete_id}"
    t = await redis_get(key)
    if not t:
        raise HTTPException(status_code=401, detail="Conecta Strava primero")

    # refrescar si caduca pronto
    if t["expires_at"] <= int(time.time()) + 30:
        async with httpx.AsyncClient(timeout=20) as client:
            data = {
                "client_id": STRAVA_CLIENT_ID,
                "client_secret": STRAVA_CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": t["refresh_token"],
            }
            r = await client.post(TOKEN_URL, data=data)
            r.raise_for_status()
            newt = r.json()
        t.update({
            "access_token": newt["access_token"],
            "refresh_token": newt.get("refresh_token", t["refresh_token"]),
            "expires_at": newt["expires_at"],
        })
        await redis_set(key, t)

    return t["access_token"]

@app.get("/agent/strava/athlete")
async def get_athlete(request: Request, athlete_id: str):
    if not _bearer_ok(request):
        raise HTTPException(status_code=403, detail="Forbidden")
    access = await _ensure_token(athlete_id)
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"{API_BASE}/athlete", headers={"Authorization": f"Bearer {access}"})
        r.raise_for_status()
        return r.json()

@app.get("/agent/strava/latest-activities")
async def latest_activities(request: Request, athlete_id: str, per_page: int = 30):
    if not _bearer_ok(request):
        raise HTTPException(status_code=403, detail="Forbidden")
    access = await _ensure_token(athlete_id)
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{API_BASE}/athlete/activities",
            params={"per_page": per_page},
            headers={"Authorization": f"Bearer {access}"},
        )
        r.raise_for_status()
        return r.json()
