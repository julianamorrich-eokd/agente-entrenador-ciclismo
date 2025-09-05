import os
import time
import json
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from dotenv import load_dotenv
from itsdangerous import URLSafeSerializer

# ---- Redis (Upstash) ----
try:
    from upstash_redis.asyncio import Redis
except Exception:
    Redis = None  # por si la librería aún no está instalada en build

# Vercel loads env vars; .env solo para local
load_dotenv()

STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")  # e.g. https://tu-proyecto.vercel.app
STATE_SECRET = os.getenv("STATE_SECRET", "change-me")
AGENT_BEARER_TOKEN = os.getenv("AGENT_BEARER_TOKEN")

# Endpoints Strava
SCOPES = ["read", "activity:read_all"]
AUTHORIZE_URL = "https://www.strava.com/oauth/authorize"
TOKEN_URL = "https://www.strava.com/oauth/token"
API_BASE = "https://www.strava.com/api/v3"

app = FastAPI(title="Agente Ciclismo Backend (Vercel)")
S = URLSafeSerializer(STATE_SECRET)

# ---- Redis client desde variables de entorno ----
redis = None
if Redis and os.getenv("UPSTASH_REDIS_REST_URL") and os.getenv("UPSTASH_REDIS_REST_TOKEN"):
    redis = Redis.from_env()

def _bearer_ok(req: Request) -> bool:
    auth = req.headers.get("authorization") or req.headers.get("Authorization")
    return bool(auth and auth.split()[:1] == ["Bearer"] and auth.split()[1] == AGENT_BEARER_TOKEN)

@app.get("/")
def root():
    return {"status": "ok", "service": "agente-ciclismo-backend"}

# ---------- Helpers de token (Redis) ----------
async def _redis_set_token(athlete_id: str, token_dict: dict):
    """Guarda el token en Redis bajo la clave tokens:{athlete_id}."""
    if not redis:
        return  # sin Redis, no persistimos (fallback no recomendado)
    # Guardamos como JSON
    await redis.set(f"tokens:{athlete_id}", json.dumps(token_dict))

async def _redis_get_token(athlete_id: str) -> dict | None:
    if not redis:
        return None
    val = await redis.get(f"tokens:{athlete_id}")
    if not val:
        return None
    try:
        return json.loads(val)
    except Exception:
        return None

# ---------- Flujo OAuth ----------
@app.get("/auth/strava/login")
async def strava_login():
    if not BASE_URL:
        raise HTTPException(status_code=500, detail="BASE_URL not configured")
    state = S.dumps({"ts": int(time.time())})
    params = {
        "client_id": STRAVA_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/auth/strava/callback",
        "response_type": "code",
        "approval_prompt": "auto",
        # OJO: Strava prefiere scopes con coma o espacio; aquí usamos coma
        "scope": ",".join(SCOPES),
        "state": state,
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

    token_record = {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token"),
        "expires_at": token.get("expires_at"),
    }
    await _redis_set_token(str(athlete_id), token_record)

    return JSONResponse({"message": "Strava conectado", "athlete_id": athlete_id})

# ---------- Renovación/lectura del token ----------
async def _ensure_token(athlete_id: str) -> str:
    t = await _redis_get_token(athlete_id)
    if not t:
        # No hay token para ese atleta en Redis
        raise HTTPException(status_code=401, detail="Conecta Strava primero")

    # Si está por expirar, refrescamos
    if t.get("expires_at") and t["expires_at"] <= int(time.time()) + 30:
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
        # Actualizamos en Redis
        t.update({
            "access_token": newt["access_token"],
            "refresh_token": newt.get("refresh_token", t.get("refresh_token")),
            "expires_at": newt.get("expires_at"),
        })
        await _redis_set_token(athlete_id, t)

    return t["access_token"]

# ---------- Endpoints protegidos para el GPT ----------
@app.get("/agent/strava/athlete")
async def get_athlete(request: Request, athlete_id: str):
    if not _bearer_ok(request):
        raise HTTPException(status_code=403, detail="Forbidden")
    access = await _ensure_token(athlete_id)
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"{API_BASE}/athlete",
                             headers={"Authorization": f"Bearer {access}"})
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
