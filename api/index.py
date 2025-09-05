import os
import json
import time
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from dotenv import load_dotenv
from itsdangerous import URLSafeSerializer

# Vercel carga las env vars desde el dashboard; .env solo para local
load_dotenv()

# === ENV ===
STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")  # p.ej. https://agente-entrenador-ciclismo.vercel.app
STATE_SECRET = os.getenv("STATE_SECRET", "change-me")
AGENT_BEARER_TOKEN = os.getenv("AGENT_BEARER_TOKEN")

# Upstash Redis REST
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").rstrip("/")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")

if not BASE_URL:
    raise RuntimeError("BASE_URL no configurado")
if not STRAVA_CLIENT_ID or not STRAVA_CLIENT_SECRET:
    raise RuntimeError("Faltan STRAVA_CLIENT_ID/STRAVA_CLIENT_SECRET")
if not UPSTASH_URL or not UPSTASH_TOKEN:
    raise RuntimeError("Faltan UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN")

# === Constantes Strava ===
SCOPES = ["read", "activity:read_all"]  # Strava requiere comas entre scopes
AUTHORIZE_URL = "https://www.strava.com/oauth/authorize"
TOKEN_URL = "https://www.strava.com/oauth/token"
API_BASE = "https://www.strava.com/api/v3"

# Firmador para el state
S = URLSafeSerializer(STATE_SECRET)

app = FastAPI(title="Agente Ciclismo Backend (Vercel)")

# =========================
# Utilidades Upstash (REST)
# =========================
async def _redis_request(path: str, method: str = "GET"):
    url = f"{UPSTASH_URL}/{path}"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    async with httpx.AsyncClient(timeout=15) as client:
        if method == "GET":
            r = await client.get(url, headers=headers)
        else:
            r = await client.post(url, headers=headers)
    r.raise_for_status()
    return r.json()

async def redis_set_json(key: str, value: dict, ttl_seconds: int | None = None):
    # set key <json>
    json_str = json.dumps(value, separators=(",", ":"))
    path = f"set/{quote(key, safe='')}/{quote(json_str, safe='')}"
    await _redis_request(path, method="POST")
    if ttl_seconds and ttl_seconds > 0:
        ms = int(ttl_seconds * 1000)
        # pexpire key <ms>
        await _redis_request(f"pexpire/{quote(key, safe='')}/{ms}", method="POST")

async def redis_get_json(key: str) -> dict | None:
    data = await _redis_request(f"get/{quote(key, safe='')}")
    # Respuesta Upstash: {"result": "<string o null>"}
    raw = data.get("result")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None

async def redis_del(key: str):
    await _redis_request(f"del/{quote(key, safe='')}", method="POST")

# ======================
# Auth Bearer del agente
# ======================
def _bearer_ok(req: Request) -> bool:
    auth = req.headers.get("authorization") or req.headers.get("Authorization")
    return bool(auth and auth.split()[:1] == ["Bearer"] and auth.split()[1] == AGENT_BEARER_TOKEN)

# ======================
# Endpoints
# ======================
@app.get("/")
def root():
    return {"status": "ok", "service": "agente-ciclismo-backend"}

@app.get("/auth/strava/login")
async def strava_login():
    """
    Obliga a pasar por la pantalla de autorización de Strava.
    """
    state = S.dumps({"ts": int(time.time())})
    # OJO: Strava quiere el scope separado por COMAS
    scope = ",".join(SCOPES)
    auth_url = (
        f"{AUTHORIZE_URL}"
        f"?client_id={STRAVA_CLIENT_ID}"
        f"&redirect_uri={BASE_URL}/auth/strava/callback"
        f"&response_type=code"
        f"&scope={scope}"
        f"&state={state}"
        f"&approval_prompt=auto"
    )
    return RedirectResponse(url=auth_url)

@app.get("/auth/strava/callback")
async def strava_callback(code: str, state: str):
    # Validar state
    try:
        S.loads(state)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state")

    # Intercambiar code por tokens
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

    # Guardar en Redis (TTL opcional según expiry)
    # expires_at viene en segundos epoch
    expires_at = int(token.get("expires_at", 0))
    # Guardamos todo lo necesario
    stored = {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token"),
        "expires_at": expires_at,
        "athlete_id": athlete_id,
    }
    key = f"athlete:{athlete_id}:token"
    ttl = max(0, expires_at - int(time.time()) - 30)  # un poco antes
    await redis_set_json(key, stored, ttl_seconds=ttl if ttl > 0 else None)

    return JSONResponse({"message": "Strava conectado", "athlete_id": athlete_id})

@app.post("/auth/strava/logout")
async def strava_logout(athlete_id: str):
    key = f"athlete:{athlete_id}:token"
    await redis_del(key)
    return {"ok": True}

# ===== Helpers Strava =====
async def _ensure_token(athlete_id: str) -> str:
    """
    Lee token de Redis; si está caducado, lo refresca y vuelve a guardar.
    """
    key = f"athlete:{athlete_id}:token"
    t = await redis_get_json(key)
    if not t:
        raise HTTPException(status_code=401, detail="Conecta Strava primero")

    # ¿Caducado?
    if int(t.get("expires_at", 0)) <= int(time.time()) + 30:
        async with httpx.AsyncClient(timeout=20) as client:
            data = {
                "client_id": STRAVA_CLIENT_ID,
                "client_secret": STRAVA_CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": t.get("refresh_token"),
            }
            r = await client.post(TOKEN_URL, data=data)
            r.raise_for_status()
            newt = r.json()

        # Actualizar y guardar en Redis con nuevo TTL
        t.update({
            "access_token": newt["access_token"],
            "refresh_token": newt.get("refresh_token", t.get("refresh_token")),
            "expires_at": int(newt["expires_at"]),
        })
        ttl = max(0, t["expires_at"] - int(time.time()) - 30)
        await redis_set_json(key, t, ttl_seconds=ttl if ttl > 0 else None)

    return t["access_token"]

# ===== Endpoints para el Agente (protegidos con Bearer interno) =====
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
