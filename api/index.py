import os
import time
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from dotenv import load_dotenv
from itsdangerous import URLSafeSerializer

# Vercel loads env vars from dashboard; .env is only for local dev
load_dotenv()

STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")  # e.g. https://your-project.vercel.app/api
STATE_SECRET = os.getenv("STATE_SECRET", "change-me")
AGENT_BEARER_TOKEN = os.getenv("AGENT_BEARER_TOKEN")

app = FastAPI(title="Agente Ciclismo Backend (Vercel)")

# In-memory token store (replace with a DB for production)
TOKENS = {}
S = URLSafeSerializer(STATE_SECRET)

SCOPES = ["read", "activity:read_all"]
AUTHORIZE_URL = "https://www.strava.com/oauth/authorize"
TOKEN_URL = "https://www.strava.com/oauth/token"
API_BASE = "https://www.strava.com/api/v3"


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

    # Strava quiere el scope separado por COMAS, y la redirect_uri debe estar URL-encoded
    params = {
        "client_id": STRAVA_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/auth/strava/callback",
        "response_type": "code",
        "scope": ",".join(SCOPES),  # <= importante
        "state": state,
        "approval_prompt": "auto",
    }

    qp = httpx.QueryParams(params)  # construye la query string correctamente
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

    TOKENS[str(athlete_id)] = {
        "access_token": token["access_token"],
        "refresh_token": token["refresh_token"],
        "expires_at": token["expires_at"],
    }

    return JSONResponse({"message": "Strava conectado", "athlete_id": athlete_id})


async def _ensure_token(athlete_id: str) -> str:
    t = TOKENS.get(athlete_id)
    if not t:
        raise HTTPException(status_code=401, detail="Conecta Strava primero")
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
