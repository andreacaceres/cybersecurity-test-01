import os
import jwt
import sqlite3
import platform
import socket
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from typing import Optional

app = FastAPI()

# Cargar configuraciones desde variables de entorno
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")
DB_PATH = os.getenv("DB_PATH", "./users.db")
JWT_EXPIRATION_MINUTES = 15

# Lista blanca de comandos permitidos
ALLOWED_COMMANDS = ["whoami", "date", "uptime"]

# --- Inicialización de la base de datos ---
@app.on_event("startup")
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')")
    conn.commit()
    conn.close()

# --- Función para generar tokens con expiración ---
def create_jwt_token(user_id: int, username: str) -> str:
    expiration = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": expiration
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# --- Middleware de autenticación ---
def verify_token(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token de autorización requerido")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# --- Endpoint de salud ---
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "message": "API funcionando"
    }

# --- Endpoint de login ---
@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Usuario y contraseña requeridos")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        token = create_jwt_token(user_id=user[0], username=user[1])
        return {"token": token}
    raise HTTPException(status_code=401, detail="Credenciales inválidas")

# --- Endpoint protegido de perfil ---
@app.get("/profile/{user_id}")
async def profile(user_id: int, payload=Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return {"id": user[0], "username": user[1]}
    raise HTTPException(status_code=404, detail="Usuario no encontrado")

# --- Endpoint protegido para ejecución de comandos ---
@app.post("/exec")
async def exec_cmd(request: Request, payload=Depends(verify_token)):
    data = await request.json()
    cmd = data.get("cmd")

    if cmd not in ALLOWED_COMMANDS:
        raise HTTPException(status_code=400, detail="Comando no permitido")

    result = os.popen(cmd).read().strip()
    return {"output": result}
