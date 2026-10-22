#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Saint-Marie agent — serveur FastAPI
Expose l'agent via une API REST et sert les pages HTML
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
import asyncio
from datetime import datetime, timezone

from saint_marie_agent import SaintMarieAgent
from saint_marie_db import get_conn, log as db_log

HERE = os.path.dirname(os.path.abspath(__file__))

# Servir les fichiers statiques
import os
STATIC_DIR = os.path.join(HERE, "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

agent = SaintMarieAgent()

# ---------- Modèles de requêtes ----------
class ChatMessage(BaseModel):
    text: str
    channel: str = "website"

class AvailabilityRequest(BaseModel):
    dates: str
    nb_personnes: str

class BookingRequest(BaseModel):
    hote: str
    dates: str
    motif: str
    besoins: str

# ---------- Routes ----------
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(open("static/chat.html").read())

@app.get("/api/knowledge")
async def get_knowledge(category: str = None):
    conn = get_conn()
    if category:
        rows = conn.execute(
            "SELECT category, title, body FROM knowledge WHERE lower(category) = ?",
            (category,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT category, title, body FROM knowledge LIMIT 20"
        ).fetchall()
    conn.close()
    return {"knowledge": [dict(r) for r in rows]}

@app.post("/api/chat")
async def chat(message: ChatMessage):
    reply = agent.chat(message.text, message.channel)
    return JSONResponse({"reply": reply, "intent": agent.classify_intent(message.text)})

@app.post("/api/availability")
async def availability(req: AvailabilityRequest):
    reply = agent.verifier_disponibilite(req.dates, req.nb_personnes)
    return JSONResponse({"reply": reply})

@app.post("/api/booking")
async def booking(req: BookingRequest):
    req_id = agent.enregistrer_demandes(req.hote, req.dates, req.motif, req.besoins)
    notif = agent.notifier_hoteliers(req_id)
    return JSONResponse({
        "request_id": req_id,
        "notifier_sent": notif.get("ok", False),
        "to_monks": notif.get("sent_to", "")
    })

@app.post("/api/relay")
async def relay(req: BookingRequest):
    """Relayer une demande complète au tableau de bord des moines."""
    req_id = agent.enregistrer_demandes(req.hote, req.dates, req.motif, req.besoins)
    notif = agent.notifier_hoteliers(req_id)
    return JSONResponse({
        "status": "relayée",
        "request_id": req_id,
        "notifier_sent": notif.get("ok", False),
        "notifier_to": notif.get("sent_to", "")
    })

@app.get("/api/dashboard")
async def get_dashboard():
    conn = get_conn()
    requests = conn.execute(
        "SELECT * FROM requests ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    notifications = conn.execute(
        "SELECT request_id, subject, body, sent_at, read FROM notifications ORDER BY id DESC LIMIT 20"
    ).fetchall()
    log_entries = conn.execute(
        "SELECT ts, level, message FROM log ORDER BY id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return {
        "requests": [dict(r) for r in requests],
        "notifications": [dict(n) for n in notifications],
        "log": [dict(l) for l in log_entries]
    }

@app.post("/api/dashboard/read/{request_id}")
async def mark_read(request_id: str):
    conn = get_conn()
    conn.execute(
        "UPDATE notifications SET read = 1 WHERE request_id = ?",
        (request_id,)
    )
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok"})

# ---------- Point de terminaison pour le monitor ----------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "Saint-Marie Agent"}

if __name__ == "__main__":
    import uvicorn
    print("🚀 Saint-Marie Agent démarré")
    print("📡 API: http://localhost:8000")
    print("💬 Chat: http://localhost:8000/")
    print("📊 Tableau de bord: http://localhost:8000/dashboard")
    uvicorn.run(app, host="0.0.0.0", port=8000)
