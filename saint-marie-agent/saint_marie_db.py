#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Saint-Marie agent — couche base de données (SQLite)
Tables : knowledge, conversations, requests, notifications
"""
import sqlite3, os, json
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "saint_marie.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    -- Connaissances partagées (extraits textuels)
    CREATE TABLE IF NOT EXISTS knowledge (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        title TEXT,
        body TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Conversations en cours (ID anonyme + état)
    CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        channel TEXT NOT NULL,            -- whatsapp | website | email | manual
        status TEXT NOT NULL,             -- new | qualifying | completed | relayed | closed
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    -- Demandes de séjour
    CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL,
        host_name TEXT,
        host_origin TEXT,
        stay_type TEXT,
        arrival TEXT,
        departure TEXT,
        people INTEGER,
        needs TEXT,
        status TEXT NOT NULL DEFAULT 'pending_receiving',  -- pending_receiving | pending_review | accepted | rejected | completed
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (conversation_id) REFERENCES conversations(id)
    );

    -- Notifications envoyées aux frères hôteliers
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT NOT NULL,
        target TEXT NOT NULL,             -- email | whatsapp_group | dashboard
        subject TEXT,
        body TEXT NOT NULL,
        sent_at TEXT,
        read INTEGER NOT NULL DEFAULT 0
    );

    -- Journal des actions de l'agent
    CREATE TABLE IF NOT EXISTS log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        level TEXT NOT NULL,              -- info | warning | error
        message TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_requests_conv ON requests(conversation_id);
    CREATE INDEX IF NOT EXISTS idx_notif_req ON notifications(request_id);
    CREATE INDEX IF NOT EXISTS idx_log_ts ON log(ts);
    """)
    conn.commit()

    # Insertion des connaissances monographiques initiales
    insert_knowledge(conn, "monastery", "Identification du monastère", 
        "Monastère Bénédictin Sainte-Marie de Bouaké — Côte d'Ivoire. Site : benedictinsbouake.com.")
    insert_knowledge(conn, "monastery", "Phones d'appel",
        "Accueil : 07 47 52 05 57 | Hôtellerie : 07 97 00 80 52 | Boutique : 07 77 13 80 84")
    insert_knowledge(conn, "hospitality", "Horaires de la vie monastique (semaine)",
        "Laudes 5h25 · Messe 6h20 · Tierce 9h · Sext 12h · None 14h40 · Vêpres 17h30 · Vigiles 20h30")
    insert_knowledge(conn, "hospitality", "Mode d'accueil",
        "L'hôtellerie accueille les retraites, le silence et le ressourcement. Silence à respecter; le rythme "
        "de la communauté n'est pas imposé aux hôtes. Chambres disponibles, pension complète ou demi-pension.")
    insert_knowledge(conn, "hospitality", "Ce qu'il faut apporter",
        "Draps et linge (sur demande) · Bible / ouvrages spirituels · Vêtements chaleureux (nuits fraîches) · "
        "Toilette personnelle · Mode de combustion interdite")
    insert_knowledge(conn, "hospitality", "Modes de pensions",
        "Pension complète (3 repas) · Pension demi-pension (déjeuner) · Régime spécial sur demande")
    conn.commit()
    conn.close()
    log("info", "Base de données de l'agent Sœur Marie initialisée", DB_PATH)

def insert_knowledge(conn, category, title, body):
    conn.execute(
        "INSERT INTO knowledge (category, title, body) VALUES (?, ?, ?)",
        (category, title, body)
    )

def log(level, message, extra=None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO log (ts, level, message) VALUES (datetime('now'), ?, ?)",
        (level, message)
    )
    conn.commit()
    conn.close()
    print(f"[{level.upper()}] {message}")

if __name__ == "__main__":
    init_db()
