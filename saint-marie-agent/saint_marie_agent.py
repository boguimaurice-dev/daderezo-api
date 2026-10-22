#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Saint-Marie agent — moteur de dialogue selon la spécification officielle
Source: AGENT_SPEC SOEUR MARIE.md
"""
import random, re, json, os, uuid
from datetime import datetime, timezone, timedelta
from knowledge import KNOWLEDGE

HERE = os.path.dirname(os.path.abspath(__file__))


class SaintMarieAgent:
    """Agent Sœur Marie selon le cahier des charges officiel."""

    def __init__(self):
        self.log = []
        self.state = {}
        self._first_message = True  # première phrase → salutation

    def _log(self, level, message):
        self.log.append({"ts": datetime.now(timezone.utc).isoformat(), "level": level, "message": message})
        print(f"[{level.upper()}] {message}")

    def now_str(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _is_emergency(self, text):
        t = text.lower()
        for kw in ["urgent", "urgence", "malade", "maladie", "grave", "secours"]:
            if kw in t:
                return True
        return False

    def _is_out_of_base(self, text):
        t = text.lower()
        out_of_base = [
            "capitale du burkina", "capitale du", "capitale de la",
            "pouvoir de", "gouvernement de", "président de", "modèle de",
            "monnaie", "devise", "mariage", "divorce", "sport", "danse",
            "météo", "température", "humidité", "géographie", "histoire de",
            "nom de", "qu'est-ce que", "qui est", "comment s'appelle",
            "combien coûte", "prix de", "tarif de", "prix", "tarif",
        ]
        for phrase in out_of_base:
            if phrase in t:
                return True
        return False

    def _find_best_knowledge(self, question):
        q = question.lower()
        best_fiche = None
        best_score = 0
        for category, fiches in KNOWLEDGE.items():
            for title, content in fiches:
                score = 0
                words = q.split()
                for w in words:
                    if w in content.lower():
                        score += 1
                    if w in title.lower():
                        score += 2
                if re.search(r'\d+', q) and re.search(r'\d+', content):
                    score += 1
                if score > best_score:
                    best_score = score
                    best_fiche = (category, title, content)
        if best_score < 2:
            return None, "aucune_fiche"
        return best_fiche, "trouvée"

    def _is_blank_fiche(self, content):
        return "[[À COMPLÉTER" in content

    def _remove_placeholder(self, content):
        return content.replace("[[À COMPLÉTER…]]", "").replace("[[À COMPLÉTER]]", "").strip()

    def _get_casual_date(self, text):
        t = text.lower()
        iso_match = re.search(r'(\d{4})-(\d{2})-(\d{2})\s*(?:au|à|et|vers?)\s*(\d{4})-(\d{2})-(\d{2})', t)
        if iso_match:
            return f"{iso_match.group(1)}-{iso_match.group(2)}-{iso_match.group(3)} → {iso_match.group(4)}-{iso_match.group(5)}-{iso_match.group(6)}"
        numeric = re.search(r'(\d{1,2})/(\d{1,2})\s*(?:au|à|et|vers?)\s*(\d{1,2})/(\d{1,2})', t)
        if numeric:
            return f"{numeric.group(1)}/{numeric.group(2)} → {numeric.group(3)}/{numeric.group(4)}"
        month = {"janv": "01", "févr": "02", "mar": "03", "avr": "04", "mai": "05", "juin": "06", "juil": "07", "aoû": "08", "sep": "09", "oct": "10", "nov": "11", "déc": "12"}
        month_range = re.search(r'du\s+(\d{1,2})\s+(janv|févr|mar|avr|mai|juin|juil|aoû|sep|oct|nov|déc)[a-z]*\s+au\s+(\d{1,2})\s+(janv|févr|mar|avr|mai|juin|juil|aoû|sep|oct|nov|déc)[a-z]*', t)
        if month_range:
            d1, m1 = month_range.group(1), month_range.group(2)
            d2, m2 = month_range.group(3), month_range.group(4)
            year = "2026" if "2026" in text else str(datetime.now().year)
            return f"{d1}/{month[m1]}/{year} → {d2}/{month[m2]}/{year}"
        if "demain" in t:
            return f"demain (~{(datetime.now() + timedelta(days=1)).strftime('%d/%m/%Y')})"
        if "semaine prochaine" in t:
            return f"semaine prochaine (~{(datetime.now() + timedelta(days=7)).strftime('%d/%m/%Y')})"
        return None

    def _get_composition(self, text):
        t = text.lower()
        if "seul" in t or "seule" in t:
            return "1 personne"
        if "couple" in t:
            return "2 personnes (un couple)"
        if "8 personnes" in t or "8 pers" in t:
            return "8 personnes"
        if "groupe" in t:
            match = re.search(r'(\d+)\s*personnes', text)
            if match:
                return f"{match.group(1)} personnes (groupe)"
            return "groupe"
        if "nous serons" in t:
            match = re.search(r'(\d+)\s*personnes', text)
            if match:
                return f"{match.group(1)} personnes"
        return None

    def _get_needs(self, text):
        t = text.lower()
        needs = []
        if "végétarien" in t or "sans porc" in t:
            needs.append("régime végétarien")
        if "diabétique" in t or "diabète" in t:
            needs.append("régime diabétique")
        if "allergie" in t:
            needs.append("allergie alimentaire")
        if "fauteuil" in t or "roulant" in t:
            needs.append("accessibilité (fauteuil roulant)")
        if "difficulté" in t and "marcher" in t:
            needs.append("accessibilité")
        if "office" in t and ("participant" in t or "assister" in t):
            needs.append("participation aux offices")
        if "rien de particulier" in t or "aucun" in t:
            return "aucun"
        if "première visite" in t or "découverte" in t:
            needs.append("première visite")
        if "sens de pax" in t or "pax" in t:
            needs.append("sens de la formule « Pax »")
        return ", ".join(needs) if needs else None

    def _get_stay_type(self, text):
        t = text.lower()
        if "retraite" in t:
            return "retraite spirituelle"
        if "couple" in t:
            return "temps de repos (couple)"
        if "groupe" in t:
            return "groupe ou session"
        if "mission" in t:
            return "mission de travail"
        if "vocation" in t or "devenir moine" in t:
            return "discernement vocationnel"
        if "repos" in t:
            return "temps de repos"
        return "retraite spirituelle"

    def _normalize_date(self, text):
        """Extraire et normaliser les dates."""
        t = text.lower()
        # Formats numériques : 12/10 au 15/10
        numeric = re.search(r'(\d{1,2})/(\d{1,2})\s*(?:au|à|et|vers?)\s*(\d{1,2})/(\d{1,2})', t)
        if numeric:
            return f"{numeric.group(1)}/{numeric.group(2)} → {numeric.group(3)}/{numeric.group(4)}"
        # "du 12 octobre au 15 octobre"
        month = {"janv": "01", "févr": "02", "mar": "03", "avr": "04", "mai": "05", "juin": "06",
                 "juil": "07", "aoû": "08", "sep": "09", "oct": "10", "nov": "11", "déc": "12"}
        month_range = re.search(r'du\s+(\d{1,2})\s+(janv|févr|mar|avr|mai|juin|juil|aoû|sep|oct|nov|déc)[a-z]*\s+au\s+(\d{1,2})\s+(janv|févr|mar|avr|mai|juin|juil|aoû|sep|oct|nov|déc)[a-z]*', t)
        if month_range:
            d1, m1 = month_range.group(1), month_range.group(2)
            d2, m2 = month_range.group(3), month_range.group(4)
            year = "2026" if "2026" in text else str(datetime.now().year)
            return f"{d1}/{month[m1]}/{year} → {d2}/{month[m2]}/{year}"
        # "2026-12-01 au 2026-12-05"
        iso = re.search(r'(\d{4})-(\d{2})-(\d{2})\s*au\s*(\d{4})-(\d{2})-(\d{2})', t)
        if iso:
            return f"{iso.group(1)}-{iso.group(2)}-{iso.group(3)} → {iso.group(4)}-{iso.group(5)}-{iso.group(6)}"
        return None

    def chat(self, text, channel="website"):
        self._log("info", f"chat (channel={channel}): {text[:100]}...")
        text_lower = text.lower().strip()

        # 1. Urgence
        if self._is_emergency(text):
            return (
                "Pour toute urgence, appelez immédiatement le monastère :\n"
                "   Accueil : 07 47 52 05 57\n"
                "   Hôtellerie : 07 97 00 80 52\n"
                "En cas d'urgence médicale grave, appelez d'abord les secours.\n"
                "Je préviens également les frères.\n"
                "Que Dieu vous garde."
            )

        # 2. Greeting — première phrase de la conversation
        if self._first_message:
            self._first_message = False
            return (
                "Pax. Bienvenue à l'hôtellerie du Monastère Sainte-Marie de Bouaké.\n"
                "Que la paix soit avec vous.\n"
                "Je suis Sœur Marie, la sœur hôtelière numérique du monastère. "
                "Comment puis-je vous aider aujourd'hui ? "
                "Souhaitez-vous un renseignement, ou préparer une demande de séjour ?"
            )

        # 3. Out of base
        if self._is_out_of_base(text):
            return (
                "Je n'ai pas la réponse exacte à cette question dans ce que la maison "
                "m'a confié, et je ne veux rien vous dire d'inexact.\n"
                "Je transmets votre question aux frères : ils vous répondront "
                "directement. Vous pouvez aussi appeler l'hôtellerie au 07 97 00 80 52.\n"
                "Souhaitez-vous autre chose entre-temps ?"
            )

        # 4. Search knowledge
        best_fiche, status = self._find_best_knowledge(text)
        reply = ""

        if best_fiche:
            category, title, content = best_fiche
            if "[[À COMPLÉTER" in content:
                content = self._remove_placeholder(content)
                reply = f"J'ai noté ce que vous m'avez dit :\n• {title}: {content}\nJe ne possède pas encore la réponse à ce point précis. Je le transmets aux frères qui vous répondront sans délai."
            else:
                reply = f"Voici ce que je peux vous dire :\n\n{content}"

        else:
            # No knowledge — check if it's about a stay/retreat
            if any(k in text_lower for k in ["retraite", "séjour", "sejour", "stage", "session", "demande", "venir", "réserver", "réservation"]):
                reply = "Je n'ai pas d'information spécifique à ce sujet dans ma base, mais je peux vous aider à préparer votre demande. Veuillez me donner votre nom, puis la période souhaitée."
            else:
                reply = (
                    "Je n'ai pas la réponse exacte à cette question dans ce que la maison "
                    "m'a confié, et je ne veux rien vous dire d'inexact.\n"
                    "Je transmets votre question aux frères : ils vous répondront "
                    "directement. Vous pouvez aussi appeler l'hôtellerie au 07 97 00 80 52."
                )

        # 5. Collect information for booking
        if any(k in text_lower for k in ["retraite", "séjour", "sejour", "stage", "session", "demande", "venir", "réserver"]):
            reply += "\n\nPuis-je vous aider à préparer votre demande de séjour ?"
            if "votre demande est" in reply or "notez" in reply or "récapitul" in reply:
                pass

        return reply

    def finalize_booking(self, conversation_id):
        conn = saint_marie_db.get_conn()
        rows = conn.execute(
            "SELECT * FROM requests WHERE conversation_id=? ORDER BY id DESC LIMIT 1",
            (conversation_id,)
        ).fetchall()
        if not rows:
            return {"error": "Aucune demande en cours."}
        r = rows[0]
        summary = (
            f"FICHE DE DEMANDE — Hôtellerie Sainte-Marie Bouaké\n"
            f"👤 Hôte : {r['host_name'] or '—'}\n"
            f"📍 Origine : {r['host_origin'] or '—'}\n"
            f"🎯 Motif : {r['stay_type'] or '—'}\n"
            f"📅 Arrivée : {r['arrival'] or '—'}\n"
            f"⇧ Départ : {r['departure'] or '—'}\n"
            f"👥 {r['people']} personne(s)\n"
            f"📋 Besoins : {r['needs'] or '—'}\n"
            f"✅ Statut : En attente de validation des frères"
        )
        return {"summary": summary, "request_id": r["id"], "to_monks": "groupe WhatsApp des frères hôteliers"}

    def reset(self):
        self.state = {}
        self._first_message = True
