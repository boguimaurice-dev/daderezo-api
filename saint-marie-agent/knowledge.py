#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Saint-Marie agent — base de connaissances du monastère
Monastère Bénédictin Sainte-Marie de Bouaké
36 fiches, 14 catégories, 17 avec [[À COMPLÉTER…]]
Source: AGENT_SPEC SOEUR MARIE.md + site benedictinsbouake.com
"""

KNOWLEDGE = {
    "L'accueil": [
        ("L'hôtellerie", "L'hôtellerie du Monastère Bénédictin Sainte-Marie de Bouaké accueille tous ceux et toutes celles qui désirent vivre un temps de retraite, de silence, de ressourcement. Hormis le silence à respecter, le rythme de la vie de la Communauté n'est pas imposé aux hôtes."),
        ("L'esprit bénédictin", "Saint Benoît, chapitre 53 de sa Règle : « Tous les hôtes qui se présentent seront reçus comme le Christ. » L'accueil est une charité chrétienne, la première étape du chemin spirituel."),
        ("Silence et clôture", "Le silence est un cahier des charges. Il doit être respecté. La clôture monastique est observée : les hôtes doivent être conscients qu'ils entrent dans un lieu de prière et de retraite."),
    ],
    "Les offices": [
        ("Horaires semaine", "5 h 25 — LAUDES · 6 h 20 — MESSES · 9 h — TIERCE · 12 h 00 — SEXT · 14 h 40 — NONE · 17 h 30 — VÊPRES · 20 h 30 — VIGILES"),
        ("Horaires dimanche", "6 h 50 — LAUDES · 10 h — MESSES · (autres offices selon calendrier)"),
        ("Participation aux offices", "Toutes les prières ne sont pas obligatoires. L'hôte est libre de choisir sa participation selon sa vocation et sa disponibilité."),
    ],
    "La vie de la communauté": [
        ("Nombre de membres", "Une vingtaine de membres (moines et oblats) de la communauté de Bouaké."),
        ("Fondation", "La communauté a été fondée en 1960 par les moines de Toumliline."),
        ("Alliance", "L'alliance avec l'Abbaye d'En Calcat."),
        ("Travail manuel", "Le travail manuel est une forme de prière et de vie communautaire."),
        ("Les sept offices", "La vie liturgique est structurée autour des sept offices du jour : Laudes, Messe, Tierce, Sext, None, Vêpres, Vigiles."),
    ],
    "Le séjour": [
        ("Durée", "Les séjours sont généralement de une à plusieurs semaines selon les disponibilités et la demande."),
        ("Chambres", "Chambres ventilées avec moustiquaire, salle d'eau individuelle."),
        ("Repas", "Pension complète (3 repas) ou demi-pension (déjeuner) selon le choix."),
        ("Ce qu'il faut apporter", "Draps et linge de lit (disponibles sur demande), Bible / ouvrages spirituels, vêtements chaleureux (nuits fraîches), articles de toilette, mode de combustion interdite dans les locaux."),
        ("[[À COMPLÉTER…]]", "Offre conseillée, durée maximale d'un séjour, tarifs indicatifs, espaces d' wifi."),
    ],
    "Les règles de la maison": [
        ("Silence", "Silence à respecter comme un cahier des charges."),
        ("Clôture monastique", "La clôture monastique est observée."),
        ("Tenue", "Tenue simple et décente, conforme à l'esprit de la vie communautaire."),
        ("Tabac et alcool", "Tabac et alcool restreints dans les locaux du monastère."),
    ],
    "L'offrande": [
        ("Participation financière", "L'offrande conseillée est un libre gage de l'hospitalité. Les frères peuvent la préciser selon les circonstances."),
        ("[[À COMPLÉTER…]]", "Montant conseillé, facilités éventuelles, modalités de paiement."),
    ],
    "L'accès": [
        ("Adresse", "Monastère Bénédictin Sainte-Marie, Bouaké, Côte d'Ivoire. Axe de Brobo, juste après le Centre Diocésain Saint Joseph."),
        ("Depuis Abidjan", "Environ 3 heures en voiture par la route nationale, selon les conditions du trajet."),
        ("Depuis Bouaké", "Depuis le centre de Bouaké, suivre les panneaux vers la commune du monastère."),
        ("Transport", "L'accueil peut fournir des indications sur les options de transport disponibles."),
    ],
    "Les contacts": [
        ("Téléphone accueil", "07 47 52 05 57"),
        ("Téléphone hôtellerie", "07 97 00 80 52"),
        ("Téléphone boutique", "07 78 32 17 37"),
        ("Courriel", "info@benedictinsbouake.com"),
        ("Site web", "https://benedictinsbouake.com"),
    ],
    "La santé": [
        ("Paludisme", "Bouaké est dans une zone de transmission du paludisme. Les hôtes sont informés des précautions : répulsifs, imprégnations,-traitements prophylactiques consulting a un médecin."),
        ("Urgence", "En cas de maladie ou d'urgence, appelez immédiatement les secours, puis l'accueil du monastère. Le numéro d'accueil est 07 47 52 05 57."),
        ("[[À COMPLÉTER…]]", "Équipements médicaux sur place, cliniques les plus proches, médicaments courants disponibles."),
    ],
    "Les groupes": [
        ("Sessions", "Le monastère accueille les groupes pour des retraites, des sessions de silence, des missions de travail."),
        ("Capacité", "La capacité d'accueil d'un groupe est limitée et précisée selon les disponibilités."),
        ("[[À COMPLÉTER…]]", "Capacité maximale par groupe, tarification groupale, quadrième de chambre, animations prévues."),
    ],
    "La vocation": [
        ("Devenir moine", "La communauté accueille ceux qui désirent entrer dans la vie monastique. Un discernement vocationnel est nécessaire."),
        ("Oblature", "L'oblature est le signe de l'alliance avec l'Abbaye d'En Calcat."),
        ("[[À COMPLÉTER…]]", "Année d'ouverture au noviciat, durée du noviciat, prérequis."),
    ],
    "Le Studium": [
        ("Formation", "Le Studium est une formation philosophique et théologique proposée par la communauté."),
        ("Public", "Destiné aux personnes qui désirent approfondir leur vie spirituelle et intellectuelle."),
        ("[[À COMPLÉTER…]]", "Établissements, durée, modalités d'accès."),
    ],
    "La boutique": [
        ("Produits", "Confitures (orange, papaye, mangue, pamplemousse), miel non brulé (80 cl), nougatine, thé de Gambie."),
        ("Commande", "La boutique en ligne est accessible sur le site benedictinsbouake.com."),
        ("Contact", "07 78 32 17 37"),
    ],
    "Divers": [
        ("Données personnelles", "Les données personnelles des hôtes sont traitées conformément à la réglementation en vigueur. Elles ne sont communiquées qu'aux frères responsables de l'hôtellerie."),
        ("Climat", "Bouaké a un climat tropical avec des nuits fraîches. Vêtements chaleureux sont recommandés."),
        ("Soutien", "Pour les difficultés financières, le monastère peut proposer des facilités. Demander à l'accueil."),
        ("Sens de « Pax»", "« Pax » est une formule de salutation paix, inspirée du latin « pax » (paix), répandue dans la tradition chrétienne."),
        ("[[À COMPLÉTER…]]", "Heure de fermeture du portail d'accueil, horaires d'ouverture du monastère, informations sur l'ambiance du monastère."),
    ],
}
