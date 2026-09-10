"""Configuration centrale d'ArcaShield CodeSec-AI.

Ce module charge les variables d'environnement depuis le fichier `.env`
(via python-dotenv) et expose les constantes partagées par toute
l'application : clé API, modèle Gemini, langages supportés, sévérités,
seuils de score et palette de couleurs.

La clé API n'est JAMAIS écrite en dur : elle provient soit des secrets
Streamlit (`st.secrets`, déploiement Community Cloud), soit de la
variable d'environnement `GEMINI_API_KEY` (fichier `.env` en local).
"""

from __future__ import annotations

import os

import streamlit as st
from dotenv import load_dotenv

# Charge le .env situé à la racine du projet (sans écraser les variables
# déjà définies dans l'environnement du système).
load_dotenv(override=False)


# --------------------------------------------------------------------------- #
# API Gemini
# --------------------------------------------------------------------------- #
# La clé API est résolue à la demande par `resolve_api_key()` / `get_api_key()`
# (voir plus bas) afin de couvrir à la fois `st.secrets` (Streamlit Community
# Cloud) et la variable d'environnement `GEMINI_API_KEY` (fichier `.env` local).

# Modèle par défaut : rapide, large fenêtre de contexte, suffisant pour du SAST.
# Surchargeable via .env (GEMINI_MODEL).
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

# Température basse = réponses déterministes et rigoureuses (audit, pas créatif).
GEMINI_TEMPERATURE: float = float(os.getenv("GEMINI_TEMPERATURE", "0.15"))


class ConfigError(RuntimeError):
    """Erreur de configuration (ex. clé API absente)."""


def resolve_api_key() -> str | None:
    """Résout la clé API Gemini sans effet de bord sur l'interface.

    Ordre de résolution :
      1. ``st.secrets["GEMINI_API_KEY"]`` -> déploiement Streamlit Community
         Cloud. L'accès lève ``StreamlitSecretsNotFoundError`` s'il n'existe
         pas de ``secrets.toml`` (cas normal en local) ou ``KeyError`` si la
         clé est absente ; les deux sont ignorés au profit du fallback.
      2. ``os.getenv("GEMINI_API_KEY")`` -> développement local ; la valeur
         provient du fichier `.env` chargé par ``load_dotenv()`` à l'import
         de ce module.

    Retourne la clé nettoyée, ou ``None`` si aucune source ne la fournit.
    """
    try:
        secret_key = st.secrets["GEMINI_API_KEY"]
        if secret_key and secret_key.strip():
            return secret_key.strip()
    except Exception:
        pass

    env_key = os.getenv("GEMINI_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    return None


def get_api_key() -> str:
    """Retourne la clé API Gemini, quel que soit l'environnement.

    Utilisé par le client Gemini au moment de l'appel. Si aucune clé n'est
    trouvée, affiche un message d'erreur explicite via ``st.error()`` et
    interrompt proprement l'exécution du script Streamlit.
    """
    api_key = resolve_api_key()
    if api_key:
        return api_key

    st.error(
        "**Clé API Gemini introuvable.**\n\n"
        "- **En local :** créez un fichier `.env` à la racine du projet "
        "contenant `GEMINI_API_KEY=votre_cle` (voir `.env.example`).\n"
        "- **Sur Streamlit Community Cloud :** ajoutez-la dans "
        "*Manage app → Settings → Secrets* sous la forme "
        '`GEMINI_API_KEY = "votre_cle"`.',
        icon="🔑",
    )
    st.stop()
    # Jamais atteint sous Streamlit ; garde-fou si appelé hors contexte.
    raise ConfigError("Clé API Gemini introuvable.")


# --------------------------------------------------------------------------- #
# Langages supportés (extension de fichier -> libellé de langage)
# --------------------------------------------------------------------------- #
LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "Python",
    ".java": "Java",
    ".php": "PHP",
    ".sql": "SQL",
    ".js": "JavaScript",
}

# Liste ordonnée proposée dans le sélecteur de l'interface.
SUPPORTED_LANGUAGES: list[str] = ["Auto"] + list(dict.fromkeys(LANGUAGE_BY_EXTENSION.values()))

# Extensions acceptées par l'uploader de fichier Streamlit (sans le point).
ALLOWED_UPLOAD_TYPES: list[str] = [ext.lstrip(".") for ext in LANGUAGE_BY_EXTENSION]


# --------------------------------------------------------------------------- #
# Sévérités
# --------------------------------------------------------------------------- #
SEVERITY_ORDER: list[str] = ["Critique", "Moyen", "Faible"]

# Couleur associée à chaque sévérité (badges, bordures de cartes).
SEVERITY_COLOR: dict[str, str] = {
    "Critique": "#C0392B",  # rouge
    "Moyen": "#E67E22",     # orange
    "Faible": "#F1C40F",    # jaune
}

# Emoji d'accompagnement, utile dans le rapport Markdown exporté.
SEVERITY_ICON: dict[str, str] = {
    "Critique": "🔴",
    "Moyen": "🟠",
    "Faible": "🟡",
}


def severity_rank(severity: str) -> int:
    """Rang numérique d'une sévérité (0 = plus grave). Sert au tri."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


# --------------------------------------------------------------------------- #
# Score global
# --------------------------------------------------------------------------- #
SCORE_GREEN_MIN: int = 80   # score > 80  -> vert
SCORE_ORANGE_MIN: int = 50  # 50 <= score <= 80 -> orange ; < 50 -> rouge

SCORE_COLOR_GREEN: str = "#2ECC71"
SCORE_COLOR_ORANGE: str = "#E67E22"
SCORE_COLOR_RED: str = "#C0392B"


def score_color(score: float) -> str:
    """Couleur de la jauge selon le score global (0-100)."""
    if score > SCORE_GREEN_MIN:
        return SCORE_COLOR_GREEN
    if score >= SCORE_ORANGE_MIN:
        return SCORE_COLOR_ORANGE
    return SCORE_COLOR_RED


def score_label(score: float) -> str:
    """Libellé qualitatif du score, affiché sous la jauge et dans le rapport."""
    if score > SCORE_GREEN_MIN:
        return "Bon niveau de sécurité"
    if score >= SCORE_ORANGE_MIN:
        return "Sécurité perfectible"
    return "Risque élevé — corrections prioritaires"


# --------------------------------------------------------------------------- #
# Métadonnées application
# --------------------------------------------------------------------------- #
APP_NAME: str = "ArcaShield CodeSec-AI"
APP_TAGLINE: str = "Security Copilot — Audit SAST & remédiation assistée par IA"
APP_ICON: str = "🛡️"
APP_ORG: str = "ArcaShield — Cybersécurité"
