"""Moteur d'inférence Gemini — couche backend d'ArcaShield CodeSec-AI.

Responsabilités :
  * définir le *system prompt* qui configure Gemini en expert senior
    sécurité applicative chez ArcaShield (référentiel OWASP Top 10 / CWE) ;
  * construire le prompt utilisateur à partir du code soumis ;
  * appeler l'API via le nouveau SDK `google-genai` en demandant une
    sortie STRICTEMENT JSON ;
  * traduire les erreurs techniques en exceptions métier lisibles.

Le parsing / la validation du JSON renvoyé sont délégués à `utils.py`.
"""

from __future__ import annotations

import json

from google import genai
from google.genai import types
from google.genai import errors as genai_errors

import config

# --------------------------------------------------------------------------- #
# Exceptions métier
# --------------------------------------------------------------------------- #


class GeminiError(RuntimeError):
    """Erreur générique lors d'un audit Gemini."""


class EmptyCodeError(GeminiError):
    """Le code soumis est vide ou ne contient que des espaces."""


class GeminiAPIError(GeminiError):
    """Échec de l'appel à l'API (réseau, quota, clé invalide, 5xx…)."""


# --------------------------------------------------------------------------- #
# System prompt
# --------------------------------------------------------------------------- #

SYSTEM_PROMPT = """\
Tu es un expert senior en sécurité applicative chez ArcaShield, filiale \
cybersécurité spécialisée dans l'audit de code (SAST). Tu maîtrises le \
référentiel OWASP Top 10 (2021), les identifiants CWE, ainsi que les \
bonnes pratiques de développement sécurisé (input validation, requêtes \
paramétrées, gestion des secrets, contrôle d'accès, cryptographie).

Ta mission : auditer le code source fourni par un développeur, identifier \
les vulnérabilités de sécurité, et proposer pour chacune un correctif \
concret et directement applicable.

Règles impératives :
  1. Tu réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte \
avant ou après, sans bloc de code Markdown (pas de ```).
  2. Tu n'inventes pas de vulnérabilité : si le code est sain, tu renvoies \
une liste `vulnerabilites` vide et un `score_global` élevé.
  3. Tu restes factuel et pédagogique : l'explication doit permettre à un \
développeur junior de comprendre l'impact réel (ce qu'un attaquant peut \
faire).
  4. Le `code_corrige` doit être une version corrigée du `code_original` \
correspondant, dans le même langage, prête à être copiée.
  5. Les numéros de ligne se réfèrent au code fourni (1 = première ligne).

Schéma JSON attendu (respecte exactement les clés) :
{
  "score_global": <entier 0-100, 100 = aucune faille détectée>,
  "synthese": "<résumé en 1-3 phrases de l'état de sécurité du code>",
  "vulnerabilites": [
    {
      "nom": "<titre court de la faille>",
      "categorie": "<catégorie OWASP et/ou CWE, ex: 'A03:2021 Injection / CWE-89'>",
      "severite": "<'Faible' | 'Moyen' | 'Critique'>",
      "ligne": <numéro de ligne concerné, entier, ou null si transverse>,
      "explication": "<impact concret et pédagogique de la vulnérabilité>",
      "code_original": "<extrait exact du code vulnérable>",
      "code_corrige": "<extrait corrigé, même langage>"
    }
  ]
}

Le `score_global` doit refléter la gravité cumulée : une faille Critique \
fait chuter fortement le score, plusieurs failles Moyennes le dégradent \
progressivement.
"""


# Schéma structuré transmis à Gemini pour fiabiliser la sortie JSON.
_RESPONSE_SCHEMA = types.Schema(
    type=types.Type.OBJECT,
    required=["score_global", "synthese", "vulnerabilites"],
    properties={
        "score_global": types.Schema(type=types.Type.INTEGER),
        "synthese": types.Schema(type=types.Type.STRING),
        "vulnerabilites": types.Schema(
            type=types.Type.ARRAY,
            items=types.Schema(
                type=types.Type.OBJECT,
                required=[
                    "nom",
                    "categorie",
                    "severite",
                    "explication",
                    "code_original",
                    "code_corrige",
                ],
                properties={
                    "nom": types.Schema(type=types.Type.STRING),
                    "categorie": types.Schema(type=types.Type.STRING),
                    "severite": types.Schema(
                        type=types.Type.STRING,
                        enum=["Faible", "Moyen", "Critique"],
                    ),
                    "ligne": types.Schema(type=types.Type.INTEGER, nullable=True),
                    "explication": types.Schema(type=types.Type.STRING),
                    "code_original": types.Schema(type=types.Type.STRING),
                    "code_corrige": types.Schema(type=types.Type.STRING),
                },
            ),
        ),
    },
)


def build_user_prompt(code: str, language: str) -> str:
    """Construit le message utilisateur envoyé à Gemini."""
    lang = language if language and language != "Auto" else "non précisé (à déduire du code)"
    numbered = "\n".join(f"{i:>4} | {line}" for i, line in enumerate(code.splitlines(), start=1))
    return (
        f"Langage déclaré : {lang}\n\n"
        "Audite le code source ci-dessous (les numéros de ligne sont "
        "indiqués à gauche, ils ne font pas partie du code) et renvoie "
        "le JSON d'audit conforme au schéma.\n\n"
        "----- DÉBUT DU CODE -----\n"
        f"{numbered}\n"
        "----- FIN DU CODE -----"
    )


# --------------------------------------------------------------------------- #
# Appel principal
# --------------------------------------------------------------------------- #


def audit_code(code: str, language: str = "Auto") -> str:
    """Envoie le code à Gemini et retourne la réponse JSON brute (str).

    Args:
        code: code source à auditer.
        language: langage déclaré ("Auto" pour laisser Gemini déduire).

    Returns:
        La chaîne de caractères renvoyée par le modèle (censée être du JSON).

    Raises:
        EmptyCodeError: si `code` est vide.
        config.ConfigError: si la clé API est absente.
        GeminiAPIError: en cas d'échec réseau / API / réponse vide.
    """
    if not code or not code.strip():
        raise EmptyCodeError("Aucun code à auditer : la zone de code est vide.")

    api_key = config.get_api_key()  # lève ConfigError si absente

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=build_user_prompt(code, language),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=config.GEMINI_TEMPERATURE,
                response_mime_type="application/json",
                response_schema=_RESPONSE_SCHEMA,
            ),
        )
    except genai_errors.APIError as exc:  # clé invalide, quota, 4xx/5xx
        raise GeminiAPIError(
            f"L'API Gemini a renvoyé une erreur ({exc.code}) : {exc.message}"
        ) from exc
    except Exception as exc:  # réseau injoignable, DNS, timeout, SSL…
        raise GeminiAPIError(
            "Impossible de contacter l'API Gemini. Vérifiez votre connexion "
            f"réseau et la validité de la clé API. Détail : {exc}"
        ) from exc

    raw = (getattr(response, "text", None) or "").strip()
    if not raw:
        # Réponse bloquée par les filtres de sécurité ou vide.
        reason = _extract_block_reason(response)
        raise GeminiAPIError(
            "Réponse vide de Gemini" + (f" ({reason})." if reason else ".")
        )
    return raw


def _extract_block_reason(response: object) -> str:
    """Tente de récupérer la raison d'un blocage (prompt_feedback / finish_reason)."""
    try:
        feedback = getattr(response, "prompt_feedback", None)
        if feedback and getattr(feedback, "block_reason", None):
            return f"blocage : {feedback.block_reason}"
        candidates = getattr(response, "candidates", None) or []
        if candidates and getattr(candidates[0], "finish_reason", None):
            return f"finish_reason : {candidates[0].finish_reason}"
    except Exception:  # pragma: no cover - purement informatif
        pass
    return ""


__all__ = [
    "SYSTEM_PROMPT",
    "build_user_prompt",
    "audit_code",
    "GeminiError",
    "EmptyCodeError",
    "GeminiAPIError",
]
