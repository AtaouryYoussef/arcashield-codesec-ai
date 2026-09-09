"""Fonctions utilitaires d'ArcaShield CodeSec-AI.

Regroupe :
  * `detect_language` : déduction du langage depuis un nom de fichier ;
  * `parse_audit_json` : extraction + validation robuste du JSON renvoyé
    par Gemini (gère les fences Markdown, le texte parasite, etc.) ;
  * `build_markdown_report` : mise en forme du rapport d'audit exportable.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import config


# --------------------------------------------------------------------------- #
# Détection de langage
# --------------------------------------------------------------------------- #


def detect_language(filename: str | None) -> str:
    """Retourne le langage déduit de l'extension, ou "Auto" si inconnu."""
    if not filename:
        return "Auto"
    ext = Path(filename).suffix.lower()
    return config.LANGUAGE_BY_EXTENSION.get(ext, "Auto")


# --------------------------------------------------------------------------- #
# Parsing JSON robuste
# --------------------------------------------------------------------------- #


class AuditParseError(ValueError):
    """Le contenu renvoyé par Gemini n'a pas pu être interprété en audit valide."""


_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(.*?)\s*```", re.DOTALL)


def _strip_code_fences(text: str) -> str:
    """Retire un éventuel bloc Markdown ```json ... ``` autour du JSON."""
    match = _FENCE_RE.search(text)
    return match.group(1) if match else text


def _extract_json_object(text: str) -> str:
    """Isole le premier objet JSON `{ ... }` complet en équilibrant les accolades.

    Ignore les accolades situées dans des chaînes de caractères et gère
    les échappements. Permet de récupérer le JSON même si Gemini l'entoure
    de texte explicatif.
    """
    start = text.find("{")
    if start == -1:
        raise AuditParseError("Aucun objet JSON trouvé dans la réponse du modèle.")

    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise AuditParseError("Objet JSON incomplet dans la réponse du modèle (accolade non fermée).")


def _coerce_int(value: Any, default: int = 0, lo: int = 0, hi: int = 100) -> int:
    """Convertit une valeur en entier borné [lo, hi]."""
    try:
        n = int(round(float(value)))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _normalize_severity(value: Any) -> str:
    """Ramène une sévérité arbitraire vers {Faible, Moyen, Critique}."""
    if not isinstance(value, str):
        return "Moyen"
    v = value.strip().lower()
    mapping = {
        "critique": "Critique", "critical": "Critique", "élevé": "Critique",
        "eleve": "Critique", "high": "Critique", "haute": "Critique",
        "moyen": "Moyen", "moyenne": "Moyen", "medium": "Moyen", "modéré": "Moyen",
        "modere": "Moyen",
        "faible": "Faible", "low": "Faible", "mineur": "Faible", "basse": "Faible",
        "info": "Faible", "informational": "Faible",
    }
    return mapping.get(v, "Moyen")


def _normalize_vuln(raw: dict[str, Any], index: int) -> dict[str, Any]:
    """Valide et complète une entrée de vulnérabilité."""
    ligne = raw.get("ligne", raw.get("line"))
    try:
        ligne = int(ligne) if ligne is not None and str(ligne).strip() != "" else None
    except (TypeError, ValueError):
        ligne = None

    return {
        "nom": str(raw.get("nom") or raw.get("name") or f"Vulnérabilité {index + 1}").strip(),
        "categorie": str(raw.get("categorie") or raw.get("category") or "Non catégorisée").strip(),
        "severite": _normalize_severity(raw.get("severite") or raw.get("severity")),
        "ligne": ligne,
        "explication": str(
            raw.get("explication") or raw.get("explanation") or raw.get("impact") or ""
        ).strip(),
        "code_original": str(raw.get("code_original") or raw.get("original") or "").strip("\n"),
        "code_corrige": str(
            raw.get("code_corrige") or raw.get("corrige") or raw.get("fixed") or ""
        ).strip("\n"),
    }


def parse_audit_json(raw_text: str) -> dict[str, Any]:
    """Transforme la réponse brute de Gemini en dictionnaire d'audit normalisé.

    Structure retournée :
        {
          "score_global": int (0-100),
          "synthese": str,
          "vulnerabilites": [ {nom, categorie, severite, ligne,
                               explication, code_original, code_corrige}, ... ]
        }

    Raises:
        AuditParseError: si aucun JSON exploitable ne peut être extrait.
    """
    if not raw_text or not raw_text.strip():
        raise AuditParseError("Réponse vide : rien à analyser.")

    candidate = _strip_code_fences(raw_text.strip())

    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        # Deuxième tentative : isoler l'objet JSON au milieu d'un texte.
        try:
            data = json.loads(_extract_json_object(candidate))
        except (json.JSONDecodeError, AuditParseError) as exc:
            raise AuditParseError(
                "Le modèle n'a pas renvoyé de JSON valide. Relancez l'audit ; "
                "si le problème persiste, réduisez la taille du code soumis.\n"
                f"Détail technique : {exc}"
            ) from exc

    if not isinstance(data, dict):
        raise AuditParseError("Le JSON renvoyé n'est pas un objet (structure inattendue).")

    raw_vulns = data.get("vulnerabilites") or data.get("vulnerabilities") or []
    if not isinstance(raw_vulns, list):
        raw_vulns = []

    vulns = [
        _normalize_vuln(v, i)
        for i, v in enumerate(raw_vulns)
        if isinstance(v, dict)
    ]
    vulns.sort(key=lambda v: config.severity_rank(v["severite"]))

    score = data.get("score_global", data.get("score"))
    score = _coerce_int(score, default=100 if not vulns else 50)

    synthese = str(data.get("synthese") or data.get("summary") or "").strip()
    if not synthese:
        synthese = (
            "Aucune vulnérabilité détectée dans le code analysé."
            if not vulns
            else f"{len(vulns)} vulnérabilité(s) identifiée(s) lors de l'audit."
        )

    return {"score_global": score, "synthese": synthese, "vulnerabilites": vulns}


def severity_counts(vulns: list[dict[str, Any]]) -> dict[str, int]:
    """Compte les vulnérabilités par sévérité (ordre : Critique, Moyen, Faible)."""
    counts = {sev: 0 for sev in config.SEVERITY_ORDER}
    for v in vulns:
        counts[v["severite"]] = counts.get(v["severite"], 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Rapport Markdown exportable
# --------------------------------------------------------------------------- #


def _lang_hint(language: str) -> str:
    """Identifiant de langage pour la coloration des blocs de code Markdown."""
    return {
        "Python": "python", "Java": "java", "PHP": "php",
        "SQL": "sql", "JavaScript": "javascript",
    }.get(language, "")


def build_markdown_report(
    audit: dict[str, Any],
    *,
    language: str = "Auto",
    source_name: str = "code collé",
    generated_at: datetime | None = None,
) -> str:
    """Génère le rapport d'audit complet au format Markdown.

    Destiné à être joint à un dossier d'audit interne ArcaShield.
    """
    now = generated_at or datetime.now()
    score = audit["score_global"]
    vulns = audit["vulnerabilites"]
    counts = severity_counts(vulns)
    hint = _lang_hint(language)

    lines: list[str] = []
    lines.append(f"# Rapport d'audit de sécurité — {config.APP_NAME}")
    lines.append("")
    lines.append(f"> {config.APP_ORG}")
    lines.append("")
    lines.append("| Élément | Valeur |")
    lines.append("| --- | --- |")
    lines.append(f"| Date de l'audit | {now:%d/%m/%Y %H:%M} |")
    lines.append(f"| Source analysée | {source_name} |")
    lines.append(f"| Langage | {language} |")
    lines.append(f"| Score global | **{score}/100** — {config.score_label(score)} |")
    lines.append(
        f"| Vulnérabilités | {len(vulns)} "
        f"({counts['Critique']} critique(s), {counts['Moyen']} moyenne(s), "
        f"{counts['Faible']} faible(s)) |"
    )
    lines.append("")
    lines.append("## Synthèse")
    lines.append("")
    lines.append(audit["synthese"])
    lines.append("")

    if not vulns:
        lines.append("## Détail des vulnérabilités")
        lines.append("")
        lines.append("_Aucune vulnérabilité détectée par l'audit automatisé._")
        lines.append("")
    else:
        lines.append("## Détail des vulnérabilités")
        lines.append("")
        for i, v in enumerate(vulns, start=1):
            icon = config.SEVERITY_ICON.get(v["severite"], "")
            ligne = f"ligne {v['ligne']}" if v["ligne"] is not None else "transverse"
            lines.append(f"### {i}. {v['nom']}  {icon} {v['severite']}")
            lines.append("")
            lines.append(f"- **Catégorie :** {v['categorie']}")
            lines.append(f"- **Localisation :** {ligne}")
            lines.append("")
            lines.append(f"**Impact.** {v['explication']}")
            lines.append("")
            if v["code_original"]:
                lines.append("**Code vulnérable :**")
                lines.append("")
                lines.append(f"```{hint}")
                lines.append(v["code_original"])
                lines.append("```")
                lines.append("")
            if v["code_corrige"]:
                lines.append("**Correctif proposé :**")
                lines.append("")
                lines.append(f"```{hint}")
                lines.append(v["code_corrige"])
                lines.append("```")
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        f"_Rapport généré automatiquement par {config.APP_NAME} "
        f"({config.GEMINI_MODEL}). Les correctifs proposés doivent être "
        "relus et testés par un développeur avant mise en production._"
    )
    lines.append("")
    return "\n".join(lines)


def report_filename(source_name: str = "audit", generated_at: datetime | None = None) -> str:
    """Nom de fichier horodaté pour le rapport téléchargeable."""
    now = generated_at or datetime.now()
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", Path(source_name).stem) or "audit"
    return f"rapport_audit_{stem}_{now:%Y%m%d_%H%M%S}.md"


__all__ = [
    "detect_language",
    "parse_audit_json",
    "AuditParseError",
    "severity_counts",
    "build_markdown_report",
    "report_filename",
]
