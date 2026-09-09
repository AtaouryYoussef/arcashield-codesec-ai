# 🛡️ ArcaShield CodeSec-AI

**Security Copilot — Audit SAST & remédiation assistée par IA**
Projet de fin d'année (PFA) — *ArcaShield, filiale cybersécurité.*

ArcaShield CodeSec-AI est un assistant d'audit de sécurité de code (SAST)
qui aide les développeurs à **détecter et corriger leurs vulnérabilités
avant les audits internes**. Il s'appuie sur l'API **Google Gemini** pour
analyser un extrait de code, produire un **score de sécurité**, une liste
de **vulnérabilités OWASP Top 10 / CWE** et un **correctif prêt à l'emploi**
pour chacune.

---

## Architecture (3 couches)

| Couche | Fichier | Rôle |
| --- | --- | --- |
| 1 · Interface | `app.py` | Frontend Streamlit : saisie/upload, anneau de score coloré, cartes de vulnérabilités, diff, export |
| 2 · Moteur d'inférence | `gemini_client.py` | System prompt « expert sécurité ArcaShield », appel `google-genai`, sortie JSON stricte |
| 3 · Traitement & rendu | `utils.py` | Détection de langage, parsing JSON robuste, génération du rapport Markdown |
| — Configuration | `config.py` | Chargement `.env`, constantes (langages, sévérités, seuils, couleurs) |

---

## Prérequis

- **Python 3.11+**
- Une **clé API Google Gemini** — https://aistudio.google.com/app/apikey

---

## Installation

```bash
# 1. Se placer dans le dossier du projet
cd arcashield-codesec-ai

# 2. Créer et activer un environnement virtuel
python -m venv venv
venv\Scripts\activate          # Windows (PowerShell / CMD)
# source venv/bin/activate     # macOS / Linux

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer la clé API
copy .env.example .env         # Windows   (cp .env.example .env sous macOS/Linux)
# puis éditer .env et renseigner GEMINI_API_KEY=...
```

Le fichier `.env` est ignoré par Git (`.gitignore`) : la clé n'est
**jamais** committée ni écrite en dur dans le code.

---

## Lancement

```bash
streamlit run app.py
```

L'application s'ouvre sur http://localhost:8501.

---

## Utilisation

1. **Coller du code** dans l'onglet dédié, ou **uploader un fichier**
   (`.py`, `.java`, `.php`, `.sql`, `.js`) — le langage est alors
   auto-détecté depuis l'extension.
2. Vérifier / ajuster le **langage** (ou laisser « Auto »).
3. Cliquer sur **« Lancer l'audit »**.
4. Consulter le **score global**, la **synthèse**, puis chaque
   **vulnérabilité** : catégorie OWASP/CWE, sévérité, impact pédagogique,
   et **diff code vulnérable / code corrigé** côte à côte.
5. Cliquer sur **« Exporter le rapport d'audit »** pour télécharger un
   rapport Markdown horodaté, à joindre au dossier d'audit interne.

---

## Configuration avancée (`.env`)

| Variable | Défaut | Description |
| --- | --- | --- |
| `GEMINI_API_KEY` | *(obligatoire)* | Clé API Google Gemini |
| `GEMINI_MODEL` | `gemini-3.6-flash` | Modèle Gemini utilisé |
| `GEMINI_TEMPERATURE` | `0.15` | Déterminisme des réponses (bas = rigoureux) |

---

## Gestion des erreurs

L'application affiche un message clair pour chaque cas :

- 🔑 **Clé API manquante / invalide** — `.env` absent ou clé erronée
- 🌐 **Erreur réseau / API** — service injoignable, quota dépassé
- 🧩 **JSON malformé** — réponse du modèle non exploitable (relancer l'audit)
- ✏️ **Code vide** — aucun code fourni

---

## Structure du projet

```
arcashield-codesec-ai/
├── .streamlit/config.toml   # Thème visuel
├── app.py                   # Interface Streamlit
├── gemini_client.py         # Appel API Gemini + system prompt
├── utils.py                 # Parsing JSON + export du rapport
├── config.py                # Chargement .env + constantes
├── requirements.txt
├── .env.example
└── README.md
```

---

## Avertissement

Les correctifs générés par l'IA sont une **aide à la remédiation**. Ils
doivent être **relus, testés et validés** par un développeur avant toute
mise en production. ArcaShield CodeSec-AI ne remplace pas un audit de
sécurité manuel complet.
