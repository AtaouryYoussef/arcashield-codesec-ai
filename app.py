"""ArcaShield CodeSec-AI — interface Streamlit (couche frontend).

Lancement :  streamlit run app.py

Ce fichier ne contient QUE de l'UI/UX : la logique d'audit (appel API,
parsing JSON) vit dans `gemini_client.py` et `utils.py` et n'est pas
modifiée ici.
"""

from __future__ import annotations

import json as _json
from datetime import datetime

import streamlit as st

import config
import utils
from gemini_client import (
    EmptyCodeError,
    GeminiAPIError,
    audit_code,
)

# --------------------------------------------------------------------------- #
# Configuration de la page
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title=config.APP_NAME,
    page_icon=config.APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------------------------------- #
# CSS custom (police moderne + thème + composants)
# --------------------------------------------------------------------------- #
_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root{
  --as-bg:#0E1117; --as-surface:#151B24; --as-border:#243044;
  --as-accent:#4A9EFF; --as-text:#E8EDF2; --as-muted:#8A97A8;
  --as-crit:#E5484D; --as-moy:#F5A623; --as-faible:#F5D90A; --as-ok:#3DD68C;
}

/* --- Base / police --- */
html,body,[class*="css"]{ font-family:'Inter',system-ui,"Segoe UI",Roboto,sans-serif; }
.stApp{ background:var(--as-bg); color:var(--as-text); }
[data-testid="stCode"] *,code,kbd{ font-family:'JetBrains Mono',ui-monospace,Menlo,monospace !important; }
.block-container{ max-width:1180px; padding-top:1.6rem; }

/* --- Header --- */
.as-header{
  display:flex; align-items:center; gap:1rem; padding:1.15rem 1.4rem;
  border-radius:16px; margin-bottom:1.4rem;
  background:linear-gradient(135deg,#12233B 0%,#16324F 55%,#123047 100%);
  border:1px solid var(--as-border);
  box-shadow:0 8px 30px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.03);
}
.as-header .as-logo{ font-size:2.4rem; filter:drop-shadow(0 0 10px rgba(74,158,255,.45)); }
.as-header h1{ margin:0; font-size:1.55rem; font-weight:800; letter-spacing:-.02em; color:#F2F6FB; }
.as-header p{ margin:.2rem 0 0; color:#9DB4CE; font-size:.9rem; font-weight:500; }

/* --- Boutons --- */
.stButton>button,.stDownloadButton>button{
  border-radius:10px; font-weight:600; border:1px solid var(--as-border);
  transition:transform .12s ease, box-shadow .12s ease;
}
.stButton>button[kind="primary"],.stDownloadButton>button{
  background:var(--as-accent); border-color:var(--as-accent); color:#08131F;
}
.stButton>button:hover,.stDownloadButton>button:hover{
  transform:translateY(-1px); box-shadow:0 6px 20px rgba(74,158,255,.28);
}

/* --- SCORE : élément le plus frappant --- */
.as-score-wrap{
  display:flex; align-items:center; gap:1.7rem; padding:1.5rem 1.7rem;
  border-radius:18px; margin:.3rem 0 1.2rem;
  background:radial-gradient(120% 140% at 0% 0%,#16202E 0%,#121821 62%);
  border:1px solid var(--as-border);
  animation:as-pop .45s cubic-bezier(.2,.7,.2,1) both;
}
.as-score-ring{
  width:140px; height:140px; border-radius:50%; flex:0 0 auto; position:relative;
  background:conic-gradient(var(--ring-c) calc(var(--ring-v)*1%), #222c3a 0);
  display:grid; place-items:center;
  box-shadow:0 0 0 1px var(--as-border), 0 0 30px -6px var(--ring-c);
}
.as-score-ring::after{ content:""; position:absolute; inset:13px; border-radius:50%; background:#0F141C; }
.as-score-ring b{ position:relative; z-index:1; font-size:2.7rem; font-weight:800; color:var(--ring-c); line-height:1; }
.as-score-ring i{ position:relative; z-index:1; font-style:normal; font-size:.78rem; color:var(--as-muted); }
.as-score-meta h3{ margin:0 0 .3rem; font-size:1.1rem; font-weight:700; }
.as-score-meta p{ margin:.2rem 0 0; color:var(--as-muted); font-size:.9rem; line-height:1.5; }
.as-score-chips{ display:flex; flex-wrap:wrap; gap:.5rem; margin-top:.8rem; }
.as-chip{ font-size:.78rem; font-weight:700; padding:.2rem .6rem; border-radius:8px;
  border:1px solid var(--as-border); background:#141C27; }

/* --- Pills / badges --- */
.as-pill{ display:inline-flex; align-items:center; gap:.35rem; padding:.2rem .7rem;
  border-radius:999px; font-size:.75rem; font-weight:700; border:1px solid transparent; }
.as-pill-owasp{ background:rgba(74,158,255,.12); color:#8FC2FF; border-color:rgba(74,158,255,.30); }
.as-cardhead{ display:flex; align-items:center; gap:.6rem; flex-wrap:wrap; margin-bottom:.6rem; }
.as-sevtag{ font-weight:700; font-size:.8rem; }

/* --- Cartes de vulnérabilité : bordure gauche colorée + apparition --- */
[data-testid="stExpander"]{ border-radius:14px !important; animation:as-fade-up .4s ease both; margin-bottom:.15rem; }
[data-testid="stExpander"] details{
  background:var(--as-surface) !important; border:1px solid var(--as-border) !important;
  border-left-width:4px !important; border-radius:14px !important;
}
[data-testid="stExpander"] details:has(.sev-crit){ border-left-color:var(--as-crit) !important; }
[data-testid="stExpander"] details:has(.sev-moy){ border-left-color:var(--as-moy) !important; }
[data-testid="stExpander"] details:has(.sev-faible){ border-left-color:var(--as-faible) !important; }
[data-testid="stExpander"] summary:hover{ color:var(--as-accent); }
[data-testid="stExpander"]:nth-of-type(1){animation-delay:.02s}
[data-testid="stExpander"]:nth-of-type(2){animation-delay:.06s}
[data-testid="stExpander"]:nth-of-type(3){animation-delay:.10s}
[data-testid="stExpander"]:nth-of-type(4){animation-delay:.14s}
[data-testid="stExpander"]:nth-of-type(n+5){animation-delay:.18s}

/* --- Diff : fond rouge léger / vert léger (via :has sur la colonne) --- */
[data-testid="stColumn"]:has(.as-diff-old) [data-testid="stCode"] pre,
[data-testid="column"]:has(.as-diff-old) [data-testid="stCode"] pre,
[data-testid="stColumn"]:has(.as-diff-old) [data-testid="stCodeBlock"] pre{
  background:rgba(229,72,77,.10) !important; border:1px solid rgba(229,72,77,.28) !important;
}
[data-testid="stColumn"]:has(.as-diff-new) [data-testid="stCode"] pre,
[data-testid="column"]:has(.as-diff-new) [data-testid="stCode"] pre,
[data-testid="stColumn"]:has(.as-diff-new) [data-testid="stCodeBlock"] pre{
  background:rgba(61,214,140,.10) !important; border:1px solid rgba(61,214,140,.28) !important;
}
.as-diff-lbl{ font-size:.8rem; font-weight:700; margin-bottom:.25rem; }
.as-diff-lbl.old{ color:#FF9B9E; } .as-diff-lbl.new{ color:#7EE6B4; }

/* --- Footer discret --- */
.as-footer{ margin-top:2.6rem; padding:1rem 0 .3rem; border-top:1px solid var(--as-border);
  text-align:center; color:var(--as-muted); font-size:.8rem; }
.as-footer a{ color:var(--as-accent); text-decoration:none; }
.as-footer a:hover{ text-decoration:underline; }

/* --- Status / spinner --- */
[data-testid="stStatusWidget"] *{ font-weight:500; }

/* --- Animations --- */
@keyframes as-fade-up{ from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
@keyframes as-pop{ from{opacity:0;transform:scale(.96)} to{opacity:1;transform:none} }
</style>
"""
st.markdown(_CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# En-tête
# --------------------------------------------------------------------------- #
st.markdown(
    f"""
    <div class="as-header">
      <div class="as-logo">{config.APP_ICON}</div>
      <div>
        <h1>{config.APP_NAME}</h1>
        <p>{config.APP_TAGLINE} &nbsp;·&nbsp; {config.APP_ORG}</p>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- #
# Barre latérale
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.subheader("À propos")
    st.write(
        "Assistant d'audit SAST : détecte les vulnérabilités **OWASP Top 10 / "
        "CWE** dans votre code et propose des correctifs prêts à l'emploi, "
        "avant les audits internes."
    )
    st.divider()
    st.subheader("Configuration")
    if config.GEMINI_API_KEY and config.GEMINI_API_KEY.strip():
        st.success("Clé API Gemini détectée.", icon="✅")
    else:
        st.error("Clé API Gemini absente (`.env`).", icon="⚠️")
    st.caption(f"Modèle : `{config.GEMINI_MODEL}`")
    st.divider()
    st.caption(
        "⚠️ Les correctifs générés par l'IA doivent être relus et testés "
        "avant toute mise en production."
    )


# --------------------------------------------------------------------------- #
# État de session
# --------------------------------------------------------------------------- #
st.session_state.setdefault("audit", None)          # dict normalisé
st.session_state.setdefault("audit_meta", None)     # {language, source_name, generated_at}


# --------------------------------------------------------------------------- #
# Zone de saisie
# --------------------------------------------------------------------------- #
st.subheader("1 · Code à auditer")

tab_paste, tab_upload = st.tabs(["📋 Coller du code", "📁 Uploader un fichier"])

code_input = ""
source_name = "code collé"
detected_language = "Auto"

with tab_paste:
    code_input = st.text_area(
        "Collez votre code source ici",
        height=320,
        placeholder="def login(user, pwd):\n    query = \"SELECT * FROM users WHERE name = '\" + user + \"'\"\n    ...",
        label_visibility="collapsed",
    )

with tab_upload:
    uploaded = st.file_uploader(
        "Fichier source",
        type=config.ALLOWED_UPLOAD_TYPES,
        help="Formats acceptés : " + ", ".join(f".{e}" for e in config.ALLOWED_UPLOAD_TYPES),
        label_visibility="collapsed",
    )
    if uploaded is not None:
        try:
            file_text = uploaded.getvalue().decode("utf-8")
        except UnicodeDecodeError:
            file_text = uploaded.getvalue().decode("latin-1", errors="replace")
        code_input = file_text
        source_name = uploaded.name
        detected_language = utils.detect_language(uploaded.name)
        st.code(
            file_text if len(file_text) < 6000 else file_text[:6000] + "\n…(tronqué)",
            language=None,
        )
        st.caption(f"Fichier chargé : **{uploaded.name}** — langage détecté : **{detected_language}**")


# --------------------------------------------------------------------------- #
# Options d'audit
# --------------------------------------------------------------------------- #
st.subheader("2 · Paramètres")

col_lang, col_btn = st.columns([1, 1])
with col_lang:
    default_idx = (
        config.SUPPORTED_LANGUAGES.index(detected_language)
        if detected_language in config.SUPPORTED_LANGUAGES
        else 0
    )
    language = st.selectbox(
        "Langage",
        options=config.SUPPORTED_LANGUAGES,
        index=default_idx,
        help="« Auto » laisse le moteur déduire le langage à partir du code.",
    )
with col_btn:
    st.write("")
    st.write("")
    launch = st.button("🔍 Lancer l'audit", type="primary", use_container_width=True)


# --------------------------------------------------------------------------- #
# Exécution de l'audit  (logique inchangée — habillage `st.status` uniquement)
# --------------------------------------------------------------------------- #
if launch:
    if not code_input or not code_input.strip():
        st.warning("Aucun code fourni : collez du code ou uploadez un fichier.", icon="✏️")
    else:
        try:
            with st.status(
                "🛡️ Analyse en cours par l'agent de sécurité d'ArcaShield…",
                expanded=True,
            ) as status:
                st.write("→ Connexion au moteur d'inférence Gemini")
                raw = audit_code(code_input, language)
                st.write("→ Analyse OWASP Top 10 / CWE")
                audit = utils.parse_audit_json(raw)
                st.write("→ Structuration du rapport d'audit")
                status.update(label="Analyse terminée", state="complete", expanded=False)
        except EmptyCodeError as exc:
            st.warning(str(exc), icon="✏️")
        except config.ConfigError as exc:
            st.error(str(exc), icon="🔑")
        except GeminiAPIError as exc:
            st.error(str(exc), icon="🌐")
        except utils.AuditParseError as exc:
            st.error(str(exc), icon="🧩")
        except Exception as exc:  # filet de sécurité
            st.exception(exc)
        else:
            st.session_state.audit = audit
            st.session_state.audit_meta = {
                "language": language,
                "source_name": source_name,
                "generated_at": datetime.now(),
            }
            st.toast("Audit terminé", icon="✅")


# --------------------------------------------------------------------------- #
# Composants de rendu
# --------------------------------------------------------------------------- #
_LANG_HINT = {
    "Python": "python", "Java": "java", "PHP": "php",
    "SQL": "sql", "JavaScript": "javascript",
}
_SEV_CLASS = {"Critique": "sev-crit", "Moyen": "sev-moy", "Faible": "sev-faible"}


def _score_banner(audit: dict, meta: dict) -> None:
    """Bandeau de score : anneau circulaire coloré = élément dominant."""
    score = audit["score_global"]
    color = config.score_color(score)
    counts = utils.severity_counts(audit["vulnerabilites"])
    chips = (
        f'<span class="as-chip" style="color:var(--as-crit)">🔴 {counts["Critique"]} critique(s)</span>'
        f'<span class="as-chip" style="color:var(--as-moy)">🟠 {counts["Moyen"]} moyenne(s)</span>'
        f'<span class="as-chip" style="color:var(--as-faible)">🟡 {counts["Faible"]} faible(s)</span>'
    )
    st.markdown(
        f"""
        <div class="as-score-wrap">
          <div class="as-score-ring" style="--ring-v:{score}; --ring-c:{color};">
            <b>{score}</b><i>/ 100</i>
          </div>
          <div class="as-score-meta">
            <h3>Score de sécurité —
              <span style="color:{color}">{config.score_label(score)}</span>
            </h3>
            <p>{audit["synthese"]}</p>
            <div class="as-score-chips">{chips}</div>
            <p style="margin-top:.6rem;font-size:.8rem">
              Source : {meta["source_name"]} · Langage : {meta["language"]} ·
              {meta["generated_at"]:%d/%m/%Y %H:%M}
            </p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _copy_button(text: str, idx: int) -> None:
    """Bouton « Copier le code corrigé » (clipboard API + repli execCommand).

    Rendu dans un iframe via `st.iframe` pour pouvoir exécuter le JS de copie.
    `_json.dumps` échappe le texte en littéral JS ; `</` est neutralisé pour
    empêcher toute fermeture prématurée de la balise <script>.
    """
    payload = _json.dumps(text or "").replace("</", "<\\/")
    st.iframe(
        f"""<!doctype html><html><head><meta charset="utf-8">
<style>
  *{{box-sizing:border-box}}
  body{{margin:0;font-family:'Inter',system-ui,"Segoe UI",Roboto,sans-serif}}
  .cpbtn{{
    display:inline-flex;align-items:center;gap:.4rem;cursor:pointer;
    background:#4A9EFF;color:#08131F;border:none;border-radius:8px;
    font-weight:700;font-size:.8rem;padding:.42rem .8rem;transition:opacity .12s;
  }}
  .cpbtn:hover{{opacity:.88}}
  .cpbtn.done{{background:#3DD68C}}
</style></head><body>
<button class="cpbtn" id="cp{idx}">📋 Copier le code corrigé</button>
<script>
  (function(){{
    var b=document.getElementById("cp{idx}"), txt={payload};
    function done(){{
      b.textContent="✓ Copié";b.classList.add("done");
      setTimeout(function(){{b.textContent="📋 Copier le code corrigé";b.classList.remove("done");}},1500);
    }}
    function fallback(){{
      var ta=document.createElement("textarea");ta.value=txt;
      ta.style.position="fixed";ta.style.opacity="0";document.body.appendChild(ta);
      ta.focus();ta.select();try{{document.execCommand("copy");}}catch(e){{}}
      document.body.removeChild(ta);done();
    }}
    b.addEventListener("click",function(){{
      if(navigator.clipboard&&navigator.clipboard.writeText){{
        navigator.clipboard.writeText(txt).then(done).catch(fallback);
      }}else{{fallback();}}
    }});
  }})();
</script></body></html>""",
        height=46,
    )


def _vuln_card(v: dict, index: int, lang_hint: str | None) -> None:
    sev = v["severite"]
    sev_class = _SEV_CLASS.get(sev, "sev-moy")
    sev_color = config.SEVERITY_COLOR.get(sev, "#8A97A8")
    ligne = f"ligne {v['ligne']}" if v["ligne"] is not None else "transverse"

    with st.expander(f"{index}. {v['nom']}  ·  {sev}  ({ligne})", expanded=(index == 1)):
        # Marqueur de sévérité (pilote la bordure gauche via CSS :has) + en-tête.
        st.markdown(
            f"""
            <div class="{sev_class} as-cardhead">
              <span class="as-pill as-pill-owasp">{v["categorie"]}</span>
              <span class="as-sevtag" style="color:{sev_color}">● {sev}</span>
              <span style="color:var(--as-muted);font-size:.8rem">{ligne}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(f"**Impact.** {v['explication']}")

        d1, d2 = st.columns(2)
        with d1:
            st.markdown(
                '<span class="as-diff-old"></span>'
                '<div class="as-diff-lbl old">🔻 Code vulnérable</div>',
                unsafe_allow_html=True,
            )
            st.code(v["code_original"] or "—", language=lang_hint)
        with d2:
            st.markdown(
                '<span class="as-diff-new"></span>'
                '<div class="as-diff-lbl new">✅ Code corrigé</div>',
                unsafe_allow_html=True,
            )
            st.code(v["code_corrige"] or "—", language=lang_hint)
            if v["code_corrige"]:
                _copy_button(v["code_corrige"], idx=index)


def _render_results() -> None:
    audit = st.session_state.audit
    meta = st.session_state.audit_meta
    if not audit:
        st.info("Lancez un audit pour afficher le score et les vulnérabilités.", icon="🛡️")
        return

    vulns = audit["vulnerabilites"]

    st.subheader("3 · Résultats de l'audit")
    _score_banner(audit, meta)

    if not vulns:
        st.success("Aucune vulnérabilité détectée par l'audit automatisé. 🎉", icon="✅")
    else:
        st.markdown(f"#### {len(vulns)} vulnérabilité(s) détectée(s)")
        lang_hint = _LANG_HINT.get(meta["language"])
        for i, v in enumerate(vulns, start=1):
            _vuln_card(v, i, lang_hint)

    st.divider()
    st.subheader("4 · Export")
    report_md = utils.build_markdown_report(
        audit,
        language=meta["language"],
        source_name=meta["source_name"],
        generated_at=meta["generated_at"],
    )
    st.download_button(
        "⬇️ Exporter le rapport d'audit (Markdown)",
        data=report_md.encode("utf-8"),
        file_name=utils.report_filename(meta["source_name"], meta["generated_at"]),
        mime="text/markdown",
        type="primary",
    )
    with st.expander("Aperçu du rapport"):
        st.markdown(report_md)


_render_results()


# --------------------------------------------------------------------------- #
# Footer
# --------------------------------------------------------------------------- #
st.markdown(
    """
    <div class="as-footer">
      <strong>ArcaShield</strong> — Corporate Software Holding
      &nbsp;·&nbsp;
      <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener">
        Référentiel OWASP Top 10 ↗
      </a>
    </div>
    """,
    unsafe_allow_html=True,
)
