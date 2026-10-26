#!/usr/bin/env python3
"""
Scelyans — vérificateur public (scelyans.com/verifier)

Petite application Flask qui réutilise telle quelle la logique de
verify.py (déjà testée en ligne de commande sur de vraies données) pour
offrir une vérification en 2 clics dans un navigateur, sans rien installer.

Conçu pour tourner derrière nginx, en reverse-proxy sur /verifier.
"""

import io
import os
import sys
import html
import re
import tempfile
import contextlib
import traceback
import threading

from flask import Flask, request, render_template_string

# Le vérificateur réutilise le fichier verify.py tel que publié publiquement
# sur https://github.com/DavidJuice-prog/scelyans-archive (archiveur/verify.py).
# Ce fichier app.py vit dans le même dépôt, sous verifier-web/ ; verify.py est
# donc son voisin direct, dans ../archiveur/ (voir DEPLOIEMENT.md). Ainsi, le
# code qui vérifie réellement les certificats sur le site est identique, au
# caractère près, à celui que n'importe qui peut auditer sur le dépôt public.
_ICI = os.path.dirname(os.path.abspath(__file__))
VERIFY_MODULE_DIR = os.environ.get(
    "SCELYANS_VERIFY_DIR",
    os.path.normpath(os.path.join(_ICI, "..", "archiveur")),
)
sys.path.insert(0, VERIFY_MODULE_DIR)
import verify as V  # noqa: E402  (import après modification de sys.path, volontaire)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 Mo largement suffisant pour un maillon + .ots

# verify.py écrit sur la sortie standard du PROCESSUS (print()), qui est
# partagée par toutes les requêtes en cours. redirect_stdout() seul ne
# suffit donc pas à isoler deux visiteurs simultanés (mélange possible si
# le serveur utilise plusieurs threads) : ce verrou sérialise les
# vérifications, une à la fois, pour que chaque sortie reste bien séparée.
_VERROU_VERIFICATION = threading.Lock()

ANSI_RE = re.compile(r"\033\[(\d+)m")
ANSI_CLASS = {"92": "ok", "91": "fail", "93": "warn", "0": None}


def ansi_vers_html(texte):
    """Convertit la sortie colorée (ANSI) de verify.py en HTML sûr (échappé)."""
    sortie = []
    pos = 0
    span_ouvert = False
    for m in ANSI_RE.finditer(texte):
        morceau = texte[pos:m.start()]
        if morceau:
            sortie.append(html.escape(morceau))
        code = m.group(1)
        if span_ouvert:
            sortie.append("</span>")
            span_ouvert = False
        cls = ANSI_CLASS.get(code)
        if cls:
            sortie.append(f'<span class="{cls}">')
            span_ouvert = True
        pos = m.end()
    reste = texte[pos:]
    if reste:
        sortie.append(html.escape(reste))
    if span_ouvert:
        sortie.append("</span>")
    return "".join(sortie)


def executer_verification(maillon_path, ots_path, veille_path):
    """Exécute la même séquence que verify.py:main(), en capturant la sortie."""
    buf = io.StringIO()
    verdict = None
    erreur = None
    try:
        with _VERROU_VERIFICATION, contextlib.redirect_stdout(buf):
            print(f"Vérification de : {os.path.basename(maillon_path)}")
            d = V.charger_maillon(maillon_path)

            resultats = {}
            resultats["structure"] = V.verifier_structure(d)
            resultats["bloc"] = V.verifier_gene_bloc(d)
            resultats["ots"] = V.verifier_opentimestamps(maillon_path, ots_path)
            resultats["code"] = V.verifier_gene_code(d)
            resultats["continuite"] = V.verifier_continuite(d, veille_path)

            V.section("Résumé")
            for nom, statut in resultats.items():
                if statut is True:
                    V.ok(nom)
                elif statut is False:
                    V.fail(nom)
                else:
                    V.warn(f"{nom} (non vérifiable avec les éléments fournis)")

            bloquant = (resultats["structure"] is False or resultats["bloc"] is False
                        or resultats["continuite"] is False or resultats["ots"] is False)
            if bloquant:
                print("\nCONCLUSION : ce maillon présente des incohérences. Ne pas s'y fier sans investigation.")
                verdict = "echec"
            else:
                print("\nCONCLUSION : aucune incohérence détectée sur les éléments vérifiables.")
                verdict = "ok"
    except Exception:
        # Le détail technique (chemins du serveur, etc.) va dans les journaux
        # du serveur uniquement — jamais affiché à un visiteur public.
        erreur = traceback.format_exc()
        app.logger.error("Échec de vérification :\n%s", erreur)
    return buf.getvalue(), verdict, erreur


PAGE_ACCUEIL = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scelyans — Vérificateur public</title>
<style>
  :root { --bg:#0b0d12; --panel:#12151c; --text:#e8eaed; --muted:#9aa3b2; --accent:#4f9dff; --ok:#3ddc84; --fail:#ff5a5a; --warn:#ffcc55; --border:#232836; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }
  .wrap { max-width:720px; margin:0 auto; padding:32px 20px 80px; }
  h1 { font-size:1.6rem; margin-bottom:4px; }
  .tagline { color:var(--muted); margin-top:0; margin-bottom:28px; }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:24px; margin-bottom:20px; }
  .panel h2 { font-size:1.05rem; margin-top:0; }
  label { display:block; font-weight:600; margin-bottom:6px; margin-top:16px; }
  label.optional::after { content:" (optionnel)"; font-weight:400; color:var(--muted); }
  input[type=file] { width:100%; padding:10px; background:#0d1017; border:1px solid var(--border); border-radius:8px; color:var(--text); }
  .hint { color:var(--muted); font-size:0.88rem; margin-top:4px; }
  button { margin-top:24px; width:100%; padding:14px; font-size:1.05rem; font-weight:600; background:var(--accent); color:#fff; border:none; border-radius:10px; cursor:pointer; }
  button:hover { filter:brightness(1.08); }
  .steps { color:var(--muted); font-size:0.92rem; }
  .steps li { margin-bottom:6px; }
  footer { color:var(--muted); font-size:0.85rem; text-align:center; margin-top:40px; }
  footer a { color:var(--accent); }
</style>
</head>
<body>
<div class="wrap">
  <h1>Vérificateur ADN — Scelyans</h1>
  <p class="tagline">Ne faites pas confiance. Vérifiez. Déposez un certificat ADN, obtenez le résultat immédiatement.</p>

  <div class="panel">
    <h2>Déposer un certificat</h2>
    <form method="post" action="" enctype="multipart/form-data">
      <label for="maillon">Fichier du certificat (.json)</label>
      <input type="file" id="maillon" name="maillon" accept="application/json,.json" required>
      <p class="hint">Le fichier ADN que vous souhaitez vérifier, par exemple adn-2026-10-25.json.</p>

      <label class="optional" for="ots">Fichier de preuve Bitcoin (.bitcoin.ots)</label>
      <input type="file" id="ots" name="ots" accept=".ots">
      <p class="hint">La preuve la plus forte : ancrage indépendant dans la blockchain Bitcoin.</p>

      <label class="optional" for="veille">Certificat de la veille (.json)</label>
      <input type="file" id="veille" name="veille" accept="application/json,.json">
      <p class="hint">Permet de vérifier que la chaîne des jours n'a pas été rompue.</p>

      <button type="submit">Vérifier</button>
    </form>
  </div>

  <div class="panel">
    <h2>Ce que ce vérificateur contrôle</h2>
    <ul class="steps">
      <li><strong>Structure</strong> — le fichier a bien la forme d'un vrai maillon ADN</li>
      <li><strong>Gène bloc</strong> — le bloc Bitcoin cité existe réellement (recoupé auprès de deux sources publiques indépendantes)</li>
      <li><strong>Ancrage OpenTimestamps</strong> — preuve cryptographique ancrée dans Bitcoin, la plus difficile à falsifier</li>
      <li><strong>Gène code</strong> — le logiciel qui a produit ce certificat correspond au code source publié publiquement sur GitHub</li>
      <li><strong>Continuité</strong> — ce jour s'enchaîne sans rupture avec le précédent</li>
    </ul>
  </div>

  <footer>
    Code source public et vérifiable :
    <a href="https://github.com/DavidJuice-prog/scelyans-archive" target="_blank" rel="noopener">github.com/DavidJuice-prog/scelyans-archive</a>
  </footer>
</div>
</body>
</html>
"""

PAGE_RESULTAT = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Résultat — Scelyans</title>
<style>
  :root { --bg:#0b0d12; --panel:#12151c; --text:#e8eaed; --muted:#9aa3b2; --accent:#4f9dff; --ok:#3ddc84; --fail:#ff5a5a; --warn:#ffcc55; --border:#232836; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }
  .wrap { max-width:780px; margin:0 auto; padding:32px 20px 80px; }
  a.back { color:var(--accent); text-decoration:none; }
  .verdict { padding:18px 20px; border-radius:12px; margin:20px 0; font-size:1.15rem; font-weight:700; }
  .verdict.ok { background:rgba(61,220,132,0.12); border:1px solid var(--ok); color:var(--ok); }
  .verdict.echec { background:rgba(255,90,90,0.12); border:1px solid var(--fail); color:var(--fail); }
  .verdict.erreur { background:rgba(255,204,85,0.12); border:1px solid var(--warn); color:var(--warn); }
  pre { background:#0d1017; border:1px solid var(--border); border-radius:10px; padding:18px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; font-size:0.92rem; }
  .ok { color:var(--ok); }
  .fail { color:var(--fail); }
  .warn { color:var(--warn); }
</style>
</head>
<body>
<div class="wrap">
  <p><a class="back" href="">&larr; Nouvelle vérification</a></p>
  {% if verdict == 'ok' %}
    <div class="verdict ok">Aucune incohérence détectée sur les éléments vérifiables.</div>
  {% elif verdict == 'echec' %}
    <div class="verdict echec">Ce certificat présente des incohérences. Ne pas s'y fier sans investigation.</div>
  {% else %}
    <div class="verdict erreur">La vérification n'a pas pu aboutir (voir le détail ci-dessous).</div>
  {% endif %}
  <pre>{{ sortie_html|safe }}</pre>
</div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template_string(PAGE_ACCUEIL)
    return verifier()


def verifier():
    maillon_file = request.files.get("maillon")
    if not maillon_file or maillon_file.filename == "":
        return render_template_string(
            PAGE_RESULTAT, verdict="erreur",
            sortie_html=html.escape("Aucun fichier de certificat fourni.")
        ), 400

    with tempfile.TemporaryDirectory(prefix="scelyans-verif-") as tmp:
        maillon_path = os.path.join(tmp, "maillon.json")
        maillon_file.save(maillon_path)

        ots_path = None
        ots_file = request.files.get("ots")
        if ots_file and ots_file.filename:
            ots_path = os.path.join(tmp, "preuve.bitcoin.ots")
            ots_file.save(ots_path)

        veille_path = None
        veille_file = request.files.get("veille")
        if veille_file and veille_file.filename:
            veille_path = os.path.join(tmp, "veille.json")
            veille_file.save(veille_path)

        sortie, verdict, erreur = executer_verification(maillon_path, ots_path, veille_path)

    if erreur:
        # Le détail technique (erreur) est déjà dans les logs serveur
        # (voir executer_verification) ; on ne montre au visiteur qu'un
        # message générique, jamais la trace technique.
        sortie_html = ansi_vers_html(sortie) + "\n\n" + html.escape(
            "La vérification n'a pas pu aboutir côté serveur. "
            "Vérifiez que le fichier envoyé est bien un certificat ADN valide."
        )
        return render_template_string(PAGE_RESULTAT, verdict="erreur", sortie_html=sortie_html), 200

    return render_template_string(PAGE_RESULTAT, verdict=verdict, sortie_html=ansi_vers_html(sortie))


@app.errorhandler(413)
def trop_gros(e):
    return render_template_string(
        PAGE_RESULTAT, verdict="erreur",
        sortie_html=html.escape("Le fichier envoyé est trop volumineux (5 Mo maximum). "
                                 "Un certificat ADN ne devrait jamais être aussi gros — "
                                 "vérifiez que vous avez bien envoyé le bon fichier.")
    ), 413


@app.errorhandler(500)
def erreur_serveur(e):
    return render_template_string(
        PAGE_RESULTAT, verdict="erreur",
        sortie_html=html.escape("Une erreur inattendue est survenue côté serveur. "
                                 "Réessayez, et si le problème persiste, vérifiez le fichier "
                                 "envoyé ou contactez l'éditeur.")
    ), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8077))
    app.run(host="127.0.0.1", port=port, debug=False)
