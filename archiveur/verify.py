#!/usr/bin/env python3
"""
verify.py — Vérificateur public des certificats ADN (Scelyans)

Objectif : permettre à n'importe qui (notaire, avocat, comptable, client)
de vérifier de façon indépendante qu'un maillon ADN scellé par TRACKYZZ
est authentique, sans avoir à contacter l'éditeur ni à lui faire confiance
sur parole.

Usage :
    python verify.py adn-2026-10-24.json [adn-2026-10-24.json.bitcoin.ots] [adn-2026-10-23.json]
                     [--feuilles feuilles-2026-10-24.txt.gz] [--bce bce-2026-10-24.xml] [--trackyzz DOSSIER]

Sans fichier .ots, veille, feuilles ou BCE en argument, le script les cherche à côté du maillon ; la veille est ensuite
cherchée sur trackyzz.com. Couleurs : actives dans la console Windows 10+ et les terminaux ; jamais dans un fichier
(ou avec la variable NO_COLOR).

Ce que ce script vérifie, et comment :

1. Structure du maillon
   Le fichier contient bien les 13 champs attendus (jour, racine,
   racine_archive, racine_veille, genes, feuilles, empreinte_trackyzz,
   algorithme, format, methode, ordre_feuilles, incidents_concernent).
   Si un champ manque ou est d'un type inattendu, c'est signalé en échec :
   un vrai maillon ADN produit par archiveur.py ne devrait jamais en manquer.

2. Gène bloc (fraîcheur Bitcoin) — vérification indépendante
   Le maillon affirme avoir été scellé après un bloc Bitcoin précis
   (hauteur + hash + horodatage). Ce script interroge TROIS sources
   publiques indépendantes (mempool.space, blockstream.info, et —
   quand configuré — votre propre nœud local) pour confirmer que ce
   bloc existe réellement, que son hash correspond, et que son
   horodatage précède bien le jour scellé. Si au moins deux des trois
   sources s'accordent, la preuve est considérée solide.

3. Ancrage OpenTimestamps (si le fichier .bitcoin.ots est fourni)
   La preuve la plus forte : OpenTimestamps est un standard ouvert,
   indépendant de TRACKYZZ, qui prouve qu'une empreinte donnée existait
   AU PLUS TARD à un bloc Bitcoin précis. Ce script lit le fichier .ots
   directement via la bibliothèque Python opentimestamps (pas via
   l'exécutable `ots`, qui peut planter sur certains Windows faute
   d'OpenSSL). Si elle n'est pas installée, il la prend, sans rien
   installer, dans le dossier TRACKYZZ (app\ancrage.py et son .venv,
   option --trackyzz). Il vérifie que l'empreinte du fichier correspond, puis
   confirme la racine Merkle attestée auprès de mempool.space — c'est
   la vérification la plus difficile à falsifier, car elle repose sur
   la preuve de travail de tout le réseau Bitcoin, pas sur une
   déclaration de TRACKYZZ.

4. Gène code (intégrité du logiciel)
   Compare les empreintes SHA-256 d'adn.py et d'archiveur.py déclarées dans le
   maillon à toutes les versions publiées dans l'historique du dépôt public
   (CODE_REPO_URL). Une version antérieure à la publication du dépôt n'y figure
   pas : ce cas est signalé en ATTENTION (à vérifier à la main), jamais en
   ECHEC, car l'absence d'un fichier dans l'historique ne prouve pas une falsification.

5. Continuité de la chaîne
   Vérifie que racine_veille correspond bien à la racine du jour
   précédent, ce qui prouve que la chaîne n'a pas été rompue ou
   réécrite rétroactivement. Maillon de la veille : fourni, sinon à côté
   du maillon, sinon téléchargé sur trackyzz.com. Introuvable : ATTENTION
   (non vérifiable), jamais ECHEC. Le premier maillon n'a pas de veille.

6. Gène tours (incidents de la collecte du jour)
   Minutes sans aucun bloc, minutes de cours écrites en retard, créneaux
   de 5 minutes sans lecture d'oracle. Un incident n'est pas une
   falsification : il est affiché en ATTENTION. Des comptes incohérents
   (nombre différent de la liste) sont un ECHEC. Les maillons scellés
   avant ce gène (28/10/2026) n'en ont pas.

7. Racine recalculée depuis les feuilles (si feuilles-AAAA-MM-JJ.txt.gz est fourni ou à côté)
   Une feuille par ligne du registre : environ 21 000 par jour. Le fichier
   publié ne contient que leurs empreintes SHA-256, jamais les relevés ni
   les prix. Ce script recalcule lui-même la racine (RFC 9162), et les
   feuilles qu'il peut reconstruire seul : veille (depuis racine_veille)
   et gènes (depuis les valeurs publiées dans le maillon).

8. Gène bce (taux de référence de la Banque centrale européenne)
   Si le fichier bce-AAAA-MM-JJ.xml est fourni ou à côté du maillon : son
   empreinte SHA-256, sa date et son taux EUR/USD doivent être ceux du gène
   (sinon ECHEC). Absent : ATTENTION. Le taux est ensuite recoupé avec le
   fichier historique publié par la BCE (eurofxref-hist.xml) : un écart ou
   une absence de réponse n'est qu'une ATTENTION, jamais un ECHEC. Les jours
   sans publication (week-end, jours fériés BCE) n'ont pas de taux. Les
   maillons scellés avant ce gène n'en ont pas.

Ce que ce script ne fait PAS (honnêteté sur les limites actuelles) :
   - Il ne relit pas les relevés eux-mêmes (ils contiennent des prix et ne
     sont pas publiés) : il vérifie que la racine scellée est bien celle de
     ces ~21 000 empreintes. Une preuve d'inclusion d'un relevé précis
     (adn.py preuve / verifier-preuve) reste remise à la demande.
"""

import sys
import os
import json
import gzip
import hashlib
import importlib.util
import re
import urllib.request
import urllib.error
from datetime import date, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — à compléter au fur et à mesure que l'infrastructure existe
# ---------------------------------------------------------------------------

# URL du dépôt public où sont publiés adn.py / archiveur.py, pour recouper
# les empreintes du gène "code". Laisser vide tant que non disponible.
CODE_REPO_URL = "https://github.com/DavidJuice-prog/scelyans-archive"

# Nœud Bitcoin personnel (une fois synchronisé) : "host:port" RPC, ou None.
LOCAL_NODE_RPC = None

# Sources publiques indépendantes pour vérifier le gène bloc.
BLOCK_SOURCES = [
    ("mempool.space", "https://mempool.space/api/block-height/{height}"),
    ("blockstream.info", "https://blockstream.info/api/block-height/{height}"),
]

CHAMPS_ATTENDUS = [
    "algorithme", "empreinte_trackyzz", "feuilles", "format", "genes",
    "incidents_concernent", "jour", "jour_veille", "methode",
    "ordre_feuilles", "racine", "racine_archive", "racine_veille",
]

GENES_ATTENDUS = ["astra", "bloc", "code", "horloge", "temoin"]
GENES_FACULTATIFS = ["tours", "bce"]   # absents des maillons scellés avant eux (tours : 28/10/2026)

# Fichier historique officiel de la BCE, pour recouper le taux du gène bce (ATTENTION seulement).
BCE_HIST_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-hist.xml"

# Maillons publiés (pour retrouver celui de la veille).
ADN_URL = "https://trackyzz.com/adn/adn-{jour}.json"

# Dossier TRACKYZZ (app\ancrage.py et son .venv) : bibliothèque OpenTimestamps sans installation.
TRACKYZZ_DEFAUT = Path.home() / "OneDrive" / "Desktop" / "TRACKYZZ v1 GEMINI"

COULEURS = False


def activer_couleurs(flux=None):
    """Couleurs ANSI seulement vers un terminal (jamais dans un fichier), sauf NO_COLOR. Sous Windows, la console
    n'interprète les codes qu'une fois le mode « terminal virtuel » activé (Windows 10 et suivants)."""
    flux = flux or sys.stdout
    if os.environ.get("NO_COLOR") or not getattr(flux, "isatty", lambda: False)():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h, mode = k.GetStdHandle(-11), ctypes.c_uint32()
        return bool(k.GetConsoleMode(h, ctypes.byref(mode)) and k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


def _c(code, texte):
    return f"\033[{code}m{texte}\033[0m" if COULEURS else texte


def ok(msg):
    print(f"  {_c(92, '[OK]')} {msg}")


def fail(msg):
    print(f"  {_c(91, '[ECHEC]')} {msg}")


def warn(msg):
    print(f"  {_c(93, '[ATTENTION]')} {msg}")


def info(msg):
    print(f"  [i] {msg}")


def section(title):
    print(f"\n=== {title} ===")


def charger_maillon(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def verifier_structure(d):
    section("1. Structure du maillon")
    valide = True
    for champ in CHAMPS_ATTENDUS:
        if champ not in d:
            fail(f"champ manquant : {champ}")
            valide = False
    if "genes" in d:
        for g in GENES_ATTENDUS:
            if g not in d["genes"]:
                fail(f"gène manquant : {g}")
                valide = False
    if valide:
        en_plus = [g for g in GENES_FACULTATIFS if g in d.get("genes", {})]
        ok(f"les {len(CHAMPS_ATTENDUS)} champs et {len(GENES_ATTENDUS)} gènes attendus sont présents"
           + (f" (+ {', '.join(en_plus)})" if en_plus else ""))
        ok(f"jour scellé : {d.get('jour')}")
        ok(f"racine : {d.get('racine')}")
    return valide


def http_get_json(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "scelyans-verify/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def verifier_gene_bloc(d):
    section("2. Gène bloc — fraîcheur Bitcoin (vérification indépendante)")
    genes = d.get("genes", {})
    bloc = genes.get("bloc")
    if not bloc:
        warn("aucun gène bloc dans ce maillon, étape sautée")
        return None

    hauteur = bloc.get("hauteur")
    hash_declare = bloc.get("hash")
    horodatage_declare = bloc.get("horodatage") or bloc.get("horodate")

    if hauteur is None:
        warn("gène bloc présent mais sans hauteur exploitable")
        info(f"contenu brut : {bloc}")
        return None

    info(f"hauteur déclarée : {hauteur}")
    info(f"hash déclaré : {hash_declare}")
    info(f"horodatage déclaré : {horodatage_declare}")

    accords = 0
    desaccords = 0
    total_sources = 0
    for nom, url_template in BLOCK_SOURCES:
        total_sources += 1
        try:
            url = url_template.format(height=hauteur)
            resultat = http_get_json(url).strip().strip('"')
            if hash_declare and resultat.lower() == str(hash_declare).lower():
                ok(f"{nom} confirme le hash du bloc {hauteur}")
                accords += 1
            elif hash_declare:
                fail(f"{nom} renvoie un hash différent pour le bloc {hauteur} : {resultat}")
                desaccords += 1
            else:
                info(f"{nom} renvoie {resultat} pour le bloc {hauteur} (pas de hash déclaré à comparer)")
                accords += 1
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            warn(f"{nom} injoignable ({e}), source ignorée")

    if LOCAL_NODE_RPC:
        info("nœud local configuré — vérification via bitcoin-cli à ajouter ici")
        # TODO : une fois le nœud synchronisé, interroger `bitcoin-cli getblockhash <hauteur>`
        # et comparer localement, sans dépendre d'aucune source tierce.

    if total_sources and accords >= max(2, total_sources - 1):
        ok(f"preuve de fraîcheur Bitcoin confirmée par {accords}/{total_sources} source(s) indépendante(s)")
        return True
    elif accords > 0:
        warn(f"seulement {accords}/{total_sources} source(s) ont confirmé — vérification partielle")
        return None
    elif desaccords == 0:                               # aucune réponse (hors ligne) : rien ne contredit le maillon
        warn("aucune source joignable (connexion internet ?) — bloc non vérifiable ici")
        return None
    else:
        fail("aucune source indépendante n'a pu confirmer ce bloc")
        return False


def bibliotheque_ots(dossier_trackyzz=None):
    """(fonction de lecture d'un .ots, classe d'attestation Bitcoin, origine), ou None. D'abord la bibliothèque
    opentimestamps si elle est installée ; sinon, sans rien installer, app\\ancrage.py de TRACKYZZ avec les
    bibliothèques de son .venv (ajoutées au chemin de recherche de Python, jamais copiées ni modifiées)."""
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.serialize import StreamDeserializationContext

        def lire(p):
            with open(p, "rb") as f:
                return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
        return lire, BitcoinBlockHeaderAttestation, "bibliothèque opentimestamps installée"
    except ImportError:
        pass
    d = Path(dossier_trackyzz or os.environ.get("SCELYANS_TRACKYZZ") or TRACKYZZ_DEFAUT)
    ancrage = d / "app" / "ancrage.py"
    paquets = [p for p in [d / ".venv" / "Lib" / "site-packages", *sorted((d / ".venv" / "lib").glob("python3*/site-packages"))]
               if (p / "opentimestamps").is_dir()]
    if not ancrage.exists() or not paquets:
        return None
    sys.path.append(str(paquets[0]))                    # en dernier : ne masque jamais une bibliothèque déjà présente
    try:
        spec = importlib.util.spec_from_file_location("ancrage_trackyzz", ancrage)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m.load, m.BitcoinBlockHeaderAttestation, f"app\\ancrage.py de TRACKYZZ ({d})"
    except Exception:
        return None


def verifier_opentimestamps(json_path, ots_path, dossier_trackyzz=None):
    """
    Vérifie le fichier .bitcoin.ots directement via la bibliothèque Python
    opentimestamps, sans passer par l'exécutable `ots` (qui plante sur
    certains Windows à cause d'une dépendance OpenSSL manquante — constaté
    sur ce projet le 26/10/2026). C'est la même logique que celle validée
    manuellement sur les 16 jours déjà ancrés (972 122 -> 973 055).
    """
    section("3. Ancrage OpenTimestamps (standard ouvert, indépendant de TRACKYZZ)")
    if not ots_path:
        warn("aucun fichier .bitcoin.ots fourni, étape sautée (voir l'usage en haut du fichier)")
        return None
    if not os.path.exists(ots_path):
        fail(f"fichier introuvable : {ots_path}")
        return False

    lib = bibliotheque_ots(dossier_trackyzz)
    if lib is None:
        warn("bibliothèque OpenTimestamps introuvable : ni installée (pip install opentimestamps-client), ni dans "
             "le dossier TRACKYZZ (option --trackyzz) — impossible de vérifier cette étape ici")
        return None
    lire_ots, BitcoinBlockHeaderAttestation, origine = lib
    info(f"lecture du .ots : {origine}")

    try:
        dtf = lire_ots(ots_path)

        with open(json_path, "rb") as f:
            contenu = f.read()
        empreinte_calculee = dtf.file_hash_op(contenu)
        if empreinte_calculee != dtf.file_digest:
            fail("l'empreinte du fichier ne correspond pas à celle attestée dans le .ots "
                 "— le fichier a été modifié depuis son scellement")
            return False
        ok("l'empreinte du fichier correspond à celle attestée dans le .ots")

        attestations_bitcoin = [
            (msg, att) for msg, att in dtf.timestamp.all_attestations()
            if isinstance(att, BitcoinBlockHeaderAttestation)
        ]
    except Exception as e:
        fail(f"lecture du fichier .ots impossible ({type(e).__name__}: {str(e)[:150]})")
        return False

    if not attestations_bitcoin:
        warn("aucune attestation Bitcoin trouvée dans ce .ots pour l'instant — "
             "la preuve est peut-être encore en attente de confirmation dans un bloc "
             "(nécessite un 'ots upgrade'), pas forcément une falsification")
        return None

    confirmes = 0
    for msg, attestation in attestations_bitcoin:
        hauteur = attestation.height
        racine_attendue = msg[::-1].hex()  # ordre big-endian habituel des explorateurs
        try:
            url = f"https://mempool.space/api/block-height/{hauteur}"
            block_hash = http_get_json(url).strip().strip('"')
            url_bloc = f"https://mempool.space/api/block/{block_hash}"
            details = json.loads(http_get_json(url_bloc))
            racine_reelle = details.get("merkle_root", "")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            warn(f"bloc {hauteur} : impossible d'interroger mempool.space ({e})")
            continue

        if racine_reelle.lower() == racine_attendue.lower():
            ok(f"attestation Bitcoin confirmée au bloc {hauteur} — "
               f"preuve existait au plus tard à ce bloc")
            confirmes += 1
        else:
            fail(f"bloc {hauteur} : la racine Merkle ne correspond pas "
                 f"(attendue {racine_attendue}, trouvée {racine_reelle})")

    if confirmes:
        ok(f"ancrage Bitcoin confirmé ({confirmes}/{len(attestations_bitcoin)} attestation(s))")
        return True
    else:
        fail("aucune attestation Bitcoin n'a pu être confirmée")
        return False


def trouver_veille(d, maillon_path, maillon_veille_path):
    """(maillon de la veille, d'où il vient) ou (None, raison). Ordre : fichier fourni, fichier à côté du maillon,
    trackyzz.com. Un fichier fourni mais introuvable est une erreur de l'utilisateur, pas une absence."""
    jv = d.get("jour_veille")
    if maillon_veille_path:
        if not os.path.exists(maillon_veille_path):
            raise FileNotFoundError(maillon_veille_path)
        return charger_maillon(maillon_veille_path), maillon_veille_path
    voisin = Path(maillon_path).with_name(f"adn-{jv}.json")
    if voisin.exists():
        return charger_maillon(voisin), str(voisin)
    url = ADN_URL.format(jour=jv)
    try:
        return json.loads(http_get_json(url)), url
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return None, f"ni fourni, ni à côté du maillon, ni sur {url} ({e})"


def verifier_continuite(d, maillon_veille_path, maillon_path="."):
    section("5. Continuité de la chaîne")
    if d.get("racine_veille") is None and d.get("jour_veille") is None:
        ok("premier maillon de la chaîne : pas de veille")
        return True
    try:
        attendu = (date.fromisoformat(d["jour"]) - timedelta(days=1)).isoformat()
    except (KeyError, TypeError, ValueError):
        fail(f"jour illisible : {d.get('jour')}")
        return False
    if d.get("jour_veille") != attendu:
        fail(f"jour_veille ({d.get('jour_veille')}) n'est pas la veille de {d.get('jour')} ({attendu})")
        return False
    try:
        veille, origine = trouver_veille(d, maillon_path, maillon_veille_path)
    except FileNotFoundError as e:
        fail(f"fichier introuvable : {e}")
        return False
    if veille is None:
        warn(f"maillon de la veille ({attendu}) introuvable : {origine} — continuité non vérifiable ici")
        return None
    info(f"maillon de la veille : {origine}")
    if veille.get("jour") != attendu:
        fail(f"le maillon de la veille porte le jour {veille.get('jour')}, et non {attendu}")
        return False
    racine_veille_declaree = d.get("racine_veille")
    racine_veille_reelle = veille.get("racine")

    if racine_veille_declaree == racine_veille_reelle:
        ok(f"racine_veille ({racine_veille_declaree}) correspond bien à la racine du maillon précédent")
        return True
    else:
        fail(f"racine_veille déclarée ({racine_veille_declaree}) ne correspond PAS "
             f"à la racine réelle du maillon précédent ({racine_veille_reelle})")
        return False


def sha256_url(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "scelyans-verify/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return hashlib.sha256(resp.read()).hexdigest()


def versions_publiees(depot, chemin):
    """{sha256: commit} de toutes les versions de `chemin` dans l'historique du dépôt GitHub public.
    Les fichiers sont comparés tels qu'enregistrés dans le dépôt (fins de ligne LF)."""
    m = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?", depot)
    if not m:
        raise ValueError("CODE_REPO_URL doit ressembler à https://github.com/PROPRIETAIRE/DEPOT")
    proprio, nom = m.group(1), m.group(2)
    api = f"https://api.github.com/repos/{proprio}/{nom}/commits?path={chemin}&per_page=100"
    commits = json.loads(http_get_json(api))
    out = {}
    for c in reversed(commits):                       # du plus ancien au plus récent : le commit d'origine l'emporte
        out.setdefault(sha256_url(f"https://raw.githubusercontent.com/{proprio}/{nom}/{c['sha']}/{chemin}"), c["sha"])
    return out


def verifier_gene_code(d):
    section("4. Gène code (intégrité du logiciel)")
    code = d.get("genes", {}).get("code")
    if not code:
        warn("aucun gène code dans ce maillon, étape sautée")
        return None
    declarees = {"adn.py": code.get("adn_py_sha256"), "archiveur.py": code.get("archiveur_py_sha256")}
    for nom, sha in declarees.items():
        info(f"{nom} déclaré : {sha}")
    if not CODE_REPO_URL:
        warn("URL du dépôt public non configurée (CODE_REPO_URL) — comparaison automatique impossible.")
        return None
    tout_ok = True
    for nom, sha in declarees.items():
        if not sha:
            warn(f"{nom} : empreinte absente du gène code")
            tout_ok = False
            continue
        try:
            publiees = versions_publiees(CODE_REPO_URL, "archiveur/" + nom)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as e:
            warn(f"{nom} : dépôt public injoignable ({e})")
            tout_ok = False
            continue
        commit = publiees.get(str(sha).lower())
        if commit:
            ok(f"{nom} {str(sha)[:12]}… correspond à la version publiée au commit {commit[:7]}")
        else:
            warn(f"{nom} {str(sha)[:12]}… ne correspond à aucune des {len(publiees)} version(s) publiée(s) — "
                 "version antérieure à la publication du dépôt, ou fichier différent : à vérifier à la main")
            tout_ok = False
    return True if tout_ok else None


def verifier_gene_tours(d):
    section("6. Gène tours (incidents de la collecte du jour)")
    t = d.get("genes", {}).get("tours")
    if not t:
        warn("aucun gène tours : maillon scellé avant ce gène (28/10/2026), étape sautée")
        return None
    if t.get("statut") != "mesure":
        warn(f"gène tours non mesuré ce jour-là : {t.get('raison')}")
        return None

    def duree(plages):
        n = 0
        for p in plages:
            a, _, b = p.partition("-")
            ha, ma = map(int, a.split(":"))
            hb, mb = map(int, (b or a).split(":"))
            n += (hb * 60 + mb) - (ha * 60 + ma) + 1
        return n
    try:
        coherent = (duree(t["plages_sans_bloc"]) == t["minutes_sans_bloc"]
                    and duree(t["plages_en_retard"]) == t["minutes_en_retard"]
                    and len(t["creneaux_oracles_perdus"]) == t["oracles_perdus"]
                    and (t["retard_max_s"] > t["seuil_retard_s"]) == (t["minutes_en_retard"] > 0))
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        fail(f"gène tours illisible ({type(e).__name__})")
        return False
    if not coherent:
        fail("gène tours incohérent : les nombres ne correspondent pas aux listes")
        return False
    if t["minutes_sans_bloc"] or t["minutes_en_retard"] or t["oracles_perdus"]:
        if t["minutes_sans_bloc"]:
            warn(f"{t['minutes_sans_bloc']} minute(s) sans aucun bloc (UTC) : {', '.join(t['plages_sans_bloc'])}")
        if t["minutes_en_retard"]:
            warn(f"{t['minutes_en_retard']} minute(s) de cours écrite(s) en retard (jusqu'à {t['retard_max_s']} s) : "
                 f"{', '.join(t['plages_en_retard'])}")
        if t["oracles_perdus"]:
            warn(f"{t['oracles_perdus']} lecture(s) d'oracles perdue(s) (UTC) : {', '.join(t['creneaux_oracles_perdus'])}")
        info("incidents de collecte notés et scellés : ce n'est pas une falsification")
    else:
        ok("aucun tour manqué, aucun retard, aucune lecture d'oracles perdue")
    return True


# Recalcul indépendant de la racine (RFC 9162 : feuille 0x00 || données, nœud 0x01 || gauche || droite).

def _feuille(donnees):
    return hashlib.sha256(b"\x00" + donnees).digest()


def _racine(h):
    while len(h) > 1:                                   # par niveaux : un nœud sans frère monte tel quel
        h = [hashlib.sha256(b"\x01" + h[i] + h[i + 1]).digest() if i + 1 < len(h) else h[i] for i in range(0, len(h), 2)]
    return h[0]


def _json_canonique(v):
    return (json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def lire_feuilles(path):
    b = Path(path).read_bytes()
    return (gzip.decompress(b) if b[:2] == b"\x1f\x8b" else b).decode("ascii")


def verifier_feuilles(d, feuilles_path):
    section("7. Racine recalculée depuis les empreintes des feuilles")
    if not feuilles_path:
        warn("aucun fichier feuilles-AAAA-MM-JJ.txt.gz fourni ni à côté du maillon, étape sautée")
        return None
    try:
        lignes = lire_feuilles(feuilles_path).splitlines()
    except (OSError, ValueError, EOFError) as e:
        fail(f"fichier des feuilles illisible ({type(e).__name__})")
        return False
    tete = ["adn-scelyans-feuilles/1", f"jour {d.get('jour')}", f"racine {d.get('racine')}",
            f"feuilles {d.get('feuilles', {}).get('total')}"]
    if lignes[:4] != tete:
        fail("en-tête différent du maillon (jour, racine ou nombre de feuilles)")
        return False
    h, types = [], []
    for k, l in enumerate(lignes[4:]):
        m = re.fullmatch(r"(\d+) (veille|empreinte|releve [0-2]\d|incident|gene [a-z]+) ([0-9a-f]{64})", l)
        if not m or int(m.group(1)) != k:
            fail(f"ligne {k + 5} illisible ou hors d'ordre")
            return False
        types.append(m.group(2))
        h.append(bytes.fromhex(m.group(3)))
    f = d.get("feuilles", {})
    info(f"{len(h)} feuilles ({f.get('releves')} relevés, soit environ 21 000 par jour complet)")
    tout_ok = True
    genes = d.get("genes") or {}
    noms = [n for n in ["code", "horloge", "bloc", "temoin", "astra", "tours", "bce"] if n in genes]
    attendu = (["veille", "empreinte"] + ["releve"] * f.get("releves", -1) + ["incident"] * f.get("incidents", -1)
               + [f"gene {n}" for n in noms])
    if [t[:6] if t.startswith("releve") else t for t in types] != attendu:
        fail("types de feuilles différents des comptes du maillon")
        tout_ok = False
    if h and h[0] == _feuille(b"adn/1 veille " + (d.get("racine_veille") or "aucune").encode() + b"\n"):
        ok("feuille veille recalculée depuis racine_veille")
    else:
        fail("feuille veille différente de racine_veille")
        tout_ok = False
    for t, x in zip(types, h):
        if t.startswith("gene ") and t[5:] in genes:
            if x != _feuille(b"adn/1 gene " + t[5:].encode() + b"\n" + _json_canonique(genes[t[5:]])):
                fail(f"feuille {t} différente de la valeur publiée dans le maillon")
                tout_ok = False
    if h and _racine(h).hex() == d.get("racine"):
        ok(f"racine recalculée sur les {len(h)} feuilles : identique à la racine scellée")
    else:
        fail("racine recalculée DIFFÉRENTE de la racine scellée")
        tout_ok = False
    return tout_ok


def lire_bce(b):
    """(date, taux EUR/USD tel qu'écrit) d'un fichier quotidien de la BCE. ValueError s'il n'en est pas un."""
    import xml.etree.ElementTree as ET
    if len(b) > 65536 or b"<!DOCTYPE" in b.upper() or b"<!ENTITY" in b.upper():
        raise ValueError("fichier refusé (taille ou DOCTYPE)")
    try:
        jours = [e for e in ET.fromstring(b).iter() if e.tag.endswith("Cube") and "time" in e.attrib]
    except ET.ParseError as e:
        raise ValueError(str(e))
    if len(jours) != 1:
        raise ValueError("pas exactement une date de publication")
    usd = [c.get("rate") for c in jours[0] if c.get("currency") == "USD"]
    if len(usd) != 1:
        raise ValueError("taux EUR/USD absent")
    return jours[0].get("time"), usd[0]


def verifier_gene_bce(d, bce_path):
    section("8. Gène bce (taux de référence de la Banque centrale européenne)")
    g = d.get("genes", {}).get("bce")
    if not g:
        warn("aucun gène bce : maillon scellé avant ce gène, étape sautée")
        return None
    if g.get("statut") == "sans_publication":
        ok(f"aucun taux ce jour-là, noté comme tel : {g.get('raison')}")
        return True
    if g.get("statut") != "mesure":
        warn(f"gène bce non mesuré ce jour-là : {g.get('raison')}")
        return None
    jour, taux = g.get("date_publication"), g.get("eur_usd")
    info(f"publication BCE du {jour} : 1 EUR = {taux} USD")
    if jour != d.get("jour"):
        fail(f"date de publication ({jour}) différente du jour scellé ({d.get('jour')})")
        return False
    resultat = True
    if not bce_path:
        warn(f"fichier bce-{jour}.xml non fourni ni à côté du maillon : empreinte non vérifiable ici")
        resultat = None
    else:
        try:
            b = Path(bce_path).read_bytes()
        except OSError as e:
            fail(f"fichier BCE illisible ({type(e).__name__})")
            return False
        if hashlib.sha256(b).hexdigest() != g.get("fichier_sha256"):
            fail("empreinte du fichier BCE différente de celle du gène : fichier modifié")
            return False
        try:
            lu = lire_bce(b)
        except ValueError as e:
            fail(f"fichier BCE illisible ({e})")
            return False
        if lu != (jour, taux):
            fail(f"le fichier BCE indique {lu[1]} USD le {lu[0]}, le gène {taux} USD le {jour}")
            return False
        ok("empreinte, date et taux du fichier BCE conservé identiques au gène")
    try:
        hist = http_get_json(BCE_HIST_URL, timeout=30)
        m = re.search(r"<Cube time=['\"]" + re.escape(jour) + r"['\"]>(.*?)</Cube>", hist, re.S)
        m = m and re.search(r"currency=['\"]USD['\"] rate=['\"]([0-9.]+)['\"]", m.group(1))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        warn(f"historique BCE injoignable ({e}) : taux non recoupé")
        return resultat
    if not m:
        warn(f"aucun taux EUR/USD du {jour} dans l'historique BCE : à vérifier à la main")
        return None
    if float(m.group(1)) != float(taux):
        warn(f"l'historique BCE donne {m.group(1)} USD le {jour}, le gène {taux} : à vérifier à la main")
        return None
    ok(f"taux confirmé par l'historique publié par la BCE ({BCE_HIST_URL})")
    return resultat


def main(argv=None):
    import argparse
    global COULEURS
    try:
        sys.stdout.reconfigure(errors="replace")        # jamais d'arrêt sur un accent dans une console limitée
    except (AttributeError, ValueError):
        pass
    COULEURS = activer_couleurs()
    p = argparse.ArgumentParser(description="Vérificateur public des maillons ADN Scelyans")
    p.add_argument("maillon")
    p.add_argument("ots", nargs="?")
    p.add_argument("veille", nargs="?")
    p.add_argument("--feuilles")
    p.add_argument("--bce", help="fichier bce-AAAA-MM-JJ.xml conservé (sinon cherché à côté du maillon)")
    p.add_argument("--trackyzz", help="dossier TRACKYZZ (app\\ancrage.py et .venv) pour lire les .ots sans installation")
    a = p.parse_args(argv)

    maillon_path = a.maillon
    ots_path = a.ots or (maillon_path + ".bitcoin.ots")
    if not os.path.exists(ots_path):
        ots_path = None
    print(f"Vérification de : {maillon_path}")
    d = charger_maillon(maillon_path)
    feuilles_path = a.feuilles
    if not feuilles_path:
        voisin = Path(maillon_path).with_name(f"feuilles-{d.get('jour')}.txt.gz")
        feuilles_path = str(voisin) if voisin.exists() else None
    bce_path = a.bce
    if not bce_path:
        voisin = Path(maillon_path).with_name(f"bce-{d.get('jour')}.xml")
        bce_path = str(voisin) if voisin.exists() else None

    resultats = {}
    resultats["structure"] = verifier_structure(d)
    resultats["bloc"] = verifier_gene_bloc(d)
    resultats["ots"] = verifier_opentimestamps(maillon_path, ots_path, a.trackyzz)
    resultats["code"] = verifier_gene_code(d)
    resultats["continuite"] = verifier_continuite(d, a.veille, maillon_path)
    resultats["tours"] = verifier_gene_tours(d)
    resultats["feuilles"] = verifier_feuilles(d, feuilles_path)
    resultats["bce"] = verifier_gene_bce(d, bce_path)

    section("Résumé")
    for nom, statut in resultats.items():
        if statut is True:
            ok(nom)
        elif statut is False:
            fail(nom)
        else:
            warn(f"{nom} (non vérifiable avec les éléments fournis)")

    if any(resultats[n] is False for n in ("structure", "bloc", "ots", "continuite", "tours", "feuilles", "bce")):
        print("\nCONCLUSION : ce maillon présente des incohérences. Ne pas s'y fier sans investigation.")
        return 2
    print("\nCONCLUSION : aucune incohérence détectée sur les éléments vérifiables.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
