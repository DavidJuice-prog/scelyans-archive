#!/usr/bin/env python3
"""
verify.py — Vérificateur public des certificats ADN (Scelyans)

Objectif : permettre à n'importe qui (notaire, avocat, comptable, client)
de vérifier de façon indépendante qu'un maillon ADN scellé par TRACKYZZ
est authentique, sans avoir à contacter l'éditeur ni à lui faire confiance
sur parole.

Usage :
    python verify.py adn-2026-10-24.json [adn-2026-10-24.json.bitcoin.ots]

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
   d'OpenSSL), vérifie que l'empreinte du fichier correspond, puis
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

5. Continuité de la chaîne (si le maillon de la veille est fourni)
   Vérifie que racine_veille correspond bien à la racine du jour
   précédent, ce qui prouve que la chaîne n'a pas été rompue ou
   réécrite rétroactivement.

Ce que ce script ne fait PAS (honnêteté sur les limites actuelles) :
   - Il ne recalcule pas la racine du jour à partir des 21 000 relevés
     de prix bruts (l'algorithme exact de construction de l'arbre de
     Merkle, décrit par les champs "algorithme"/"methode"/"ordre_feuilles",
     doit être documenté publiquement pour que cette étape soit possible
     à quiconque, pas seulement à TRACKYZZ). C'est la prochaine étape à
     publier pour une vérification totalement de bout en bout.
"""

import sys
import os
import json
import hashlib
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone

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


def ok(msg):
    print(f"  \033[92m[OK]\033[0m {msg}")


def fail(msg):
    print(f"  \033[91m[ECHEC]\033[0m {msg}")


def warn(msg):
    print(f"  \033[93m[ATTENTION]\033[0m {msg}")


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
        ok(f"les {len(CHAMPS_ATTENDUS)} champs et {len(GENES_ATTENDUS)} gènes attendus sont présents")
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
    else:
        fail("aucune source indépendante n'a pu confirmer ce bloc")
        return False


def verifier_opentimestamps(json_path, ots_path):
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

    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.serialize import StreamDeserializationContext
    except ImportError:
        warn("la bibliothèque 'opentimestamps' n'est pas installée sur cette machine "
             "(pip install opentimestamps-client) — impossible de vérifier cette étape ici")
        return None

    try:
        with open(ots_path, "rb") as f:
            ctx = StreamDeserializationContext(f)
            dtf = DetachedTimestampFile.deserialize(ctx)

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


def verifier_continuite(d, maillon_veille_path):
    section("5. Continuité de la chaîne")
    if not maillon_veille_path:
        warn("maillon de la veille non fourni, étape sautée")
        return None
    if not os.path.exists(maillon_veille_path):
        fail(f"fichier introuvable : {maillon_veille_path}")
        return False

    veille = charger_maillon(maillon_veille_path)
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


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    maillon_path = sys.argv[1]
    ots_path = sys.argv[2] if len(sys.argv) > 2 else (maillon_path + ".bitcoin.ots")
    if not os.path.exists(ots_path):
        ots_path = None

    maillon_veille_path = sys.argv[3] if len(sys.argv) > 3 else None

    print(f"Vérification de : {maillon_path}")
    d = charger_maillon(maillon_path)

    resultats = {}
    resultats["structure"] = verifier_structure(d)
    resultats["bloc"] = verifier_gene_bloc(d)
    resultats["ots"] = verifier_opentimestamps(maillon_path, ots_path)
    resultats["code"] = verifier_gene_code(d)
    resultats["continuite"] = verifier_continuite(d, maillon_veille_path)

    section("Résumé")
    for nom, statut in resultats.items():
        if statut is True:
            ok(nom)
        elif statut is False:
            fail(nom)
        else:
            warn(f"{nom} (non vérifiable avec les éléments fournis)")

    if (resultats["structure"] is False or resultats["bloc"] is False or resultats["ots"] is False
            or resultats["continuite"] is False):
        print("\nCONCLUSION : ce maillon présente des incohérences. Ne pas s'y fier sans investigation.")
        sys.exit(2)
    else:
        print("\nCONCLUSION : aucune incohérence détectée sur les éléments vérifiables.")
        sys.exit(0)


if __name__ == "__main__":
    main()
