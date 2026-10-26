"""Archiveur ARCHIVE_PROJET : découpe le registre et les réponses brutes de TRACKYZZ en fichiers horaires fermés.

LECTURE SEULE des fichiers de TRACKYZZ : aucune écriture, aucun verrou, aucun import de son code.
Seule la bibliothèque standard de Python est utilisée (rien à installer).

Chaque ligne de TRACKYZZ porte son heure de réception (« collecte », croissante dans chaque fichier). Pour chaque heure
UTC terminée H :
  heures/AAAA-MM-JJ/HH.registre.jsonl.gz   lignes du registre reçues pendant H, octet pour octet
  heures/AAAA-MM-JJ/HH.brut.jsonl.gz       réponses brutes reçues pendant H, octet pour octet (contenu décompressé)
  heures/AAAA-MM-JJ/HH.json                manifeste : nombre de lignes, SHA-256, premier et dernier index, chaînage
Le manifeste est écrit en dernier : une heure est fermée quand son manifeste existe.

Règles :
  - un fichier est créé une seule fois (création exclusive), puis mis en lecture seule ; jamais réécrit ni effacé ;
  - une heure est fermée quand TRACKYZZ a déjà écrit une ligne de l'heure suivante (fermeture « normale »), ou, si le
    collecteur se tait, une heure après sa fin (fermeture « par_delai ») ;
  - une heure sans ligne est fermée vide et notée dans trous.jsonl : rien n'est inventé ;
  - toute anomalie (chaîne rompue entre deux heures, fichier déjà présent avec un autre contenu, jour discordant,
    heure toujours pas fermée 20 minutes après sa fin, vérification quotidienne en échec, ancrage en échec) est ajoutée
    à incidents.jsonl, et signalée par ntfy si une adresse est configurée (priorité maximale, titre « 🔴 ARCHIVE ») ;
    une heure fermée vide est aussi signalée ; rien d'autre n'est envoyé ;
  - une heure fermée plus de deux heures après sa fin est marquée « a_posteriori » (reprise du passé, panne).
Un jour dont les 24 heures sont fermées reçoit :
  jours/AAAA-MM-JJ.json      bilan : les 24 fichiers horaires du registre mis bout à bout doivent redonner exactement le
                             fichier du jour de TRACKYZZ, dont l'empreinte figure dans sa tête horodatée du lendemain
                             (tetes/AAAA-MM-JJ.txt, ancrée sur Bitcoin) ; arbre de Merkle des 24 manifestes ;
  preuves/AAAA-MM-JJ/HH.json chemin de Merkle d'une heure : suffit pour prouver cette heure seule ;
  racines/AAAA-MM-JJ.txt     petit texte avec la racine de Merkle, seul fichier à horodater.
Ancrage de chaque racine (si configuré) : OpenTimestamps (.ots, puis .bitcoin.ots une fois confirmé par Bitcoin) et
RFC 3161 (.tsq/.tsr). Les preuves sont produites dans un dossier de travail puis créées une seule fois : le fichier
.ots d'origine n'est jamais complété sur place.

Arbre de Merkle : RFC 9162 (SHA-256 ; feuille = SHA-256(0x00 || manifeste horaire), nœud = SHA-256(0x01 || g || d)).

    python3 archiveur.py executer --config /etc/archiveur/archiveur.conf
    python3 archiveur.py verifier --config /etc/archiveur/archiveur.conf
    python3 archiveur.py prouver  --config /etc/archiveur/archiveur.conf --heure 2026-10-15T14:00:00Z
    python3 archiveur.py alerter  --config /etc/archiveur/archiveur.conf --titre "..." --texte "..."
"""
import argparse, configparser, gzip, hashlib, io, json, os, shutil, subprocess, sys, tempfile, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "archiveur/1"
FORMAT_HEURE = "archive-prix-heure/1"
FORMAT_JOUR = "archive-prix-jour/1"
FORMAT_PREUVE = "archive-prix-preuve-heure/1"
FORMAT_RACINE = "archive-prix-racine/1"
ALGORITHME_MERKLE = "RFC 9162 SHA-256 (feuille 0x00 || manifeste horaire, noeud 0x01 || gauche || droite)"
RELANCE_UPGRADE_S = 3600   # complément Bitcoin d'une preuve OpenTimestamps : tenté au plus une fois par heure
ALERTE_ANCRAGE_S = 7200    # racine toujours sans .ots (ou sans .tsr) 2 h après la fin de son jour : incident, une fois
ALERTE_BITCOIN_S = 172800  # .ots toujours sans confirmation Bitcoin 48 h après sa création : incident, une fois
RETARD_HEURE_S = 1200      # heure toujours pas fermée 20 minutes après sa fin : incident, une fois
PREFIXE_ALERTE = "\U0001F534 ARCHIVE : "
LIBELLES = {
    "chaine_rompue_entre_heures": "chaîne rompue entre deux heures",
    "fichier_deja_present_autre_contenu": "fichier déjà présent avec un autre contenu",
    "jour_discordant": "journée non concordante avec TRACKYZZ",
    "tete_trackyzz_absente": "tête horodatée de TRACKYZZ absente",
    "heure_non_fermee": "heure non fermée",
    "verification_en_echec": "vérification de l'archive en échec",
    "ancrage_ots_en_echec": "ancrage OpenTimestamps en échec",
    "ancrage_rfc3161_en_echec": "horodatage FreeTSA (RFC 3161) en échec",
    "ancrage_bitcoin_en_attente": "confirmation Bitcoin absente après 48 h",
}
MARGE_S = 120              # une heure n'est jamais fermée moins de 2 minutes après sa fin
SILENCE_S = 3600           # collecteur muet : l'heure est fermée une heure après sa fin, avec ce qui existe
A_POSTERIORI_S = 7200      # fermée plus de 2 h après sa fin : constitution « a_posteriori »
ATTENTE_TETE_S = 6 * 3600  # le bilan du jour attend la tête horodatée de TRACKYZZ au plus 6 h


# ------------------------------------------------------------------ outils

def iso(s):
    return datetime.fromtimestamp(int(s), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def secondes(iso_str):
    return int(datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def jour_de(s):
    return datetime.fromtimestamp(int(s), tz=timezone.utc).strftime("%Y-%m-%d")


def sha256_octets(b):
    return hashlib.sha256(b).hexdigest()


def sha256_fichier(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def sha256_contenu_gz(p):
    h = hashlib.sha256()
    with gzip.open(p, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def lignes_completes(p):
    """Lignes terminées par un saut de ligne, telles quelles (octets). Fichier .gz : un membre en cours d'écriture par
    TRACKYZZ en fin de fichier est ignoré (il ne contient que des lignes plus récentes que celles déjà lues)."""
    f = gzip.open(p, "rb") if p.suffix == ".gz" else open(p, "rb")
    try:
        for ligne in f:
            if not ligne.endswith(b"\n"):
                return
            yield ligne
    except (EOFError, gzip.BadGzipFile):
        return
    finally:
        f.close()


def derniere_collecte(fichier):
    """Heure de réception de la dernière ligne complète d'un fichier du registre (lecture de la fin seulement)."""
    if not fichier.exists():
        return None
    with open(fichier, "rb") as f:
        f.seek(0, os.SEEK_END)
        depart = max(0, f.tell() - (1 << 20))
        f.seek(depart)
        fin = f.read()
    lignes = fin.split(b"\n")[:-1]          # après le dernier saut de ligne : ligne en cours d'écriture, ignorée
    if depart:
        lignes = lignes[1:]                 # première ligne coupée par la lecture de la fin seulement
    for l in reversed(lignes):
        try:
            return json.loads(l)["collecte"]
        except (ValueError, KeyError):
            continue
    return None


def creer_une_fois(p, contenu, journal):
    """Création exclusive puis lecture seule. Si le fichier existe : même contenu, rien à faire ; autre contenu, il
    n'est jamais touché et la nouvelle version est gardée à côté (suffixe .conflit-<empreinte>), avec un incident."""
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(p, "xb") as f:
            f.write(contenu)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(p, 0o444)
        return p
    except FileExistsError:
        pass
    ancien = p.read_bytes()
    if ancien == contenu or (p.suffix == ".gz" and gzip.decompress(ancien) == gzip.decompress(contenu)):
        return p
    autre = p.with_name(f"{p.name}.conflit-{sha256_octets(contenu)[:12]}")
    if not autre.exists():
        with open(autre, "xb") as f:
            f.write(contenu)
        os.chmod(autre, 0o444)
    journal.incident("fichier_deja_present_autre_contenu", fichier=str(p), garde_a_cote=autre.name)
    return p


def gz_deterministe(contenu):
    """Compression reproductible : sans nom ni date dans l'en-tête gzip (même contenu, mêmes octets)."""
    tampon = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=tampon, mtime=0, compresslevel=6) as g:
        g.write(contenu)
    return tampon.getvalue()


def json_canonique(o):
    return (json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


# ------------------------------------------------------------------ arbre de Merkle (RFC 9162, section 2.1)

def feuille(donnees):
    return hashlib.sha256(b"\x00" + donnees).digest()


def noeud(gauche, droite):
    return hashlib.sha256(b"\x01" + gauche + droite).digest()


def _coupure(n):
    """Plus grande puissance de 2 strictement inférieure à n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def racine_merkle(feuilles):
    if len(feuilles) == 1:
        return feuilles[0]
    k = _coupure(len(feuilles))
    return noeud(racine_merkle(feuilles[:k]), racine_merkle(feuilles[k:]))


def chemin_merkle(m, feuilles):
    """Chemin d'inclusion de la feuille m (frères du bas vers le haut)."""
    if len(feuilles) == 1:
        return []
    k = _coupure(len(feuilles))
    if m < k:
        return chemin_merkle(m, feuilles[:k]) + [racine_merkle(feuilles[k:])]
    return chemin_merkle(m - k, feuilles[k:]) + [racine_merkle(feuilles[:k])]


def verifier_chemin(index, taille, f, chemin, racine):
    """Vérification d'inclusion, algorithme de la RFC 9162 (section 2.1.3.2)."""
    if index >= taille:
        return False
    fn, sn, r = index, taille - 1, f
    for p in chemin:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = noeud(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = noeud(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == racine


# ------------------------------------------------------------------ journaux (ajout seul)

class Journal:
    def __init__(self, dest, ntfy_url=None, now_s=None):
        self.dest, self.ntfy_url, self.now_s = dest, ntfy_url, now_s
        self.incidents, self.trous = [], []

    def _ajouter(self, nom, entree):
        self.dest.mkdir(parents=True, exist_ok=True)
        with open(self.dest / nom, "ab") as f:
            f.write(json_canonique(entree))

    def incident(self, type_, **details):
        e = {"type": type_, "detecte_le": iso(self.now_s), "version": VERSION, **details}
        self._ajouter("incidents.jsonl", e)
        self.incidents.append(e)
        envoyer_ntfy(self.ntfy_url, LIBELLES.get(type_, "incident " + type_), json.dumps(details, ensure_ascii=False)[:1000])

    def incident_une_fois(self, type_, **details):
        """Comme incident(), sauf si le même incident (même type, mêmes détails) figure déjà dans incidents.jsonl."""
        p = self.dest / "incidents.jsonl"
        if p.exists():
            for ligne in p.read_text(encoding="utf-8").splitlines():
                try:
                    e = json.loads(ligne)
                except ValueError:
                    continue
                if e.get("type") == type_ and all(e.get(k) == v for k, v in details.items()):
                    return False
        self.incident(type_, **details)
        return True

    def trou(self, heure, type_):
        e = {"heure": heure, "type": type_, "note_le": iso(self.now_s), "version": VERSION}
        self._ajouter("trous.jsonl", e)
        self.trous.append(e)
        envoyer_ntfy(self.ntfy_url, "heure fermée vide (aucune donnée de TRACKYZZ)",
                     f"Heure {heure} fermée sans aucune ligne ({type_}). Notée dans trous.jsonl, jamais comblée.")


def envoyer_ntfy(url, titre, texte):
    """Alerte facultative (priorité maximale, titre « 🔴 ARCHIVE : ... ») ; ne fait jamais échouer l'archivage.
    Publication JSON de ntfy : l'adresse « https://serveur/sujet » donne le serveur et le sujet."""
    if not url:
        return False
    try:
        base, _, sujet = url.strip().rstrip("/").rpartition("/")
        corps = json.dumps({"topic": sujet, "title": PREFIXE_ALERTE + titre, "message": texte, "priority": 5},
                           ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(base, data=corps, method="POST",
                                     headers={"Content-Type": "application/json; charset=utf-8"})
        urllib.request.urlopen(req, timeout=10).close()
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ fermeture des heures

def dossier_heure(dest, h):
    return dest / "heures" / jour_de(h)


def manifeste_heure(dest, h):
    return dossier_heure(dest, h) / f"{datetime.fromtimestamp(h, tz=timezone.utc):%H}.json"


def lire_manifeste(dest, h):
    p = manifeste_heure(dest, h)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def precedent_non_vide(dest, h, debut_s):
    """Dernier manifeste avant h qui contient des lignes du registre (pour vérifier le chaînage entre heures)."""
    t = h - 3600
    while t >= debut_s:
        m = lire_manifeste(dest, t)
        if m and m["registre"]["lignes"]:
            return m
        t -= 3600
    return None


def heures_a_fermer(dest, jour_str, now_s, derniere):
    """Heures du jour non fermées qui peuvent l'être maintenant. Renvoie [(h, mode_de_fermeture)]."""
    debut = secondes(jour_str + "T00:00:00Z")
    out = []
    for h in range(debut, debut + 86400, 3600):
        fin = h + 3600
        if now_s < fin + MARGE_S or manifeste_heure(dest, h).exists():
            continue
        if derniere is not None and secondes(derniere) >= fin:
            out.append((h, "normale"))
        elif now_s >= fin + SILENCE_S:
            out.append((h, "par_delai"))
    return out


def decouper(fichier, heures):
    """Une lecture du fichier : {h: (contenu en octets, lignes décodées)} pour les heures demandées. S'arrête dès qu'une
    ligne dépasse la dernière heure demandée (les lignes sont dans l'ordre de réception)."""
    morceaux = {h: [io.BytesIO(), []] for h in heures}
    if not heures or not fichier.exists():
        return {h: (b"", []) for h in heures}
    derniere_h = max(heures)
    for ligne in lignes_completes(fichier):
        o = json.loads(ligne)
        h = secondes(o["collecte"]) // 3600 * 3600
        if h > derniere_h:
            break
        if h in morceaux:
            morceaux[h][0].write(ligne)
            morceaux[h][1].append(o)
    return {h: (b.getvalue(), objs) for h, (b, objs) in morceaux.items()}


def fermer_heure(dest, h, mode, reg, brut, now_s, debut_s, journal):
    contenu_reg, blocs = reg
    contenu_brut, reponses = brut
    d = dossier_heure(dest, h)
    hh = f"{datetime.fromtimestamp(h, tz=timezone.utc):%H}"
    f_reg = creer_une_fois(d / f"{hh}.registre.jsonl.gz", gz_deterministe(contenu_reg), journal)
    f_brut = creer_une_fois(d / f"{hh}.brut.jsonl.gz", gz_deterministe(contenu_brut), journal)
    m = {
        "format": FORMAT_HEURE, "version": VERSION, "heure": iso(h), "fin": iso(h + 3600),
        "source": "TRACKYZZ /var/lib/trackyzz (registre et brut, heure de réception « collecte »)",
        "fermeture": mode, "ferme_le": iso(now_s),
        "constitution": "a_posteriori" if now_s > h + 3600 + A_POSTERIORI_S else "en_direct",
        "registre": {
            "fichier": f_reg.name, "lignes": len(blocs), "octets": len(contenu_reg),
            "sha256_contenu": sha256_octets(contenu_reg), "sha256_fichier": sha256_fichier(f_reg),
            "premier_index": blocs[0]["index"] if blocs else None, "dernier_index": blocs[-1]["index"] if blocs else None,
            "premier_prev_hash": blocs[0]["prev_hash"] if blocs else None, "dernier_hash": blocs[-1]["hash"] if blocs else None,
            "premiere_collecte": blocs[0]["collecte"] if blocs else None,
            "derniere_collecte": blocs[-1]["collecte"] if blocs else None,
        },
        "brut": {
            "fichier": f_brut.name, "lignes": len(reponses), "octets": len(contenu_brut),
            "sha256_contenu": sha256_octets(contenu_brut), "sha256_fichier": sha256_fichier(f_brut),
        },
    }
    if blocs:
        p = precedent_non_vide(dest, h, debut_s)
        if p and (blocs[0]["prev_hash"] != p["registre"]["dernier_hash"]
                  or blocs[0]["index"] != p["registre"]["dernier_index"] + 1):
            journal.incident("chaine_rompue_entre_heures", heure=iso(h), precedente=p["heure"],
                             attendu_prev_hash=p["registre"]["dernier_hash"], trouve_prev_hash=blocs[0]["prev_hash"],
                             attendu_index=p["registre"]["dernier_index"] + 1, trouve_index=blocs[0]["index"])
    else:
        journal.trou(iso(h), "aucune_ligne_registre")
    creer_une_fois(manifeste_heure(dest, h), json_canonique(m), journal)
    return m


# ------------------------------------------------------------------ bilan du jour

def empreinte_dans_tete(src, jour_str):
    """SHA-256 du registre du jour inscrite par TRACKYZZ dans sa tête horodatée du lendemain, ou None."""
    lendemain = jour_de(secondes(jour_str + "T00:00:00Z") + 86400)
    p = src / "tetes" / f"{lendemain}.txt"
    if not p.exists():
        return None, None
    for l in p.read_text(encoding="utf-8").splitlines():
        parts = l.split()
        if len(parts) == 3 and parts[0] == "sha256" and parts[2] == f"registre/{jour_str}.jsonl":
            return parts[1], f"tetes/{lendemain}.txt"
    return None, f"tetes/{lendemain}.txt"


def feuilles_du_jour(dest, jour_str):
    """Feuilles de Merkle des 24 manifestes horaires du jour (octets exacts des fichiers), ou None s'il en manque."""
    debut = secondes(jour_str + "T00:00:00Z")
    out = []
    for h in range(debut, debut + 86400, 3600):
        p = manifeste_heure(dest, h)
        if not p.exists():
            return None
        out.append(feuille(p.read_bytes()))
    return out


def texte_racine(bilan, sha_bilan):
    r = bilan["registre"]
    concorde = "oui" if r["concorde_fichier"] and r["concorde_tete"] and bilan["brut"]["concorde"] else "NON"
    return (f"archive-prix racine du jour {bilan['jour']}\n"
            f"format {FORMAT_RACINE}\n"
            f"algorithme {ALGORITHME_MERKLE}\n"
            f"heures {len(bilan['heures'])}\n"
            f"racine {bilan['merkle']['racine']}\n"
            f"sha256 {sha_bilan} jours/{bilan['jour']}.json\n"
            f"sha256 {r['sha256_fichier_trackyzz']} trackyzz/registre/{bilan['jour']}.jsonl (concorde avec TRACKYZZ : {concorde})\n"
            ).encode("utf-8")


def fermer_jour(src, dest, jour_str, now_s, journal):
    """Bilan du jour (une seule fois), puis preuves horaires et racine à horodater. Relançable : un bilan existant est
    relu, jamais refait ; preuves et racine se déduisent de lui à l'identique."""
    p = dest / "jours" / f"{jour_str}.json"
    if (dest / "racines" / f"{jour_str}.txt").exists():
        return None
    if not p.exists():
        if not creer_bilan(src, dest, jour_str, now_s, journal):
            return None
    bilan = json.loads(p.read_text(encoding="utf-8"))
    feuilles = [bytes.fromhex(x) for x in bilan["merkle"]["feuilles"]]
    racine = bytes.fromhex(bilan["merkle"]["racine"])
    for i, e in enumerate(bilan["heures"]):
        h = secondes(e["heure"])
        hh = f"{datetime.fromtimestamp(h, tz=timezone.utc):%H}"
        preuve = {"format": FORMAT_PREUVE, "version": VERSION, "jour": jour_str, "heure": e["heure"],
                  "manifeste": f"heures/{jour_str}/{hh}.json", "manifeste_sha256": e["manifeste_sha256"],
                  "algorithme": ALGORITHME_MERKLE, "index": i, "taille": len(feuilles), "feuille": feuilles[i].hex(),
                  "chemin": [x.hex() for x in chemin_merkle(i, feuilles)], "racine": racine.hex(),
                  "racine_fichier": f"racines/{jour_str}.txt"}
        creer_une_fois(dest / "preuves" / jour_str / f"{hh}.json", json_canonique(preuve), journal)
    creer_une_fois(dest / "racines" / f"{jour_str}.txt", texte_racine(bilan, sha256_fichier(p)), journal)
    return bilan


def creer_bilan(src, dest, jour_str, now_s, journal):
    p = dest / "jours" / f"{jour_str}.json"
    debut = secondes(jour_str + "T00:00:00Z")
    heures = [lire_manifeste(dest, h) for h in range(debut, debut + 86400, 3600)]
    if not all(heures):
        return None
    tete_sha, tete_fichier = empreinte_dans_tete(src, jour_str)
    if tete_sha is None and now_s < debut + 86400 + ATTENTE_TETE_S:
        return None                                     # la tête de TRACKYZZ est écrite à 00:10 UTC : on l'attend
    reg, brut = hashlib.sha256(), hashlib.sha256()
    for m in heures:
        d = dest / "heures" / jour_str
        with gzip.open(d / m["registre"]["fichier"], "rb") as f:
            reg.update(f.read())
        with gzip.open(d / m["brut"]["fichier"], "rb") as f:
            brut.update(f.read())
    src_reg, src_brut = src / "registre" / f"{jour_str}.jsonl", src / "brut" / f"{jour_str}.jsonl.gz"
    sha_src_reg = sha256_fichier(src_reg) if src_reg.exists() else None
    sha_src_brut = None
    if src_brut.exists():
        h_brut = hashlib.sha256()
        for ligne in lignes_completes(src_brut):
            h_brut.update(ligne)
        sha_src_brut = h_brut.hexdigest()
    bilan = {
        "format": FORMAT_JOUR, "version": VERSION, "jour": jour_str, "ferme_le": iso(now_s),
        "heures": [{"heure": m["heure"], "manifeste_sha256": sha256_fichier(manifeste_heure(dest, secondes(m["heure"]))),
                    "lignes_registre": m["registre"]["lignes"], "lignes_brut": m["brut"]["lignes"],
                    "fermeture": m["fermeture"], "constitution": m["constitution"]} for m in heures],
        "registre": {"sha256_concatenation_heures": reg.hexdigest(), "sha256_fichier_trackyzz": sha_src_reg,
                     "sha256_tete_trackyzz": tete_sha, "tete_trackyzz": tete_fichier,
                     "concorde_fichier": reg.hexdigest() == sha_src_reg,
                     "concorde_tete": None if tete_sha is None else reg.hexdigest() == tete_sha},
        "brut": {"sha256_concatenation_heures": brut.hexdigest(), "sha256_contenu_trackyzz": sha_src_brut,
                 "concorde": brut.hexdigest() == sha_src_brut},
        "trous_heures": [m["heure"] for m in heures if not m["registre"]["lignes"]],
    }
    feuilles = feuilles_du_jour(dest, jour_str)
    bilan["merkle"] = {"algorithme": ALGORITHME_MERKLE, "feuilles": [f.hex() for f in feuilles],
                       "racine": racine_merkle(feuilles).hex()}
    if not (bilan["registre"]["concorde_fichier"] and bilan["brut"]["concorde"] and bilan["registre"]["concorde_tete"] is not False):
        journal.incident("jour_discordant", jour=jour_str, registre=bilan["registre"], brut=bilan["brut"])
    if tete_sha is None:
        journal.incident("tete_trackyzz_absente", jour=jour_str, attendue=tete_fichier)
    creer_une_fois(p, json_canonique(bilan), journal)
    return bilan


# ------------------------------------------------------------------ ancrage des racines

class Horodateurs:
    """OpenTimestamps (client officiel « ots ») et RFC 3161 (openssl + autorité d'horodatage). Chaque méthode travaille
    sur une copie dans un dossier temporaire et renvoie les octets de la preuve, ou None : rien n'est écrit dans
    l'archive ici. Sans « ots » ni « tsa_url » configurés, aucun appel réseau n'est fait."""

    def __init__(self, ots=None, tsa_url=None, openssl="openssl", delai_s=120):
        self.ots, self.tsa_url, self.openssl, self.delai_s = ots, tsa_url, openssl, delai_s

    def _lancer(self, cmd):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=self.delai_s)

    def ots_stamp(self, p):
        if not self.ots:
            return None
        with tempfile.TemporaryDirectory() as t:
            copie = Path(t) / p.name
            shutil.copyfile(p, copie)
            self._lancer([self.ots, "stamp", str(copie)])
            sortie = copie.with_name(copie.name + ".ots")
            return sortie.read_bytes() if sortie.exists() else None

    def ots_upgrade(self, p, ots_octets):
        """Preuve complétée par Bitcoin (nouveaux octets) si l'attestation Bitcoin est présente, sinon None."""
        if not self.ots:
            return None
        with tempfile.TemporaryDirectory() as t:
            copie = Path(t) / p.name
            shutil.copyfile(p, copie)
            preuve = copie.with_name(copie.name + ".ots")
            preuve.write_bytes(ots_octets)
            self._lancer([self.ots, "upgrade", str(preuve)])
            info = self._lancer([self.ots, "info", str(preuve)])
            if "BitcoinBlockHeaderAttestation" not in info.stdout:
                return None
            return preuve.read_bytes()

    def rfc3161(self, p):
        """(requête .tsq, réponse .tsr) si l'autorité a accordé le jeton, sinon None."""
        if not self.tsa_url:
            return None
        with tempfile.TemporaryDirectory() as t:
            tsq, tsr = Path(t) / "q.tsq", Path(t) / "r.tsr"
            self._lancer([self.openssl, "ts", "-query", "-data", str(p), "-sha256", "-cert", "-no_nonce", "-out", str(tsq)])
            if not tsq.exists():
                return None
            req = urllib.request.Request(self.tsa_url, data=tsq.read_bytes(), method="POST",
                                         headers={"Content-Type": "application/timestamp-query"})
            with urllib.request.urlopen(req, timeout=self.delai_s) as r:
                tsr.write_bytes(r.read())
            texte = self._lancer([self.openssl, "ts", "-reply", "-in", str(tsr), "-text"]).stdout
            if "Granted" not in texte:
                return None
            return tsq.read_bytes(), tsr.read_bytes()


def ancrer(dest, now_s, horo, journal):
    """Pour chaque racine : .ots (une fois), .bitcoin.ots (quand Bitcoin a confirmé), .tsq/.tsr (une fois).
    Une erreur réseau ne fait jamais échouer le passage : l'ancrage est retenté au passage suivant."""
    etat = {"racines": 0, "ots": 0, "bitcoin": 0, "rfc3161": 0, "erreurs": []}
    for p in sorted((dest / "racines").glob("????-??-??.txt")):
        etat["racines"] += 1
        f_ots, f_btc = p.with_name(p.name + ".ots"), p.with_name(p.name + ".bitcoin.ots")
        f_tsq, f_tsr = p.with_name(p.name + ".tsq"), p.with_name(p.name + ".tsr")
        try:
            if not f_ots.exists():
                b = horo.ots_stamp(p)
                if b:
                    creer_une_fois(f_ots, b, journal)
            if f_ots.exists() and not f_btc.exists() and now_s % RELANCE_UPGRADE_S < 300:
                b = horo.ots_upgrade(p, f_ots.read_bytes())
                if b:
                    creer_une_fois(f_btc, b, journal)
        except Exception as e:
            etat["erreurs"].append(f"{p.name} ots : {type(e).__name__} {str(e)[:120]}")
        try:
            if not f_tsr.exists():
                r = horo.rfc3161(p)
                if r:
                    creer_une_fois(f_tsq, r[0], journal)
                    creer_une_fois(f_tsr, r[1], journal)
        except Exception as e:
            etat["erreurs"].append(f"{p.name} rfc3161 : {type(e).__name__} {str(e)[:120]}")
        etat["ots"] += f_ots.exists()
        etat["bitcoin"] += f_btc.exists()
        etat["rfc3161"] += f_tsr.exists()
        # Alertes : une seule fois par racine et par type, seulement si l'ancrage est configuré
        depuis = now_s - max(secondes(p.stem + "T00:00:00Z") + 86400, int(p.stat().st_mtime))
        if horo.ots and not f_ots.exists() and depuis > ALERTE_ANCRAGE_S:
            journal.incident_une_fois("ancrage_ots_en_echec", racine=p.name)
        if getattr(horo, "tsa_url", None) and not f_tsr.exists() and depuis > ALERTE_ANCRAGE_S:
            journal.incident_une_fois("ancrage_rfc3161_en_echec", racine=p.name)
        if horo.ots and f_ots.exists() and not f_btc.exists() and now_s - int(f_ots.stat().st_mtime) > ALERTE_BITCOIN_S:
            journal.incident_une_fois("ancrage_bitcoin_en_attente", racine=p.name)
    return etat


# ------------------------------------------------------------------ passage complet

def lire_config(path):
    cp = configparser.ConfigParser()
    if not cp.read(path, encoding="utf-8-sig") or "archiveur" not in cp:     # -sig : fichier enregistré avec BOM
        raise SystemExit(f"Configuration introuvable ou sans section [archiveur] : {path}")
    c = cp["archiveur"]
    v = lambda k, d="": c.get(k, d).strip() or None
    return {"source": Path(v("source", "/var/lib/trackyzz")), "destination": Path(v("destination", "/var/lib/archiveur")),
            "debut": v("debut"), "ntfy_url": v("ntfy_url"),
            "ots": v("ots"), "tsa_url": v("tsa_url"), "openssl": v("openssl", "openssl")}


def executer(conf, now_s=None, horo=None):
    now_s = int(now_s or time.time())
    src, dest = conf["source"], conf["destination"]
    horo = horo or Horodateurs(conf.get("ots"), conf.get("tsa_url"), conf.get("openssl") or "openssl")
    journal = Journal(dest, conf.get("ntfy_url"), now_s)
    fichiers = sorted((src / "registre").glob("????-??-??.jsonl"))
    if not fichiers:
        return {"heures_fermees": 0, "jours_fermes": [], "message": "aucun registre TRACKYZZ"}
    premier = conf.get("debut") or fichiers[0].stem
    debut_s = secondes(premier + "T00:00:00Z")
    derniere = derniere_collecte(fichiers[-1])
    fermees, jours = [], []
    for j in range(debut_s, now_s // 86400 * 86400 + 86400, 86400):
        jour_str = jour_de(j)
        if (dest / "racines" / f"{jour_str}.txt").exists():
            continue                                        # jour terminé : heures, bilan, preuves et racine écrits
        a_fermer = heures_a_fermer(dest, jour_str, now_s, derniere)
        if a_fermer:
            hs = [h for h, _ in a_fermer]
            reg = decouper(src / "registre" / f"{jour_str}.jsonl", hs)
            brut = decouper(src / "brut" / f"{jour_str}.jsonl.gz", hs)
            for h, mode in a_fermer:
                fermees.append(fermer_heure(dest, h, mode, reg[h], brut[h], now_s, debut_s, journal)["heure"])
        if fermer_jour(src, dest, jour_str, now_s, journal):
            jours.append(jour_str)
    # Heure toujours pas fermée 20 minutes après sa fin (collecteur muet ou archiveur bloqué) : signalée une fois
    for h in range(max(debut_s, (now_s - 6 * 3600) // 3600 * 3600), now_s, 3600):
        if now_s >= h + 3600 + RETARD_HEURE_S and not manifeste_heure(dest, h).exists():
            journal.incident_une_fois("heure_non_fermee", heure=iso(h), derniere_collecte_trackyzz=derniere)
    # Une fois par jour, après la fermeture d'une journée : vérification complète de l'archive
    verification = None
    if jours:
        n, problemes = verifier(conf)
        verification = {"heures_relues": n, "problemes": len(problemes)}
        if problemes:
            journal.incident("verification_en_echec", jour=jours[-1], problemes=problemes[:10])
    ancrage = ancrer(dest, now_s, horo, journal)
    return {"heures_fermees": len(fermees), "premiere": fermees[0] if fermees else None,
            "derniere": fermees[-1] if fermees else None, "jours_fermes": jours, "verification": verification,
            "trous": len(journal.trous), "incidents": [i["type"] for i in journal.incidents], "ancrage": ancrage}


def verifier(conf):
    """Relit tout, ne modifie rien : fichiers horaires contre manifestes, bilans contre manifestes, arbre de Merkle
    recalculé, racines et preuves horaires contre l'arbre."""
    dest = conf["destination"]
    problemes, n = [], 0
    for mp in sorted((dest / "heures").glob("????-??-??/??.json")):
        m = json.loads(mp.read_text(encoding="utf-8"))
        n += 1
        for cle in ("registre", "brut"):
            f = mp.parent / m[cle]["fichier"]
            if not f.exists():
                problemes.append(f"{mp.parent.name}/{f.name} : absent")
            elif sha256_fichier(f) != m[cle]["sha256_fichier"] or sha256_contenu_gz(f) != m[cle]["sha256_contenu"]:
                problemes.append(f"{mp.parent.name}/{f.name} : empreinte différente du manifeste")
    for bp in sorted((dest / "jours").glob("????-??-??.json")):
        b = json.loads(bp.read_text(encoding="utf-8"))
        j = b["jour"]
        for e in b["heures"]:
            mp = manifeste_heure(dest, secondes(e["heure"]))
            if not mp.exists() or sha256_fichier(mp) != e["manifeste_sha256"]:
                problemes.append(f"{bp.name} : manifeste {e['heure']} absent ou modifié")
        feuilles = feuilles_du_jour(dest, j)
        if feuilles is None or racine_merkle(feuilles).hex() != b["merkle"]["racine"]:
            problemes.append(f"{bp.name} : racine de Merkle recalculée différente")
            continue
        rp = dest / "racines" / f"{j}.txt"
        if not rp.exists() or rp.read_bytes() != texte_racine(b, sha256_fichier(bp)):
            problemes.append(f"racines/{j}.txt : absente ou différente du bilan")
        for i in range(len(feuilles)):
            pp = dest / "preuves" / j / f"{i:02d}.json"
            if not pp.exists() or not preuve_valide(dest, json.loads(pp.read_text(encoding="utf-8"))):
                problemes.append(f"preuves/{j}/{i:02d}.json : absente ou invalide")
    return n, problemes


def preuve_valide(dest, preuve):
    """Une heure seule : son manifeste redonne la feuille, le chemin redonne la racine, la racine est celle du texte
    horodaté."""
    mp = dest / preuve["manifeste"]
    rp = dest / preuve["racine_fichier"]
    if not mp.exists() or not rp.exists():
        return False
    f = feuille(mp.read_bytes())
    if f.hex() != preuve["feuille"] or f"racine {preuve['racine']}\n" not in rp.read_text(encoding="utf-8"):
        return False
    return verifier_chemin(preuve["index"], preuve["taille"], f, [bytes.fromhex(x) for x in preuve["chemin"]],
                           bytes.fromhex(preuve["racine"]))


def prouver(conf, heure_iso):
    """Liste des fichiers qui prouvent une heure, et résultat de la vérification. Ne modifie rien."""
    dest = conf["destination"]
    h = secondes(heure_iso) // 3600 * 3600
    j, hh = jour_de(h), f"{datetime.fromtimestamp(h, tz=timezone.utc):%H}"
    pp = dest / "preuves" / j / f"{hh}.json"
    if not pp.exists():
        return {"heure": iso(h), "statut": "pas encore de preuve (jour non terminé ou hors archive)"}
    preuve = json.loads(pp.read_text(encoding="utf-8"))
    m = lire_manifeste(dest, h)
    fichiers = [f"heures/{j}/{hh}.json", f"heures/{j}/{m['registre']['fichier']}", f"heures/{j}/{m['brut']['fichier']}",
                f"preuves/{j}/{hh}.json", f"racines/{j}.txt"]
    fichiers += [f"racines/{j}.txt{s}" for s in (".ots", ".bitcoin.ots", ".tsr") if (dest / f"racines/{j}.txt{s}").exists()]
    ok = preuve_valide(dest, preuve) and all(
        sha256_fichier(dest / "heures" / j / m[c]["fichier"]) == m[c]["sha256_fichier"] for c in ("registre", "brut"))
    return {"heure": iso(h), "statut": "preuve valide" if ok else "PREUVE INVALIDE", "racine": preuve["racine"],
            "fichiers": fichiers}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Archiveur ARCHIVE_PROJET (lecture seule de TRACKYZZ)")
    ap.add_argument("commande", choices=["executer", "verifier", "prouver", "alerter"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--heure", help="pour « prouver » : AAAA-MM-JJTHH:00:00Z")
    ap.add_argument("--titre", help="pour « alerter » : titre de l'alerte (précédé de « 🔴 ARCHIVE : »)")
    ap.add_argument("--texte", default="", help="pour « alerter » : texte de l'alerte")
    a = ap.parse_args(argv)
    conf = lire_config(a.config)
    if a.commande == "alerter":
        if not a.titre:
            ap.error("--titre est obligatoire pour « alerter »")
        if not conf.get("ntfy_url"):
            print("ntfy_url n'est pas configuré : aucune alerte envoyée")
            return 1
        ok = envoyer_ntfy(conf["ntfy_url"], a.titre, a.texte)
        print("alerte envoyée" if ok else "ÉCHEC de l'envoi de l'alerte")
        return 0 if ok else 1
    if a.commande == "executer":
        print(json.dumps(executer(conf), ensure_ascii=False))
        return 0
    if a.commande == "prouver":
        if not a.heure:
            ap.error("--heure est obligatoire pour « prouver »")
        r = prouver(conf, a.heure)
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return 0 if r["statut"] == "preuve valide" else 1
    n, problemes = verifier(conf)
    for p in problemes:
        print(p)
    print(f"{n} heure(s) relue(s) : " + ("archive intègre" if not problemes else f"{len(problemes)} problème(s)"))
    return 0 if not problemes else 1


if __name__ == "__main__":
    sys.exit(main())
