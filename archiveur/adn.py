"""ADN Scelyans v1 : un arbre de Merkle par jour, chaîné à celui de la veille, ancré dans Bitcoin (OpenTimestamps).

S'ajoute à l'archiveur sans rien changer : lit l'archive (fichiers horaires fermés, incidents, trous) et l'empreinte
du jour de TRACKYZZ (lecture seule) ; écrit seulement dans <destination>/adn/. Bibliothèque standard uniquement.

Feuilles du jour J, dans cet ordre (RFC 9162 : feuille = SHA-256(0x00 || données)) :
  0       « adn/1 veille <racine ADN de J-1> » (« aucune » pour le premier jour) : la racine contient celle de la veille ;
  1       « adn/1 empreinte » + octets exacts de l'empreinte du jour de TRACKYZZ (empreintes/J.txt) ;
  2..     « adn/1 releve » + chaque ligne du registre de J (octets exacts, saut de ligne compris), heure par heure ;
  puis    « adn/1 incident » + « concerne AAAA-MM-JJ » + chaque ligne de incidents.jsonl et de trous.jsonl CONSTATÉE le
          jour J (champ detecte_le ou note_le) ; « concerne » = jour touché (champ jour, heure ou racine de l'incident),
          par exemple constaté le 16/10, concerne le 09/10. Les journaux sont en ajout seul et ne sont jamais réécrits :
          la sélection ne change donc plus une fois le jour passé, et un jour déjà scellé n'est jamais refait ;
  enfin   sept « gènes » du jour, « adn/1 gene <nom> » + leur valeur en JSON canonique, recopiés dans le fichier ADN
          (clé « genes ») pour que la vérification les relise : code (empreintes SHA-256 de adn.py et archiveur.py),
          horloge (écart serveur / heure officielle, chrony ou timesyncd), bloc (dernier bloc Bitcoin avant minuit UTC
          de fin de journée), temoin (concordance Oracle / témoin Cloudflare), astra (tête du jour du registre de
          l'IA ASTRA-M, recopiée telle quelle : empreinte de son fichier du jour et dernier hash de sa chaîne), tours
          (incidents de la collecte du jour, recalculés depuis les relevés scellés : minutes sans aucun bloc écrit,
          minutes de cours écrites en retard, créneaux de 5 minutes sans lecture d'oracle ; la vérification le
          recalcule), bce (taux de référence de la Banque centrale européenne publié le jour J : date de publication,
          taux EUR/USD tel qu'écrit, empreinte du fichier XML quotidien conservé tel quel ; « sans_publication » le
          week-end et les jours où la BCE ne publie pas : jamais le taux de la veille). Un gène non disponible est
          une feuille « statut: indisponible » avec sa raison : l'ADN est produit quand même. Les ADN scellés avant
          les gènes n'en ont pas (pas de clé « genes »), ceux scellés avant le gène astra n'en ont que quatre, avant
          le gène tours que cinq, avant le gène bce que six : tous restent vérifiables tels quels.
Fichiers créés une seule fois, jamais réécrits :
  adn/adn-AAAA-MM-JJ.json            racine, racine de la veille, nombre de feuilles par type, méthode ; aucun prix,
                                     aucune donnée personnelle : c'est le seul fichier destiné à être publié ;
  adn/adn-AAAA-MM-JJ.json.ots        preuve OpenTimestamps, puis .bitcoin.ots une fois confirmée par Bitcoin ;
  adn/feuilles-AAAA-MM-JJ.txt.gz     empreintes SHA-256 de toutes les feuilles du jour, dans l'ordre (« <position>
                                     <type> <empreinte> », type releve suivi de l'heure UTC d'écriture) : un tiers
                                     recalcule la racine sans aucun relevé ni prix (commande « verifier-feuilles »).
                                     Créé seulement s'il redonne exactement la racine de l'ADN ; publiable.
  bce/bce-AAAA-MM-JJ.xml             publication quotidienne de la BCE, octets reçus tels quels (aucune donnée de
                                     TRACKYZZ). Lue au passage horaire les jours ouvrés après 15:00 UTC, sinon au
                                     scellement du jour ; enregistrée seulement sous la date qu'elle porte.
Une preuve d'inclusion (commande « preuve ») contient le relevé lui-même, donc des prix : elle n'est jamais publiée,
seulement remise à qui en a besoin.

    python3 adn.py executer        --config /etc/archiveur/archiveur.conf
    python3 adn.py verifier        --config /etc/archiveur/archiveur.conf
    python3 adn.py preuve          --config /etc/archiveur/archiveur.conf --jour 2026-10-15 --index 123456 [--sortie f]
    python3 adn.py verifier-preuve --preuve preuve.json --adn adn-2026-10-15.json
    python3 adn.py verifier-feuilles --feuilles feuilles-2026-10-15.txt.gz --adn adn-2026-10-15.json [--empreinte 2026-10-15.txt]
"""
import argparse, configparser, gzip, json, re, subprocess, sys, time, urllib.error, urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import archiveur as ar

METHODE = "adn/1"
FORMAT_ADN = "adn-scelyans-jour/1"
FORMAT_PREUVE = "adn-scelyans-preuve-releve/1"
FORMAT_FEUILLES = "adn-scelyans-feuilles/1"
LIGNE_FEUILLE = re.compile(r"(\d+) (veille|empreinte|releve [0-2]\d|incident|gene [a-z]+) ([0-9a-f]{64})")
ALGORITHME = "RFC 9162 SHA-256 (feuille 0x00 || donnees, noeud 0x01 || gauche || droite)"
P_VEILLE, P_EMPREINTE, P_RELEVE, P_INCIDENT = (b"adn/1 veille ", b"adn/1 empreinte\n", b"adn/1 releve\n",
                                               b"adn/1 incident\n")
P_GENE = b"adn/1 gene "                     # + nom + « \n » + valeur JSON canonique
NOMS_GENES = ("code", "horloge", "bloc", "temoin", "astra", "tours", "bce")   # un nouveau gène toujours à la fin
SEUIL_RETARD_S = 180             # comme TRACKYZZ (RETARD_MAX_S) : une minute écrite plus tard a été rattrapée
PERIODE_ORACLES_S = 300          # une lecture d'oracles attendue par créneau de 5 minutes
TAILLE_MAX_TETE_ASTRA = 4096                 # une tête fait 3 lignes ; au-delà, ce n'est pas une tête
API_BLOC = "https://mempool.space/api"      # publique, gratuite, sans clé
REGLE_BLOC = "bloc de plus grande hauteur dont l'horodatage est strictement avant minuit UTC de fin du jour"
ATTENTE_EMPREINTE_S = 6 * 3600   # empreinte TRACKYZZ du jour toujours absente 6 h après minuit : incident, une fois
ATTENTE_ASTRA_S = 9 * 3600       # tête ASTRA publiée par le PC à 08:05 Paris : au-delà de 9 h, scellé sans elle
URL_BCE = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"   # source unique, officielle
VERSION_BCE = "bce/1"
HEURE_BCE_UTC_S = 15 * 3600      # publiée vers 16:00 Paris (15:00 UTC en hiver, 14:00 en été)
DELAI_BCE_S = 10                 # par essai : le passage horaire reste court même si la BCE ne répond pas
ESSAIS_BCE = 3
TAILLE_MAX_BCE = 65536           # le fichier quotidien fait environ 1,5 Ko
ar.LIBELLES.setdefault("adn_empreinte_absente", "ADN : empreinte TRACKYZZ du jour absente")
ar.LIBELLES.setdefault("adn_verification_en_echec", "ADN : vérification en échec")
ar.LIBELLES.setdefault("adn_feuilles_incoherentes", "ADN : empreintes des feuilles ne redonnent pas la racine")


def lire_config(path):
    conf = ar.lire_config(path)
    cp = configparser.ConfigParser()
    cp.read(path, encoding="utf-8-sig")
    c = cp["adn"] if "adn" in cp else {}
    conf["empreintes"] = Path((c.get("empreintes") or "").strip() or conf["source"] / "empreintes")
    conf["temoin"] = (c.get("temoin") or "").strip() or None
    conf["astra"] = (c.get("astra") or "").strip() or None
    conf["adn_debut"] = (c.get("debut") or "").strip() or None
    return conf


def fichier_adn(dest, jour_str):
    return dest / "adn" / f"adn-{jour_str}.json"


def fichier_feuilles(dest, jour_str):
    return dest / "adn" / f"feuilles-{jour_str}.txt.gz"


def fichier_bce(dest, jour_str):
    return dest / "bce" / f"bce-{jour_str}.xml"


def veille_de(jour_str):
    return ar.jour_de(ar.secondes(jour_str + "T00:00:00Z") - 86400)

# ------------------------------------------------------------------ gènes du jour

def indisponible(raison):
    return {"statut": "indisponible", "raison": str(raison)[:160]}


def gene_code():
    """Empreinte du code de l'archiveur et de l'ADN tels qu'ils tournent ce jour-là."""
    ici = Path(__file__).resolve().parent
    return {"statut": "mesure", "version_archiveur": ar.VERSION, "methode_adn": METHODE,
            "archiveur_py_sha256": ar.sha256_octets((ici / "archiveur.py").read_bytes()),
            "adn_py_sha256": ar.sha256_octets((ici / "adn.py").read_bytes())}


def lancer(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True).stdout


def gene_horloge(now_s, lancer=lancer):
    """Écart (serveur moins heure officielle) lu au moment du calcul : chrony, sinon systemd-timesyncd."""
    erreurs = []
    try:
        m = re.search(r"System time\s*:\s*([\d.]+) seconds (fast|slow)", lancer(["chronyc", "tracking"]))
        if m:
            ms = float(m.group(1)) * 1000 * (1 if m.group(2) == "fast" else -1)
            return {"statut": "mesure", "source": "chrony", "ecart_ms": f"{ms:.3f}", "mesure_le": ar.iso(now_s)}
        erreurs.append("chrony : sortie illisible")
    except Exception as e:
        erreurs.append(f"chrony : {type(e).__name__}")
    try:
        m = re.search(r"Offset:\s*([+-]?[\d.]+)\s*(us|µs|ms|s)\b", lancer(["timedatectl", "timesync-status"]))
        if m:
            ms = float(m.group(1)) * {"us": 0.001, "µs": 0.001, "ms": 1, "s": 1000}[m.group(2)]
            return {"statut": "mesure", "source": "timesyncd", "ecart_ms": f"{ms:.3f}", "mesure_le": ar.iso(now_s)}
        erreurs.append("timesyncd : sortie illisible")
    except Exception as e:
        erreurs.append(f"timesyncd : {type(e).__name__}")
    return indisponible(" ; ".join(erreurs))


def http_json(url, essais=3):
    derniere = None
    for k in range(essais):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "adn-scelyans/1"}), timeout=15) as r:
                return json.loads(r.read())
        except Exception as e:
            derniere = e
            time.sleep(k)
    raise derniere


def gene_bloc(jour_str, get=http_json):
    """Dernier bloc Bitcoin avant minuit UTC de fin du jour (mempool.space). Repli : feuille « indisponible »."""
    fin = ar.secondes(jour_str + "T00:00:00Z") + 86400
    try:
        b = get(f"{API_BLOC}/v1/mining/blocks/timestamp/{fin - 1}")
        h = int(b["height"])
        bloc = get(f"{API_BLOC}/block/{b['hash']}")
        for _ in range(12):                                     # horodatages non monotones : on ajuste de proche en proche
            if bloc["timestamp"] >= fin:                        # trop tard : on recule
                bloc = get(f"{API_BLOC}/block/{bloc['previousblockhash']}")
                h -= 1
                continue
            try:                                                # le suivant est-il encore avant minuit ? on avance
                # route JSON : /block-height/ renvoie le hash en texte brut, que http_json (JSON) ne sait pas lire
                suivant = get(f"{API_BLOC}/v1/blocks/{h + 1}")[0]
                if suivant["height"] != h + 1:
                    break                                       # hauteur pas encore minée : on garde celui-ci
            except Exception:
                break                                           # pas de suivant (jour récent) : on garde celui-ci
            if suivant["timestamp"] >= fin:
                break
            bloc, h = suivant, h + 1
        else:
            return indisponible("bloc introuvable autour de minuit")
        return {"statut": "mesure", "source": API_BLOC, "regle": REGLE_BLOC, "hauteur": h, "hash": bloc["id"],
                "horodatage": ar.iso(bloc["timestamp"])}
    except Exception as e:
        return indisponible(f"{type(e).__name__} {str(e)[:100]}")


def gene_temoin(conf, jour_str):
    """Concordance du jour entre Oracle et témoin Cloudflare : lue dans <temoin>/AAAA-MM-JJ.json
    ({"concordance_pct": "99.87"}) quand le dossier est configuré ([adn] temoin) ; sinon « indisponible »."""
    d = conf.get("temoin")
    if not d:
        return indisponible("aucun témoin configuré")
    try:
        v = json.loads((Path(d) / f"{jour_str}.json").read_text(encoding="utf-8"))
        pct = float(v["concordance_pct"])
        if not 0 <= pct <= 100:
            raise ValueError("hors 0..100")
        return {"statut": "mesure", "concordance_pct": f"{pct:.2f}", "temoin": "cloudflare", "reference": "oracle"}
    except Exception as e:
        return indisponible(f"témoin du jour illisible : {type(e).__name__}")


def lire_tete_astra(source, jour_str):
    """Octets de <source>/AAAA-MM-JJ.txt, source = route publique (https://trackyzz.com/astra/tetes) ou dossier ;
    None si la tête n'existe pas (404). Toute autre erreur remonte."""
    if source.startswith(("https://", "http://")):
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{source.rstrip('/')}/{jour_str}.txt",
                                        headers={"User-Agent": "adn-scelyans/1"}), timeout=15) as r:
                return r.read(TAILLE_MAX_TETE_ASTRA + 1)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
    p = Path(source) / f"{jour_str}.txt"
    return p.read_bytes() if p.exists() else None


def gene_astra(conf, jour_str, lire=lire_tete_astra):
    """Tête du jour du registre d'ASTRA-M (l'IA tourne sur le PC, qui publie ses têtes sur trackyzz.com/astra/tetes),
    lue quand la source est configurée ([adn] astra). Seuls l'empreinte de la tête entière et ses champs de chaîne sont
    gardés : la ligne « contenu » (types de blocs) n'est pas recopiée dans le fichier publié, mais tete_sha256 la couvre."""
    d = conf.get("astra")
    if not d:
        return indisponible("aucun dossier ASTRA configuré")
    try:
        b = lire(d, jour_str)
        if b is None:
            return indisponible("aucune tête ASTRA ce jour-là")
        if len(b) > TAILLE_MAX_TETE_ASTRA:
            raise ValueError("trop grande")
        m = re.match(rf"([0-9a-f]{{64}})  adn/{jour_str}\.jsonl\r?\n"      # \r\n : tête écrite sous Windows
                     r"# blocs=(\d+) dernier_index=(\d+) dernier_hash=([0-9a-f]{64})\r?\n", b.decode("utf-8"))
        if not m:
            raise ValueError("format inattendu")
        return {"statut": "mesure", "source": "astra-m", "tete_sha256": ar.sha256_octets(b),
                "fichier": f"adn/{jour_str}.jsonl", "fichier_sha256": m.group(1), "blocs": int(m.group(2)),
                "dernier_index": int(m.group(3)), "dernier_hash": m.group(4)}
    except Exception as e:
        return indisponible(f"tête ASTRA illisible : {type(e).__name__}")


def plages(minutes_s):
    """[t, t+60, t+120, t+600] -> ["HH:MM-HH:MM", "HH:MM"] (minutes consécutives regroupées, heure UTC)."""
    out, debut, prec = [], None, None
    for t in sorted(minutes_s) + [None]:
        if t is not None and prec is not None and t == prec + 60:
            prec = t
            continue
        if debut is not None:
            a, b = ar.iso(debut)[11:16], ar.iso(prec)[11:16]
            out.append(a if a == b else f"{a}-{b}")
        debut = prec = t
    return out


def gene_tours(conf, jour_str, releves=None):
    """Incidents de la collecte du jour, recalculés depuis les relevés scellés (lignes du registre de J, rangées par
    heure d'écriture) : un tour coupé n'écrit rien et ne peut pas se noter lui-même. Sans bloc : minutes de J où rien
    n'a été écrit ; en retard : minutes de cours écrites plus de SEUIL_RETARD_S après leur fin ; oracles perdus :
    créneaux de 5 minutes de J sans lecture d'oracle. Déterministe : la vérification le recalcule."""
    try:
        lignes = releves_du_jour(conf["destination"], jour_str) if releves is None else releves
        j0 = ar.secondes(jour_str + "T00:00:00Z")
        ecrits, retard, lus = set(), {}, set()
        for l in lignes:
            b = json.loads(l)
            t = ar.secondes(b["collecte"])
            ecrits.add(t // 60 * 60)
            f = str(b.get("format", ""))
            if f.startswith("trackyzz-multi-exchanges/") and b.get("close_time"):
                r = t - ar.secondes(b["close_time"])
                if r > SEUIL_RETARD_S:
                    m = ar.secondes(b["open_time"])
                    retard[m] = max(retard.get(m, 0), r)
            elif f.startswith("trackyzz-oracles/") and b.get("open_time"):
                lus.add(ar.secondes(b["open_time"]) // PERIODE_ORACLES_S * PERIODE_ORACLES_S)
        sans = [m for m in range(j0, j0 + 86400, 60) if m not in ecrits]
        perdus = [c for c in range(j0, j0 + 86400, PERIODE_ORACLES_S) if c not in lus]
        return {"statut": "mesure", "source": "releves scelles du jour", "seuil_retard_s": SEUIL_RETARD_S,
                "minutes_sans_bloc": len(sans), "plages_sans_bloc": plages(sans),
                "minutes_en_retard": len(retard), "plages_en_retard": plages(retard),
                "retard_max_s": max(retard.values(), default=0),
                "oracles_perdus": len(perdus), "creneaux_oracles_perdus": [ar.iso(c)[11:16] for c in perdus]}
    except Exception as e:
        return indisponible(f"relevés du jour illisibles : {type(e).__name__}")


def lire_bce(url=URL_BCE, essais=ESSAIS_BCE):
    """Octets bruts de la publication quotidienne de la BCE : quelques essais courts (DELAI_BCE_S chacun)."""
    derniere = None
    for k in range(essais):
        if k:
            time.sleep(2)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "adn-scelyans/1"}),
                                        timeout=DELAI_BCE_S) as r:
                b = r.read(TAILLE_MAX_BCE + 1)
            if len(b) > TAILLE_MAX_BCE:
                raise ValueError("réponse BCE trop grande")
            return b
        except Exception as e:
            derniere = e
    raise derniere


def analyser_bce(b):
    """(date de publication, {devise: taux tel qu'écrit}) d'un fichier quotidien de la BCE ; ValueError sinon."""
    if len(b) > TAILLE_MAX_BCE or b"<!DOCTYPE" in b.upper() or b"<!ENTITY" in b.upper():
        raise ValueError("fichier BCE refusé (taille ou DOCTYPE)")
    try:
        jours = [e for e in ET.fromstring(b).iter() if e.tag.endswith("Cube") and "time" in e.attrib]
    except ET.ParseError as e:
        raise ValueError(f"XML BCE illisible : {e}")
    if len(jours) != 1 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", jours[0].get("time")):
        raise ValueError("date de publication BCE introuvable")
    taux = {c.get("currency"): c.get("rate") for c in jours[0] if c.get("currency")}
    if not re.fullmatch(r"\d+(\.\d+)?", taux.get("USD") or ""):
        raise ValueError("taux EUR/USD introuvable")
    return jours[0].get("time"), taux


def week_end(jour_str):
    return time.gmtime(ar.secondes(jour_str + "T00:00:00Z")).tm_wday >= 5


def conserver_bce(dest, b, journal, au_plus_tard):
    """Enregistre une fois le fichier reçu, tel quel, sous la date qu'il porte (jamais une date postérieure à
    au_plus_tard). Renvoie cette date."""
    d, _ = analyser_bce(b)
    if d > au_plus_tard:
        raise ValueError(f"publication BCE datée du {d}, après le {au_plus_tard}")
    if not fichier_bce(dest, d).exists():
        ar.creer_une_fois(fichier_bce(dest, d), b, journal)
    return d


def recuperer_bce(conf, now_s, journal, lire=None):
    """Passage horaire : les jours ouvrés après HEURE_BCE_UTC_S, tant que le fichier du jour manque, lit la
    publication quotidienne et la conserve. Renvoie la date lue, l'erreur, ou None (rien à faire). Une panne
    n'arrête jamais le passage : retenté au passage suivant, puis une dernière fois au scellement du jour."""
    j = ar.jour_de(now_s)
    if week_end(j) or now_s % 86400 < HEURE_BCE_UTC_S or fichier_bce(conf["destination"], j).exists():
        return None
    try:
        return conserver_bce(conf["destination"], (lire or lire_bce)(), journal, j)
    except Exception as e:
        return f"{type(e).__name__} {str(e)[:100]}"


def gene_bce(conf, jour_str, now_s, lire=None):
    """Taux de référence BCE publié le jour J, depuis le fichier conservé ; s'il manque, une dernière lecture.
    Week-end, ou fichier quotidien encore daté d'avant J (jour sans publication) : « sans_publication », sans taux.
    Jamais le taux de la veille, jamais d'estimation."""
    dest = conf["destination"]
    try:
        p = fichier_bce(dest, jour_str)
        if not p.exists():
            if week_end(jour_str):
                return {"statut": "sans_publication", "version": VERSION_BCE, "raison": "week-end : la BCE ne publie pas"}
            try:
                b = (lire or lire_bce)()
            except Exception as e:
                return indisponible(f"échec réseau BCE : {type(e).__name__}")
            d = conserver_bce(dest, b, ar.Journal(dest, conf.get("ntfy_url"), now_s), jour_str)
            if d < jour_str:
                return {"statut": "sans_publication", "version": VERSION_BCE,
                        "raison": f"aucune publication BCE datée de ce jour (dernière : {d})"}
        b = p.read_bytes()
        d, taux = analyser_bce(b)
        if d != jour_str:
            raise ValueError("date différente du nom du fichier")
        return {"statut": "mesure", "version": VERSION_BCE, "source": URL_BCE, "date_publication": d,
                "fichier": f"bce/{p.name}", "fichier_sha256": ar.sha256_octets(b), "eur_usd": taux["USD"],
                "conserve_le": ar.iso(p.stat().st_mtime)}
    except Exception as e:
        return indisponible(f"publication BCE illisible : {type(e).__name__} {str(e)[:100]}")


def probleme_bce(dest, g):
    """None si le fichier BCE conservé redonne le gène bce scellé (empreinte, date, taux) ; sinon le problème."""
    p = fichier_bce(dest, g.get("date_publication", ""))
    if not p.exists():
        return "fichier BCE conservé introuvable"
    b = p.read_bytes()
    if ar.sha256_octets(b) != g.get("fichier_sha256"):
        return "fichier BCE modifié (empreinte différente du gène bce)"
    try:
        d, taux = analyser_bce(b)
    except ValueError:
        return "fichier BCE illisible"
    if (d, taux["USD"]) != (g.get("date_publication"), g.get("eur_usd")):
        return "fichier BCE différent du gène bce (date ou taux)"
    return None


def mesurer_genes(conf, jour_str, now_s):
    return {"code": gene_code(), "horloge": gene_horloge(now_s), "bloc": gene_bloc(jour_str),
            "temoin": gene_temoin(conf, jour_str), "astra": gene_astra(conf, jour_str), "tours": gene_tours(conf, jour_str),
            "bce": gene_bce(conf, jour_str, now_s)}


def noms_genes(genes):
    """Gènes présents, dans l'ordre fixe : un ADN scellé avant un nouveau gène se relit sans lui."""
    return [n for n in NOMS_GENES if n in genes]


def feuilles_genes(genes):
    return [ar.feuille(P_GENE + n.encode() + b"\n" + ar.json_canonique(genes[n])) for n in noms_genes(genes)]


# ------------------------------------------------------------------ feuilles

def releves_du_jour(dest, jour_str):
    """Lignes du registre du jour (octets exacts), depuis les 24 fichiers horaires fermés de l'archive."""
    out = []
    debut = ar.secondes(jour_str + "T00:00:00Z")
    for h in range(debut, debut + 86400, 3600):
        m = ar.lire_manifeste(dest, h)
        with gzip.open(ar.dossier_heure(dest, h) / m["registre"]["fichier"], "rb") as f:
            out.extend(l for l in f.read().splitlines(keepends=True))
    return out


def concerne(e, constate):
    """Jour touché par un incident (champ jour, heure ou racine), sinon le jour où il a été constaté."""
    for cle in ("jour", "heure", "racine"):
        v = str(e.get(cle) or "")
        for debut in (0, 4):                                    # « 2026-10-09... » ou « adn-2026-10-09.json »
            if len(v) >= debut + 10 and v[debut + 4] == "-" and v[debut + 7] == "-" and v[debut:debut + 4].isdigit():
                return v[debut:debut + 10]
    return constate


def incidents_du_jour(dest, jour_str):
    """[(jour concerné, ligne exacte)] des incidents et trous CONSTATÉS le jour J, dans l'ordre des journaux. La ligne
    archivée n'est jamais réécrite : le jour concerné est ajouté dans la feuille de l'ADN, devant la ligne."""
    out = []
    for nom, cle in (("incidents.jsonl", "detecte_le"), ("trous.jsonl", "note_le")):
        p = dest / nom
        if not p.exists():
            continue
        for l in p.read_bytes().splitlines(keepends=True):
            try:
                e = json.loads(l)
            except ValueError:
                continue
            if str(e.get(cle, "")).startswith(jour_str):
                out.append((concerne(e, jour_str), l))
    return out


def pret(conf, jour_str):
    return (conf["destination"] / "racines" / f"{jour_str}.txt").exists() and (conf["empreintes"] / f"{jour_str}.txt").exists()


def construire_feuilles(conf, jour_str, racine_veille, genes=None):
    """(feuilles, détail) du jour ; None si l'archive du jour ou l'empreinte TRACKYZZ n'existe pas encore."""
    dest = conf["destination"]
    p_emp = conf["empreintes"] / f"{jour_str}.txt"
    if not pret(conf, jour_str):
        return None
    empreinte = p_emp.read_bytes()
    releves, incidents = releves_du_jour(dest, jour_str), incidents_du_jour(dest, jour_str)
    feuilles = [ar.feuille(P_VEILLE + (racine_veille or "aucune").encode() + b"\n"), ar.feuille(P_EMPREINTE + empreinte)]
    feuilles += [ar.feuille(P_RELEVE + l) for l in releves]
    feuilles += [ar.feuille(P_INCIDENT + b"concerne " + c.encode() + b"\n" + l) for c, l in incidents]
    par_jour = {}
    for c, _ in incidents:
        par_jour[c] = par_jour.get(c, 0) + 1
    if genes:
        feuilles += feuilles_genes(genes)
    detail = {"empreinte_sha256": ar.sha256_octets(empreinte), "releves": len(releves), "incidents": len(incidents),
              "incidents_concernent": par_jour, "releves_lignes": releves}
    return feuilles, detail


def contenu_adn(conf, jour_str, racine_veille, feuilles, detail, genes=None):
    bilan = json.loads((conf["destination"] / "jours" / f"{jour_str}.json").read_text(encoding="utf-8"))
    adn = {
        "format": FORMAT_ADN, "methode": METHODE, "algorithme": ALGORITHME, "jour": jour_str,
        "racine": ar.racine_merkle(feuilles).hex(), "racine_veille": racine_veille,
        "jour_veille": None if racine_veille is None else veille_de(jour_str),
        "feuilles": {"total": len(feuilles), "veille": 1, "empreinte": 1, "releves": detail["releves"],
                     "incidents": detail["incidents"]},
        "incidents_concernent": detail["incidents_concernent"],
        "ordre_feuilles": "veille, empreinte, releves (heure par heure), incidents constates le jour J "
                          "(feuille : « concerne AAAA-MM-JJ » puis la ligne archivee, inchangee)",
        "empreinte_trackyzz": {"fichier": f"empreintes/{jour_str}.txt", "sha256": detail["empreinte_sha256"]},
        "racine_archive": bilan["merkle"]["racine"],
    }
    if genes:
        adn["genes"] = genes
        adn["feuilles"]["genes"] = len(noms_genes(genes))
        adn["ordre_feuilles"] += (f", genes ({', '.join(noms_genes(genes))} : « adn/1 gene <nom> » "
                                  "puis la valeur JSON canonique)")
    return ar.json_canonique(adn)


# ------------------------------------------------------------------ passage

def premier_jour(conf):
    if conf.get("adn_debut"):
        return conf["adn_debut"]
    jours = sorted(p.stem for p in (conf["destination"] / "racines").glob("????-??-??.txt"))
    return jours[0] if jours else None


def executer(conf, now_s=None, horo=None, genes=None):
    """Construit dans l'ordre les jours fermés qui n'ont pas encore d'ADN, puis ancre. Relançable sans effet."""
    now_s = int(now_s or time.time())
    dest = conf["destination"]
    horo = horo or ar.Horodateurs(conf.get("ots"), None, conf.get("openssl") or "openssl")
    journal = ar.Journal(dest, conf.get("ntfy_url"), now_s)
    bce = recuperer_bce(conf, now_s, journal)
    debut = premier_jour(conf)
    construits = []
    if debut:
        j_s = ar.secondes(debut + "T00:00:00Z")
        while j_s + 86400 <= now_s:
            j = ar.jour_de(j_s)
            p = fichier_adn(dest, j)
            if not p.exists():
                veille = None
                if j != debut:
                    pv = fichier_adn(dest, veille_de(j))
                    if not pv.exists():
                        break                                   # la chaîne ne saute jamais un jour
                    veille = json.loads(pv.read_text(encoding="utf-8"))["racine"]
                g = (genes or mesurer_genes)(conf, j, now_s) if pret(conf, j) else None   # pas de mesure avant que le jour soit prêt
                if (g and conf.get("astra") and g.get("astra", {}).get("statut") != "mesure"
                        and now_s < j_s + 86400 + ATTENTE_ASTRA_S):
                    break                                       # tête ASTRA pas encore publiée par le PC : passage suivant
                r = construire_feuilles(conf, j, veille, g)
                if r is None:
                    if (dest / "racines" / f"{j}.txt").exists() and now_s > j_s + 86400 + ATTENTE_EMPREINTE_S:
                        journal.incident_une_fois("adn_empreinte_absente", jour=j,
                                                  attendue=str(conf["empreintes"] / f"{j}.txt"))
                    break
                ar.creer_une_fois(p, contenu_adn(conf, j, veille, *r, g), journal)
                construits.append(j)
            j_s += 86400
    return {"adn_construits": construits, "bce": bce, "feuilles_publiees": ecrire_feuilles(conf, journal),
            "ancrage": ancrer(dest, now_s, horo, journal), "incidents": [i["type"] for i in journal.incidents]}


def texte_feuilles(conf, a):
    """Empreintes des feuilles de l'ADN `a`, dans l'ordre (en-tête : format, jour, racine, total). None si l'archive du
    jour manque ou si elles ne redonnent pas exactement la racine scellée : jamais de fichier faux."""
    r = construire_feuilles(conf, a["jour"], a["racine_veille"], a.get("genes"))
    if r is None:
        return None
    feuilles, detail = r
    if ar.racine_merkle(feuilles).hex() != a["racine"] or len(feuilles) != a["feuilles"]["total"]:
        return None
    types = ["veille", "empreinte"] + [f"releve {json.loads(l)['collecte'][11:13]}" for l in detail["releves_lignes"]]
    types += ["incident"] * detail["incidents"] + [f"gene {n}" for n in noms_genes(a.get("genes") or {})]
    lignes = [FORMAT_FEUILLES, f"jour {a['jour']}", f"racine {a['racine']}", f"feuilles {len(feuilles)}"]
    lignes += [f"{k} {t} {f.hex()}" for k, (t, f) in enumerate(zip(types, feuilles))]
    return ("\n".join(lignes) + "\n").encode("ascii")


def ecrire_feuilles(conf, journal):
    """Pour chaque ADN scellé (anciens compris) : crée une fois adn/feuilles-J.txt.gz (gzip reproductible, mtime 0)."""
    dest, ecrits = conf["destination"], []
    for p in sorted((dest / "adn").glob("adn-????-??-??.json")):
        a = json.loads(p.read_text(encoding="utf-8"))
        f = fichier_feuilles(dest, a["jour"])
        if f.exists():
            continue
        t = texte_feuilles(conf, a)
        if t is None:
            if (dest / "racines" / f"{a['jour']}.txt").exists():
                journal.incident_une_fois("adn_feuilles_incoherentes", jour=a["jour"])
            continue
        ar.creer_une_fois(f, gzip.compress(t, mtime=0), journal)
        ecrits.append(a["jour"])
    return ecrits


def verifier_feuilles(texte, a, empreinte=None):
    """Vérification par un tiers, avec les seuls fichiers publiés : recalcule la racine depuis les empreintes des
    feuilles, et recalcule lui-même les feuilles qu'il peut (veille, gènes, empreinte TRACKYZZ si fournie).
    Renvoie la liste des problèmes (vide : la racine du jour est retrouvée)."""
    pb = []
    lignes = texte.decode("ascii").splitlines()
    tete = [FORMAT_FEUILLES, f"jour {a['jour']}", f"racine {a['racine']}", f"feuilles {a['feuilles']['total']}"]
    if lignes[:4] != tete:
        return ["en-tête différent de l'ADN (format, jour, racine ou nombre de feuilles)"]
    feuilles, types = [], []
    for k, l in enumerate(lignes[4:]):
        m = LIGNE_FEUILLE.fullmatch(l)
        if not m or int(m.group(1)) != k:
            return [f"ligne {k + 5} illisible ou hors d'ordre"]
        types.append(m.group(2))
        feuilles.append(bytes.fromhex(m.group(3)))
    attendu = (["veille", "empreinte"] + ["releve"] * a["feuilles"]["releves"] + ["incident"] * a["feuilles"]["incidents"]
               + [f"gene {n}" for n in noms_genes(a.get("genes") or {})])
    if [t[:6] if t.startswith("releve") else t for t in types] != attendu:
        pb.append("types de feuilles différents des comptes de l'ADN")
    if feuilles and feuilles[0] != ar.feuille(P_VEILLE + (a["racine_veille"] or "aucune").encode() + b"\n"):
        pb.append("feuille veille différente de racine_veille")
    if empreinte is not None and len(feuilles) > 1 and feuilles[1] != ar.feuille(P_EMPREINTE + empreinte):
        pb.append("feuille empreinte différente du fichier d'empreinte TRACKYZZ fourni")
    genes = a.get("genes") or {}
    for t, f in zip(types, feuilles):
        if t.startswith("gene ") and t[5:] in genes and f != feuilles_genes({t[5:]: genes[t[5:]]})[0]:
            pb.append(f"feuille {t} différente de la valeur publiée dans l'ADN")
    if not feuilles or ar.racine_merkle(feuilles).hex() != a["racine"]:
        pb.append("racine recalculée différente de la racine de l'ADN")
    return pb


def ancrer(dest, now_s, horo, journal):
    """OpenTimestamps : .ots une fois, puis .bitcoin.ots dès que Bitcoin a confirmé. Une panne réseau ne fait jamais
    échouer le passage : retenté au passage suivant. Le complément Bitcoin est tenté à CHAQUE passage (le minuteur de
    l'ADN ne passe qu'une fois par heure, à la 50e minute) ; il ne peut que créer un nouveau .bitcoin.ots : le .json et
    le .ots existants ne sont jamais ouverts en écriture (le client ots travaille sur une copie temporaire)."""
    etat = {"adn": 0, "ots": 0, "bitcoin": 0, "erreurs": []}
    for p in sorted((dest / "adn").glob("adn-????-??-??.json")):
        etat["adn"] += 1
        f_ots, f_btc = p.with_name(p.name + ".ots"), p.with_name(p.name + ".bitcoin.ots")
        try:
            if not f_ots.exists():
                b = horo.ots_stamp(p)
                if b:
                    ar.creer_une_fois(f_ots, b, journal)
            if f_ots.exists() and not f_btc.exists():
                b = horo.ots_upgrade(p, f_ots.read_bytes())
                if b:
                    ar.creer_une_fois(f_btc, b, journal)
        except Exception as e:
            etat["erreurs"].append(f"{p.name} ots : {type(e).__name__} {str(e)[:120]}")
        etat["ots"] += f_ots.exists()
        etat["bitcoin"] += f_btc.exists()
        depuis = now_s - int(p.stat().st_mtime)
        if horo.ots and not f_ots.exists() and depuis > ar.ALERTE_ANCRAGE_S:
            journal.incident_une_fois("ancrage_ots_en_echec", racine=p.name)
        if horo.ots and f_ots.exists() and not f_btc.exists() and now_s - int(f_ots.stat().st_mtime) > ar.ALERTE_BITCOIN_S:
            journal.incident_une_fois("ancrage_bitcoin_en_attente", racine=p.name)
    return etat


# ------------------------------------------------------------------ vérification et preuves

def verifier(conf):
    """Recalcule chaque ADN depuis l'archive et l'empreinte, et contrôle le chaînage. Ne modifie rien."""
    dest = conf["destination"]
    problemes, n, precedent = [], 0, None
    for p in sorted((dest / "adn").glob("adn-????-??-??.json")):
        n += 1
        a = json.loads(p.read_text(encoding="utf-8"))
        j = a["jour"]
        if precedent is not None and (a["jour_veille"] != precedent["jour"] or a["racine_veille"] != precedent["racine"]):
            problemes.append(f"{p.name} : chaînage rompu avec {precedent['jour']}")
        g = a.get("genes")                                      # relus tels que scellés : un gène vivant ne se recalcule pas
        r = construire_feuilles(conf, j, a["racine_veille"], g)
        if r is None:
            problemes.append(f"{p.name} : archive ou empreinte du jour introuvable")
        elif p.read_bytes() != contenu_adn(conf, j, a["racine_veille"], *r, g):
            problemes.append(f"{p.name} : recalcul différent (racine ou comptes)")
        elif (g and g.get("tours", {}).get("statut") == "mesure"         # « indisponible » n'affirme rien
              and g["tours"] != gene_tours(conf, j, r[1]["releves_lignes"])):
            problemes.append(f"{p.name} : gène tours différent du recalcul depuis les relevés")
        elif g and g.get("bce", {}).get("statut") == "mesure" and probleme_bce(dest, g["bce"]):
            problemes.append(f"{p.name} : {probleme_bce(dest, g['bce'])}")
        elif fichier_feuilles(dest, j).exists() and (gzip.decompress(fichier_feuilles(dest, j).read_bytes())
                                                      != texte_feuilles(conf, a)):
            problemes.append(f"{fichier_feuilles(dest, j).name} : différent des feuilles recalculées")
        precedent = a
    return n, problemes


def preuve(conf, jour_str, index_bloc):
    """Preuve d'inclusion d'un relevé (bloc du registre d'index donné) dans l'ADN du jour. Contient le relevé : à ne
    jamais publier. Ne modifie rien."""
    p = fichier_adn(conf["destination"], jour_str)
    if not p.exists():
        return None
    a = json.loads(p.read_text(encoding="utf-8"))
    feuilles, detail = construire_feuilles(conf, jour_str, a["racine_veille"], a.get("genes"))
    for k, l in enumerate(detail["releves_lignes"]):
        if json.loads(l).get("index") == index_bloc:
            m = 2 + k
            return {"format": FORMAT_PREUVE, "methode": METHODE, "algorithme": ALGORITHME, "jour": jour_str,
                    "adn": p.name, "releve": l.decode("utf-8"), "position": m, "taille": len(feuilles),
                    "chemin": [x.hex() for x in ar.chemin_merkle(m, feuilles)], "racine": a["racine"],
                    "avertissement": "contient un relevé de prix : ne pas publier"}
    return None


def verifier_preuve(pr, adn):
    """Vérification autonome : ne demande que la preuve et le fichier ADN publié (lui-même ancré dans Bitcoin)."""
    if pr.get("format") != FORMAT_PREUVE or adn.get("jour") != pr.get("jour") or adn.get("racine") != pr.get("racine"):
        return False
    if pr.get("taille") != adn.get("feuilles", {}).get("total"):
        return False
    if not 2 <= pr["position"] < 2 + adn["feuilles"]["releves"]:
        return False                                            # un relevé n'est jamais en position veille/empreinte/incident
    f = ar.feuille(P_RELEVE + pr["releve"].encode("utf-8"))
    return ar.verifier_chemin(pr["position"], pr["taille"], f, [bytes.fromhex(x) for x in pr["chemin"]],
                              bytes.fromhex(pr["racine"]))


def main(argv=None):
    ap = argparse.ArgumentParser(description="ADN Scelyans v1 (lecture seule de TRACKYZZ et de l'archive)")
    ap.add_argument("commande", choices=["executer", "verifier", "preuve", "verifier-preuve", "verifier-feuilles"])
    ap.add_argument("--config")
    ap.add_argument("--jour")
    ap.add_argument("--index", type=int)
    ap.add_argument("--sortie")
    ap.add_argument("--preuve")
    ap.add_argument("--adn")
    ap.add_argument("--feuilles")
    ap.add_argument("--empreinte")
    a = ap.parse_args(argv)
    if a.commande == "verifier-feuilles":
        if not (a.feuilles and a.adn):
            ap.error("--feuilles et --adn sont obligatoires")
        b = Path(a.feuilles).read_bytes()
        pb = verifier_feuilles(gzip.decompress(b) if b[:2] == b"\x1f\x8b" else b,
                               json.loads(Path(a.adn).read_text(encoding="utf-8")),
                               Path(a.empreinte).read_bytes() if a.empreinte else None)
        for x in pb:
            print(x)
        print("racine retrouvée depuis les feuilles" if not pb else "FEUILLES INVALIDES")
        return 0 if not pb else 1
    if a.commande == "verifier-preuve":
        if not (a.preuve and a.adn):
            ap.error("--preuve et --adn sont obligatoires")
        ok = verifier_preuve(json.loads(Path(a.preuve).read_text(encoding="utf-8")),
                             json.loads(Path(a.adn).read_text(encoding="utf-8")))
        print("preuve valide" if ok else "PREUVE INVALIDE")
        return 0 if ok else 1
    if not a.config:
        ap.error("--config est obligatoire")
    conf = lire_config(a.config)
    if a.commande == "executer":
        print(json.dumps(executer(conf), ensure_ascii=False))
        return 0
    if a.commande == "preuve":
        if not a.jour or a.index is None:
            ap.error("--jour et --index sont obligatoires")
        pr = preuve(conf, a.jour, a.index)
        if pr is None:
            print("aucun ADN pour ce jour, ou relevé introuvable")
            return 1
        texte = json.dumps(pr, ensure_ascii=False, indent=1)
        if a.sortie:
            with open(a.sortie, "x", encoding="utf-8") as f:    # jamais d'écrasement
                f.write(texte + "\n")
            print(f"preuve écrite dans {a.sortie} (contient un relevé : ne pas publier)")
        else:
            print(texte)
        return 0
    n, problemes = verifier(conf)
    for p in problemes:
        print(p)
    print(f"{n} ADN relu(s) : " + ("intègre(s)" if not problemes else f"{len(problemes)} problème(s)"))
    return 0 if not problemes else 1


if __name__ == "__main__":
    sys.exit(main())
