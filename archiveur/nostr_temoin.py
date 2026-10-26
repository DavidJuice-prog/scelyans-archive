"""Témoin public Nostr : publie « jour » et « racine_du_jour » de chaque ADN scellé sur des relais publics.

S'ajoute à l'archiveur sans rien changer : lit <destination>/adn/adn-AAAA-MM-JJ.json (le seul fichier de l'ADN destiné à être
publié) ; écrit seulement son journal. Bibliothèque standard uniquement : signature Schnorr BIP-340 (secp256k1) et client
WebSocket minimal. L'événement ne contient que {"jour", "racine_du_jour"} : aucun prix, aucune autre donnée.

Règles :
  - un jour n'est publié qu'à partir de la date « debut » de la configuration (absente : rien n'est publié) ;
  - un événement par jour, jamais deux : un nouvel essai renvoie le MÊME événement (même identifiant) aux relais qui ne l'ont
    pas encore accepté ; la date created_at est celle du premier essai ;
  - un jour est publié quand au moins « min_ok » relais ont répondu OK ; le journal (ajout seul) garde l'événement entier et la
    réponse de chaque relais ;
  - recul progressif : après un essai infructueux pour un jour, le suivant attend 1 h, puis 2 h, 4 h, 8 h… (plafond 24 h), pour
    ne pas harceler des relais qui refusent ; l'alerte « scellé depuis plus de 6 h » reste émise à chaque passage ;
  - la racine d'un jour déjà publié ne doit jamais changer : sinon erreur, rien n'est renvoyé ;
  - la date created_at est déclarée par le signataire : elle ne remplace pas l'ancrage Bitcoin de l'ADN.

    python3 nostr_temoin.py cle-generer --sortie /etc/nostr-temoin/cle.hex     (affiche la clé PUBLIQUE seulement)
    python3 nostr_temoin.py publier  --config /etc/nostr-temoin/nostr.conf [--a-blanc]
    python3 nostr_temoin.py verifier --config /etc/nostr-temoin/nostr.conf
"""
import argparse, base64, configparser, hashlib, json, os, re, socket, ssl, struct, sys, time, urllib.parse
from datetime import datetime, timezone
from pathlib import Path

KIND_DEFAUT = 1778            # type ordinaire (1000-9999), non remplaçable ; à confirmer avant la première publication
MIN_OK_DEFAUT = 2
DELAI_DEFAUT_S = 15
RETARD_ALERTE_S = 6 * 3600    # un ADN scellé depuis plus de 6 h et toujours pas publié : exit 1 (alerte ntfy du service)
RECUL_BASE_S = 3600           # après un échec : attendre 1 h, puis 2 h, 4 h, 8 h… (doublement) avant de réessayer le même jour
RECUL_MAX_S = 24 * 3600       # plafond : un jour en échec est réessayé au plus une fois toutes les 24 h
MAX_REPRISES = 8              # jour déjà publié (quorum atteint) : au plus 8 reprises infructueuses auprès des relais manquants
MAX_MESSAGE = 1 << 20
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
RE_JOUR = re.compile(r"\d{4}-\d{2}-\d{2}")
RE_HEX64 = re.compile(r"[0-9a-f]{64}")

# ------------------------------------------------------------------ BIP-340 (algorithme de référence, secp256k1)
# Non résistant aux attaques par canal auxiliaire : acceptable pour une signature par jour sur un serveur dédié.
FP = 2**256 - 2**32 - 977
ORDRE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def entier(b):
    return int.from_bytes(b, "big")


def octets(n):
    return n.to_bytes(32, "big")


def addition(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], FP - 2, FP) % FP
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], FP - 2, FP) % FP
    x3 = (lam * lam - p1[0] - p2[0]) % FP
    return x3, (lam * (p1[0] - x3) - p1[1]) % FP


def multiplication(pt, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = addition(r, pt)
        pt = addition(pt, pt)
    return r


def hachage_etiquete(etiquette, msg):
    h = hashlib.sha256(etiquette.encode()).digest()
    return hashlib.sha256(h + h + msg).digest()


def lift_x(x):
    if x >= FP:
        return None
    y2 = (pow(x, 3, FP) + 7) % FP
    y = pow(y2, (FP + 1) // 4, FP)
    if pow(y, 2, FP) != y2:
        return None
    return x, (y if y % 2 == 0 else FP - y)


def pubkey_gen(cle):
    d0 = entier(cle)
    if len(cle) != 32 or not 1 <= d0 <= ORDRE - 1:
        raise ValueError("clé secrète invalide")
    return octets(multiplication(G, d0)[0])


def schnorr_sign(msg, cle, aux):
    if len(msg) != 32 or len(aux) != 32:
        raise ValueError("message et aléa doivent faire 32 octets")
    d0 = entier(cle)
    if len(cle) != 32 or not 1 <= d0 <= ORDRE - 1:
        raise ValueError("clé secrète invalide")
    pt = multiplication(G, d0)
    d = d0 if pt[1] % 2 == 0 else ORDRE - d0
    t = bytes(a ^ b for a, b in zip(octets(d), hachage_etiquete("BIP0340/aux", aux)))
    k0 = entier(hachage_etiquete("BIP0340/nonce", t + octets(pt[0]) + msg)) % ORDRE
    if k0 == 0:
        raise ValueError("nonce nul")
    r = multiplication(G, k0)
    k = k0 if r[1] % 2 == 0 else ORDRE - k0
    e = entier(hachage_etiquete("BIP0340/challenge", octets(r[0]) + octets(pt[0]) + msg)) % ORDRE
    sig = octets(r[0]) + octets((k + e * d) % ORDRE)
    if not schnorr_verify(msg, octets(pt[0]), sig):
        raise ValueError("signature produite invalide")
    return sig


def schnorr_verify(msg, pub, sig):
    if len(msg) != 32 or len(pub) != 32 or len(sig) != 64:
        return False
    pt = lift_x(entier(pub))
    r, s = entier(sig[:32]), entier(sig[32:])
    if pt is None or r >= FP or s >= ORDRE:
        return False
    e = entier(hachage_etiquete("BIP0340/challenge", sig[:32] + pub + msg)) % ORDRE
    res = addition(multiplication(G, s), multiplication(pt, ORDRE - e))
    return res is not None and res[1] % 2 == 0 and res[0] == r


# ------------------------------------------------------------------ événement Nostr (NIP-01)

def serialiser(pub_hex, created_at, kind, tags, contenu):
    return json.dumps([0, pub_hex, created_at, kind, tags, contenu], separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def evenement(cle, jour, racine, created_at, kind, aux=None):
    """Événement signé ; son contenu est exactement {"jour", "racine_du_jour"}, rien d'autre."""
    if not RE_JOUR.fullmatch(jour) or not RE_HEX64.fullmatch(racine):
        raise ValueError("jour ou racine mal formés")
    pub = pubkey_gen(cle).hex()
    contenu = json.dumps({"jour": jour, "racine_du_jour": racine}, separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(serialiser(pub, created_at, kind, [], contenu)).digest()
    sig = schnorr_sign(eid, cle, aux if aux is not None else os.urandom(32))
    return {"id": eid.hex(), "pubkey": pub, "created_at": created_at, "kind": kind, "tags": [], "content": contenu,
            "sig": sig.hex()}


def verifier_evenement(ev):
    """Identifiant recalculé et signature valides ?"""
    try:
        eid = hashlib.sha256(serialiser(ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"])).digest()
        return ev["id"] == eid.hex() and schnorr_verify(eid, bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"]))
    except (KeyError, TypeError, ValueError):
        return False


# ------------------------------------------------------------------ WebSocket minimal (RFC 6455, texte uniquement)

def masquer(donnees, masque):
    return bytes(b ^ masque[i % 4] for i, b in enumerate(donnees))


def trame(opcode, charge, masque=None):
    """Trame complète (FIN=1). Le client doit masquer, le serveur non."""
    n = len(charge)
    bit = 0x80 if masque else 0
    if n < 126:
        t = bytes([0x80 | opcode, bit | n])
    elif n < 65536:
        t = bytes([0x80 | opcode, bit | 126]) + struct.pack(">H", n)
    else:
        t = bytes([0x80 | opcode, bit | 127]) + struct.pack(">Q", n)
    return t + (masque + masquer(charge, masque) if masque else charge)


def lire_exact(f, n):
    donnees = f.read(n)
    if len(donnees) < n:
        raise ConnectionError("connexion fermée")
    return donnees


def lire_trame(f, max_octets=MAX_MESSAGE):
    """(fin, opcode, charge) d'une trame lue sur un fichier binaire."""
    h = lire_exact(f, 2)
    fin, opcode, masque_actif, n = bool(h[0] & 0x80), h[0] & 0x0F, bool(h[1] & 0x80), h[1] & 0x7F
    if n == 126:
        n = struct.unpack(">H", lire_exact(f, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", lire_exact(f, 8))[0]
    if n > max_octets:
        raise ValueError("trame trop grande")
    masque = lire_exact(f, 4) if masque_actif else None
    charge = lire_exact(f, n)
    return fin, opcode, (masquer(charge, masque) if masque else charge)


class Ws:
    def __init__(self, url, delai=DELAI_DEFAUT_S):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("ws", "wss") or not u.hostname:
            raise ValueError("URL de relais invalide")
        brut = socket.create_connection((u.hostname, u.port or (443 if u.scheme == "wss" else 80)), timeout=delai)
        self.sock = brut
        try:
            if u.scheme == "wss":
                self.sock = ssl.create_default_context().wrap_socket(brut, server_hostname=u.hostname)
            self.sock.settimeout(delai)
            self.f = self.sock.makefile("rb")
            cle = base64.b64encode(os.urandom(16)).decode()
            chemin = (u.path or "/") + ("?" + u.query if u.query else "")
            self.sock.sendall((f"GET {chemin} HTTP/1.1\r\nHost: {u.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                               f"Sec-WebSocket-Key: {cle}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: archiveur-nostr/1\r\n\r\n").encode())
            statut = self.f.readline(8192).decode("latin-1")
            entetes = {}
            for _ in range(100):
                ligne = self.f.readline(8192).decode("latin-1")
                if ligne in ("\r\n", "\n", ""):
                    break
                nom, _, valeur = ligne.partition(":")
                entetes[nom.strip().lower()] = valeur.strip()
            attendu = base64.b64encode(hashlib.sha1((cle + GUID).encode()).digest()).decode()
            if " 101 " not in statut + " " or entetes.get("sec-websocket-accept") != attendu:
                raise ConnectionError("poignée de main WebSocket refusée : " + statut.strip()[:80])
        except BaseException:
            self.sock.close()                  # jamais de connexion laissée ouverte si la poignée de main échoue
            raise

    def envoyer(self, texte):
        self.sock.sendall(trame(0x1, texte.encode("utf-8"), os.urandom(4)))

    def recevoir(self):
        """Prochain message texte ; None si le relais ferme. Les ping reçoivent un pong."""
        morceaux, total = [], 0
        while True:
            fin, opcode, charge = lire_trame(self.f)
            if opcode == 0x9:
                self.sock.sendall(trame(0xA, charge, os.urandom(4)))
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x8:
                return None
            total += len(charge)
            if total > MAX_MESSAGE:
                raise ValueError("message trop grand")
            morceaux.append(charge)
            if fin:
                return b"".join(morceaux).decode("utf-8")

    def fermer(self):
        try:
            self.sock.sendall(trame(0x8, b"", os.urandom(4)))
        except OSError:
            pass
        finally:
            self.sock.close()


def publier_sur(url, ev, delai=DELAI_DEFAUT_S, ws=Ws):
    """(ok, message). ok seulement si le relais répond ["OK", <id>, true, ...] (« duplicate » compte comme accepté)."""
    try:
        c = ws(url, delai)
        try:
            c.envoyer(json.dumps(["EVENT", ev], separators=(",", ":"), ensure_ascii=False))
            fin = time.monotonic() + delai
            while time.monotonic() < fin:
                m = c.recevoir()
                if m is None:
                    return False, "connexion fermée par le relais"
                try:
                    rep = json.loads(m)
                except ValueError:
                    continue
                if isinstance(rep, list) and len(rep) >= 3 and rep[0] == "OK" and rep[1] == ev["id"]:
                    return bool(rep[2]), str(rep[3] if len(rep) > 3 else "")[:160]
            return False, "pas de réponse OK dans le délai"
        finally:
            c.fermer()
    except Exception as e:
        return False, f"{type(e).__name__} {str(e)[:100]}"


def lire_evenements(url, filtre, delai=DELAI_DEFAUT_S, ws=Ws):
    """Événements d'un relais pour un filtre (REQ jusqu'à EOSE). Lève une exception si le relais est injoignable."""
    c = ws(url, delai)
    try:
        c.envoyer(json.dumps(["REQ", "temoin", filtre], separators=(",", ":")))
        evs, fin = [], time.monotonic() + delai
        while time.monotonic() < fin:
            m = c.recevoir()
            if m is None:
                break
            try:
                rep = json.loads(m)
            except ValueError:
                continue
            if isinstance(rep, list) and rep and rep[0] == "EOSE":
                break
            if isinstance(rep, list) and len(rep) >= 3 and rep[0] == "EVENT" and rep[1] == "temoin" and isinstance(rep[2], dict):
                evs.append(rep[2])
        else:
            raise TimeoutError("EOSE non reçu dans le délai")
        return evs
    finally:
        c.fermer()


# ------------------------------------------------------------------ clé, configuration, journal

def lire_cle(chemin):
    p = Path(chemin)
    if os.name == "posix" and p.stat().st_mode & 0o077:
        raise PermissionError("le fichier de clé est lisible par d'autres utilisateurs (chmod 600)")
    h = p.read_text(encoding="utf-8").strip().lower()
    if not RE_HEX64.fullmatch(h):
        raise ValueError("format de clé inattendu (64 caractères hexadécimaux attendus)")
    cle = bytes.fromhex(h)
    pubkey_gen(cle)
    return cle


def generer_cle(chemin):
    """Crée un fichier de clé neuf (0600, jamais écrasé) ; renvoie la clé PUBLIQUE en hexadécimal, jamais la clé secrète."""
    while True:
        cle = os.urandom(32)
        if 1 <= entier(cle) <= ORDRE - 1:
            break
    fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(cle.hex() + "\n")
    return pubkey_gen(cle).hex()


def lire_config(chemin):
    cp = configparser.ConfigParser()
    cp.read(chemin, encoding="utf-8-sig")
    c = cp["nostr"] if "nostr" in cp else {}
    conf = {"destination": Path((c.get("destination") or "").strip() or "/var/lib/archiveur"),
            "journal": Path((c.get("journal") or "").strip() or "/var/lib/nostr-temoin/journal.jsonl"),
            "cle": (c.get("cle") or "").strip() or None,
            "pubkey": (c.get("pubkey") or "").strip().lower() or None,
            "relais": [r.strip() for r in (c.get("relais") or "").split(",") if r.strip()],
            "debut": (c.get("debut") or "").strip() or None,
            "kind": int((c.get("kind") or "").strip() or KIND_DEFAUT),
            "min_ok": int((c.get("min_ok") or "").strip() or MIN_OK_DEFAUT),
            "delai": float((c.get("delai") or "").strip() or DELAI_DEFAUT_S)}
    controler_config(conf, chiffre_obligatoire=True, cle_requise=False)       # « publier » exige la clé, « verifier » non
    return conf


def controler_config(conf, chiffre_obligatoire=False, cle_requise=True):
    """chiffre_obligatoire : relais en wss:// seulement (toujours le cas pour le service ; les tests utilisent ws:// en local).
    cle_requise : la clé secrète est nécessaire pour publier ; pour vérifier, la clé PUBLIQUE configurée suffit."""
    if cle_requise and not conf.get("cle"):
        raise ValueError("[nostr] cle n'est pas configuré")
    if conf.get("pubkey") and not RE_HEX64.fullmatch(conf["pubkey"]):
        raise ValueError("[nostr] pubkey doit faire 64 caractères hexadécimaux (clé publique, pas la clé secrète)")
    if not conf.get("relais") or (chiffre_obligatoire and any(not r.startswith("wss://") for r in conf["relais"])):
        raise ValueError("[nostr] relais : au moins un relais, tous en wss://")
    if not 1 <= conf["min_ok"] <= len(conf["relais"]):
        raise ValueError("[nostr] min_ok doit être compris entre 1 et le nombre de relais")
    if conf.get("debut") and not RE_JOUR.fullmatch(conf["debut"]):
        raise ValueError("[nostr] debut doit être une date AAAA-MM-JJ")


def lire_journal(chemin):
    p = Path(chemin)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def ajouter_journal(chemin, entree):
    p = Path(chemin)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(entree, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def delai_recul(echecs, base=RECUL_BASE_S, maxi=RECUL_MAX_S):
    """Attente avant le prochain essai d'un jour après `echecs` essais infructueux (1 : base, 2 : 2 x base, 3 : 4 x base…)."""
    return min(base * 2 ** (echecs - 1), maxi)


def etat_par_jour(entrees):
    """jour -> {racine, evenement, ok_relais, echecs, dernier_essai} cumulés sur tous les essais du journal.
    Une ligne « avant envoi » (événement journalisé avant l'envoi) ne compte pas comme un essai."""
    etat = {}
    for e in entrees:
        s = etat.setdefault(e["jour"], {"racine": e["racine"], "evenement": e["evenement"], "ok_relais": set(),
                                        "echecs": 0, "dernier_essai": 0, "reprises": 0, "derniere_reprise": 0})
        s["ok_relais"] |= {r for r, v in e["relais"].items() if v["ok"]}
        if e.get("etape") != "avant envoi" and not e["publie"]:
            s["echecs"] += 1
            s["dernier_essai"] = max(s["dernier_essai"], e.get("tente_a", 0))
        elif e.get("etape") != "avant envoi" and any(not v["ok"] for v in e["relais"].values()):
            # quorum atteint mais au moins un relais a refusé : compte comme une reprise infructueuse (recul propre)
            s["reprises"] += 1
            s["derniere_reprise"] = max(s["derniere_reprise"], e.get("tente_a", 0))
    return etat


def adn_du_jour(destination):
    """[(jour, racine, mtime)] des ADN scellés, du plus ancien au plus récent."""
    res = []
    for p in sorted((Path(destination) / "adn").glob("adn-????-??-??.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if not RE_JOUR.fullmatch(str(d.get("jour"))) or not RE_HEX64.fullmatch(str(d.get("racine"))):
            raise ValueError(f"{p.name} : jour ou racine mal formés")
        res.append((d["jour"], d["racine"], p.stat().st_mtime))
    return res


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ publication et vérification

def publier(conf, now_s=None, envoyer=publier_sur, a_blanc=False):
    now_s = int(time.time() if now_s is None else now_s)
    controler_config(conf)
    res = {"publies": [], "deja": [], "en_attente": [], "reportes": [], "erreurs": []}

    def signaler_retard(jour, mtime, nb_ok):
        if now_s - mtime > RETARD_ALERTE_S:
            res["erreurs"].append(f"{jour} : ADN scellé depuis plus de 6 h et pas encore publié ({nb_ok}/{conf['min_ok']} relais)")
    if not conf.get("debut"):
        res["note"] = "aucune date de début ([nostr] debut) : rien n'est publié"
        return res
    cle = lire_cle(conf["cle"])
    if conf.get("pubkey") and conf["pubkey"] != pubkey_gen(cle).hex():
        raise ValueError("[nostr] pubkey ne correspond pas à la clé secrète du fichier « cle » : rien n'est publié")
    etat = etat_par_jour(lire_journal(conf["journal"]))
    for jour, racine, mtime in adn_du_jour(conf["destination"]):
        if jour < conf["debut"]:
            continue
        s = etat.get(jour)
        if s and s["racine"] != racine:
            res["erreurs"].append(f"{jour} : la racine de l'ADN a changé depuis la publication, rien n'est renvoyé")
            continue
        reprise = False
        if s and len(s["ok_relais"]) >= conf["min_ok"]:
            # Quorum atteint : le jour est publié. Les relais qui n'ont pas répondu OK sont resollicités (même événement),
            # avec recul progressif et au plus MAX_REPRISES échecs ; un refus à ce stade n'est jamais une erreur.
            manquants = [r for r in conf["relais"] if r not in s["ok_relais"]]
            if (not manquants or s["reprises"] >= MAX_REPRISES
                    or now_s < s["derniere_reprise"] + delai_recul(max(s["reprises"], 1), conf.get("recul_base", RECUL_BASE_S),
                                                                  conf.get("recul_max", RECUL_MAX_S))):
                res["deja"].append(jour)
                continue
            reprise = True
        if s and s["echecs"] and now_s < s["dernier_essai"] + delai_recul(s["echecs"], conf.get("recul_base", RECUL_BASE_S),
                                                                          conf.get("recul_max", RECUL_MAX_S)):
            res["reportes"].append(jour)                    # recul progressif : pas de nouvel essai avant l'échéance
            res["en_attente"].append(jour)
            signaler_retard(jour, mtime, len(s["ok_relais"]))
            continue
        ev = s["evenement"] if s else evenement(cle, jour, racine, now_s, conf["kind"])
        if a_blanc:
            res.setdefault("reprises_a_blanc" if reprise else "evenements_a_blanc", []).append(jour if reprise else ev)
            continue
        if not s:
            # Événement journalisé AVANT l'envoi : si le processus s'arrête en cours de route, le passage suivant renvoie
            # ce même événement au lieu d'en créer un second pour le même jour.
            ajouter_journal(conf["journal"], {"jour": jour, "racine": racine, "evenement": ev, "tente_le": iso(now_s),
                                              "tente_a": now_s, "relais": {}, "ok_total": 0, "publie": False,
                                              "etape": "avant envoi"})
            s = {"racine": racine, "evenement": ev, "ok_relais": set(), "echecs": 0, "dernier_essai": 0,
                 "reprises": 0, "derniere_reprise": 0}
            etat[jour] = s
        deja_ok = s["ok_relais"]
        resultats = {r: envoyer(r, ev, conf["delai"]) for r in conf["relais"] if r not in deja_ok}
        ok_relais = deja_ok | {r for r, (ok, _) in resultats.items() if ok}
        publie = len(ok_relais) >= conf["min_ok"]
        ajouter_journal(conf["journal"], {"jour": jour, "racine": racine, "evenement": ev, "tente_le": iso(now_s),
                                          "tente_a": now_s,
                                          "relais": {r: {"ok": ok, "message": m} for r, (ok, m) in resultats.items()},
                                          "ok_total": len(ok_relais), "publie": publie})
        reste = any(not ok for ok, _ in resultats.values())
        etat[jour] = {"racine": racine, "evenement": ev, "ok_relais": ok_relais,
                      "echecs": s["echecs"] + (0 if publie else 1), "dernier_essai": now_s,
                      "reprises": s["reprises"] + (1 if publie and reste else 0),
                      "derniere_reprise": now_s if publie and reste else s["derniere_reprise"]}
        if reprise:
            res.setdefault("reprises", []).append(jour)          # jour déjà publié : seulement les relais manquants resollicités
        elif publie:
            res["publies"].append(jour)
        else:
            res["en_attente"].append(jour)
            signaler_retard(jour, mtime, len(ok_relais))
    return res


def verifier(conf, lire=lire_evenements):
    """Relit les événements sur chaque relais et les compare aux ADN locaux (lecture seule)."""
    controler_config(conf, cle_requise=not conf.get("pubkey"))
    pub = conf.get("pubkey") or pubkey_gen(lire_cle(conf["cle"])).hex()       # avec pubkey configurée, la clé secrète n'est pas lue
    attendus = {j: r for j, r, _ in adn_du_jour(conf["destination"]) if conf.get("debut") and j >= conf["debut"]}
    rapport = {}
    for url in conf["relais"]:
        try:
            evs = lire(url, {"authors": [pub], "kinds": [conf["kind"]]}, conf["delai"])
        except Exception as e:
            rapport[url] = {"erreur": f"{type(e).__name__} {str(e)[:100]}"}
            continue
        trouves, invalides = {}, 0
        for ev in evs:
            try:
                c = json.loads(ev["content"])
                valide = (ev["pubkey"] == pub and ev["kind"] == conf["kind"] and verifier_evenement(ev)
                          and set(c) == {"jour", "racine_du_jour"})
            except (KeyError, TypeError, ValueError):
                valide = False
            if not valide:
                invalides += 1
                continue
            trouves.setdefault(c["jour"], set()).add(c["racine_du_jour"])
        rapport[url] = {"presents": sorted(j for j in attendus if trouves.get(j) == {attendus[j]}),
                        "absents": sorted(j for j in attendus if j not in trouves),
                        "divergents": sorted(j for j in attendus if j in trouves and trouves[j] != {attendus[j]}),
                        "invalides": invalides}
    return rapport


def main(argv=None):
    ap = argparse.ArgumentParser(description="Témoin public Nostr de l'ADN")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("publier")
    p.add_argument("--config", required=True)
    p.add_argument("--a-blanc", action="store_true", help="construit et signe les événements sans rien envoyer ni journaliser")
    v = sp.add_parser("verifier")
    v.add_argument("--config", required=True)
    k = sp.add_parser("cle-generer")
    k.add_argument("--sortie", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "cle-generer":
        print("clé publique (hex) :", generer_cle(a.sortie))
        print("clé secrète écrite dans", a.sortie, "(0600) : ne jamais la publier ni la committer")
        print("à recopier dans la configuration : [nostr] pubkey = <la clé publique ci-dessus>")
        return 0
    conf = lire_config(a.config)
    if a.cmd == "publier":
        r = publier(conf, a_blanc=a.a_blanc)
        print(json.dumps(r, ensure_ascii=False))
        return 1 if r["erreurs"] else 0
    r = verifier(conf)
    print(json.dumps(r, ensure_ascii=False))
    return 1 if any("erreur" in v or v["absents"] or v["divergents"] or v["invalides"] for v in r.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
