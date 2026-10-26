"""Tests du témoin Nostr (aucun réseau externe : les relais sont des faux relais locaux sur 127.0.0.1, aucune vraie clé).

    python -m unittest -v test_nostr_temoin
"""
import base64, hashlib, io, json, os, shutil, socket, tempfile, threading, unittest
from pathlib import Path

import nostr_temoin as nt

J1, J2, J3 = "2026-10-15", "2026-10-16", "2026-10-17"
RACINE = {J1: "a1" * 32, J2: "b2" * 32, J3: "c3" * 32}
CLE_TEST = bytes.fromhex("11" * 32)          # clé de test fixe, jamais utilisée ailleurs
T0 = 1_792_000_000


class FauxRelais:
    """Relais Nostr minimal (ws://, sans TLS) : vérifie la signature des EVENT reçus, répond OK, garde les acceptés."""

    def __init__(self, accepte=True, repond=True, ping_avant=False):
        self.accepte, self.repond, self.ping_avant = accepte, repond, ping_avant
        self.evenements, self.arret, self.reponses_pong = [], False, 0
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.srv.settimeout(0.2)
        self.url = f"ws://127.0.0.1:{self.srv.getsockname()[1]}"
        threading.Thread(target=self.boucle, daemon=True).start()

    def boucle(self):
        while not self.arret:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.client, args=(conn,), daemon=True).start()

    def envoyer(self, conn, msg):
        conn.sendall(nt.trame(0x1, json.dumps(msg).encode()))

    def client(self, conn):
        conn.settimeout(5)
        f = conn.makefile("rb")
        try:
            lignes = []
            while True:
                l = f.readline(8192)
                if l in (b"\r\n", b""):
                    break
                lignes.append(l.decode("latin-1"))
            cle = next(l.split(":", 1)[1].strip() for l in lignes if l.lower().startswith("sec-websocket-key"))
            accept = base64.b64encode(hashlib.sha1((cle + nt.GUID).encode()).digest()).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
            while True:
                fin, op, charge = nt.lire_trame(f)
                if op == 0x8:
                    break
                if op == 0xA:
                    self.reponses_pong += 1
                    continue
                if op != 0x1:
                    continue
                m = json.loads(charge.decode())
                if m[0] == "EVENT":
                    ev = m[1]
                    ok = self.accepte and nt.verifier_evenement(ev)
                    if ok:
                        self.evenements.append(ev)
                    if self.ping_avant:
                        conn.sendall(nt.trame(0x9, b"salut"))
                    if self.repond:
                        self.envoyer(conn, ["OK", ev["id"], ok, "" if ok else "blocked: test"])
                elif m[0] == "REQ":
                    for ev in self.evenements:
                        self.envoyer(conn, ["EVENT", m[1], ev])
                    self.envoyer(conn, ["EOSE", m[1]])
        except Exception:
            pass
        finally:
            conn.close()

    def fermer(self):
        self.arret = True
        self.srv.close()


class TestBIP340(unittest.TestCase):
    """Vecteurs de test officiels de la BIP-340 (bip-0340/test-vectors.csv)."""

    VECTEURS = [
        ("0000000000000000000000000000000000000000000000000000000000000003",
         "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
        ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
         "0000000000000000000000000000000000000000000000000000000000000001",
         "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
         "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
    ]

    def test_cle_publique_signature_et_verification(self):
        for sk, pk, aux, msg, sig in self.VECTEURS:
            with self.subTest(pk=pk[:8]):
                self.assertEqual(nt.pubkey_gen(bytes.fromhex(sk)).hex().upper(), pk)
                self.assertEqual(nt.schnorr_sign(bytes.fromhex(msg), bytes.fromhex(sk), bytes.fromhex(aux)).hex().upper(), sig)
                self.assertTrue(nt.schnorr_verify(bytes.fromhex(msg), bytes.fromhex(pk), bytes.fromhex(sig)))

    def test_signature_ou_message_alteres_refuses(self):
        sk, pk, aux, msg, sig = self.VECTEURS[0]
        s = bytearray(bytes.fromhex(sig))
        s[10] ^= 1
        self.assertFalse(nt.schnorr_verify(bytes.fromhex(msg), bytes.fromhex(pk), bytes(s)))
        self.assertFalse(nt.schnorr_verify(b"\x01" * 32, bytes.fromhex(pk), bytes.fromhex(sig)))
        self.assertFalse(nt.schnorr_verify(bytes.fromhex(msg), bytes.fromhex(pk), bytes.fromhex(sig)[:63]))

    def test_cle_secrete_invalide(self):
        for mauvaise in (b"\x00" * 32, nt.octets(nt.ORDRE), b"\x01" * 31):
            with self.assertRaises(ValueError):
                nt.pubkey_gen(mauvaise)


class TestEvenement(unittest.TestCase):
    def test_contenu_strictement_jour_et_racine(self):
        ev = nt.evenement(CLE_TEST, J1, RACINE[J1], T0, nt.KIND_DEFAUT)
        self.assertEqual(json.loads(ev["content"]), {"jour": J1, "racine_du_jour": RACINE[J1]})
        self.assertEqual(ev["tags"], [])
        self.assertEqual(set(ev), {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
        self.assertEqual(ev["pubkey"], nt.pubkey_gen(CLE_TEST).hex())
        self.assertTrue(1000 <= ev["kind"] <= 9999)

    def test_identifiant_et_signature(self):
        ev = nt.evenement(CLE_TEST, J1, RACINE[J1], T0, nt.KIND_DEFAUT)
        attendu = hashlib.sha256(json.dumps([0, ev["pubkey"], T0, nt.KIND_DEFAUT, [], ev["content"]],
                                            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(ev["id"], attendu)
        self.assertTrue(nt.verifier_evenement(ev))
        faux = dict(ev, content=json.dumps({"jour": J1, "racine_du_jour": "00" * 32}, separators=(",", ":")))
        self.assertFalse(nt.verifier_evenement(faux))
        self.assertFalse(nt.verifier_evenement(dict(ev, sig="00" * 64)))
        self.assertFalse(nt.verifier_evenement({"id": "x"}))

    def test_entrees_mal_formees_refusees(self):
        for jour, racine in (("15/10/2026", RACINE[J1]), (J1, "zz"), (J1, RACINE[J1].upper())):
            with self.assertRaises(ValueError):
                nt.evenement(CLE_TEST, jour, racine, T0, nt.KIND_DEFAUT)


class TestTrames(unittest.TestCase):
    def test_aller_retour_masque_et_non_masque(self):
        for n in (0, 1, 125, 126, 127, 65535, 65536, 70000):
            charge = bytes(i % 251 for i in range(n))
            for masque in (None, b"\x01\x02\x03\x04"):
                with self.subTest(n=n, masque=bool(masque)):
                    fin, op, lu = nt.lire_trame(io.BytesIO(nt.trame(0x1, charge, masque)))
                    self.assertEqual((fin, op, lu), (True, 0x1, charge))

    def test_trame_trop_grande_ou_tronquee(self):
        with self.assertRaises(ValueError):
            nt.lire_trame(io.BytesIO(nt.trame(0x1, b"x" * 200)), max_octets=100)
        with self.assertRaises(ConnectionError):
            nt.lire_trame(io.BytesIO(nt.trame(0x1, b"x" * 200)[:50]))


class TestPublication(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "adn").mkdir()
        for j in (J1, J2, J3):
            self.ecrire_adn(j, RACINE[j])
        self.cle = self.tmp / "cle.hex"
        self.cle.write_text(CLE_TEST.hex() + "\n", encoding="utf-8")
        os.chmod(self.cle, 0o600)
        self.relais = []

    def faux_relais(self, **kw):
        r = FauxRelais(**kw)
        self.addCleanup(r.fermer)
        self.relais.append(r)
        return r

    def ecrire_adn(self, jour, racine):
        (self.tmp / "adn" / f"adn-{jour}.json").write_text(json.dumps({"jour": jour, "racine": racine, "prix": "NE PAS PUBLIER"}),
                                                          encoding="utf-8")

    def conf(self, urls, **kw):
        c = {"destination": self.tmp, "journal": self.tmp / "nostr" / "journal.jsonl", "cle": str(self.cle), "relais": urls,
             "debut": J1, "kind": nt.KIND_DEFAUT, "min_ok": 2, "delai": 2.0}
        c.update(kw)
        return c

    def envoyer_local(self, url, ev, delai):
        return nt.publier_sur(url, ev, delai)

    def test_publication_deux_relais_sur_trois_puis_reprise_du_relais_manquant(self):
        a, b, c = self.faux_relais(), self.faux_relais(), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url, c.url], debut=J2)
        res = nt.publier(conf, T0, self.envoyer_local)
        self.assertEqual((res["publies"], res["en_attente"], res["erreurs"]), ([J2, J3], [], []))
        self.assertEqual([len(r.evenements) for r in self.relais], [2, 2, 0])
        for ev in a.evenements:
            self.assertEqual(set(json.loads(ev["content"])), {"jour", "racine_du_jour"})
            self.assertNotIn("NE PAS PUBLIER", ev["content"])
        trop_tot = nt.publier(conf, T0 + 1800, self.envoyer_local)                  # recul de 1 h : rien n'est renvoyé
        self.assertEqual((trop_tot["publies"], trop_tot["deja"], trop_tot.get("reprises")), ([], [J2, J3], None))
        self.assertEqual([len(r.evenements) for r in self.relais], [2, 2, 0])
        c.accepte = True                                                              # le relais manquant répond enfin
        again = nt.publier(conf, T0 + 3600, self.envoyer_local)
        self.assertEqual((again["publies"], again["reprises"], again["erreurs"]), ([], [J2, J3], []))
        self.assertEqual([len(r.evenements) for r in self.relais], [2, 2, 2])         # a et b ne sont pas resollicités
        self.assertEqual({ev["id"] for r in self.relais for ev in r.evenements}, {ev["id"] for ev in a.evenements})
        final = nt.publier(conf, T0 + 10 * 3600, self.envoyer_local)
        self.assertEqual((final["reprises"] if "reprises" in final else [], final["deja"]), ([], [J2, J3]))
        self.assertEqual([len(r.evenements) for r in self.relais], [2, 2, 2])

    def test_reprise_infructueuse_recul_plafond_et_jamais_une_erreur(self):
        a, b, c = self.faux_relais(), self.faux_relais(), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url, c.url], debut=J3)
        appels = []

        def compte(url, ev, delai):
            appels.append(url)
            return nt.publier_sur(url, ev, delai)
        nt.publier(conf, T0, compte)
        self.assertEqual(len(appels), 3)
        t = T0
        for essai in range(1, nt.MAX_REPRISES + 5):
            t += 86400 * 2                                                          # toujours au-delà du plus long recul
            avant = len(appels)
            res = nt.publier(conf, t, compte)
            self.assertEqual(res["erreurs"], [])                                       # un relais récalcitrant n'alerte jamais
            self.assertEqual(len(appels) - avant, 1 if essai < nt.MAX_REPRISES else 0)   # 1 envoi (c seul), puis plus rien
        self.assertEqual([len(r.evenements) for r in self.relais], [1, 1, 0])

    def test_reprise_a_blanc_ne_touche_pas_au_journal(self):
        a, b, c = self.faux_relais(), self.faux_relais(), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url, c.url], debut=J3)
        nt.publier(conf, T0, self.envoyer_local)
        n = len(nt.lire_journal(conf["journal"]))
        res = nt.publier(conf, T0 + 7200, self.envoyer_local, a_blanc=True)
        self.assertEqual((res["reprises_a_blanc"], len(nt.lire_journal(conf["journal"]))), ([J3], n))

    def test_un_seul_relais_accepte_puis_reprise_avec_le_meme_evenement(self):
        a, b = self.faux_relais(), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url], debut=J3)
        res = nt.publier(conf, T0, self.envoyer_local)
        self.assertEqual((res["publies"], res["en_attente"]), ([], [J3]))
        premier = a.evenements[0]
        b.accepte = True
        res = nt.publier(conf, T0 + 3600, self.envoyer_local)
        self.assertEqual(res["publies"], [J3])
        self.assertEqual(b.evenements[0]["id"], premier["id"])                       # même événement, même created_at
        self.assertEqual(len(a.evenements), 1)                                       # le relais qui l'avait déjà n'est pas resollicité
        self.assertEqual(b.evenements[0]["created_at"], T0)

    def test_delai_de_recul(self):
        self.assertEqual([nt.delai_recul(n) for n in (1, 2, 3, 4, 5, 6, 7, 50)],
                         [3600, 7200, 14400, 28800, 57600, 86400, 86400, 86400])
        self.assertEqual(nt.delai_recul(3, base=60, maxi=100), 100)

    def test_recul_progressif_entre_les_essais(self):
        a, b = self.faux_relais(accepte=False), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url], debut=J3)
        appels = []

        def compte(url, ev, delai):
            appels.append(url)
            return nt.publier_sur(url, ev, delai)

        def passage(secondes):
            n = len(appels)
            res = nt.publier(conf, T0 + secondes, compte)
            return res, len(appels) - n
        res, n = passage(0)                                    # essai 1 : échec, prochain essai dans 1 h
        self.assertEqual((res["en_attente"], res["reportes"], n), ([J3], [], 2))
        res, n = passage(1800)                                 # trop tôt : reporté, aucun envoi
        self.assertEqual((res["en_attente"], res["reportes"], n), ([J3], [J3], 0))
        res, n = passage(3600)                                 # essai 2 : échec, prochain essai dans 2 h
        self.assertEqual((res["reportes"], n), ([], 2))
        res, n = passage(3600 + 7000)                          # encore trop tôt (7000 s < 7200 s)
        self.assertEqual((res["reportes"], n), ([J3], 0))
        res, n = passage(3600 + 7200)                          # essai 3 : échec, prochain essai dans 4 h
        self.assertEqual((res["reportes"], n), ([], 2))
        res, n = passage(3600 + 7200 + 14399)
        self.assertEqual((res["reportes"], n), ([J3], 0))
        a.accepte = b.accepte = True                           # les relais acceptent de nouveau
        res, n = passage(3600 + 7200 + 14400)
        self.assertEqual((res["publies"], res["reportes"], n), ([J3], [], 2))
        self.assertEqual({ev["id"] for r in self.relais for ev in r.evenements}, {a.evenements[0]["id"]})   # toujours le même événement
        res, n = passage(3600 + 7200 + 14400 + 3600)
        self.assertEqual((res["deja"], n), ([J3], 0))

    def test_le_recul_n_efface_pas_l_alerte_de_retard(self):
        a, b = self.faux_relais(accepte=False), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url], debut=J3)
        mtime = int((self.tmp / "adn" / f"adn-{J3}.json").stat().st_mtime)
        res = nt.publier(conf, mtime + 7 * 3600, self.envoyer_local)
        self.assertEqual(len(res["erreurs"]), 1)
        res = nt.publier(conf, mtime + 7 * 3600 + 600, self.envoyer_local)          # reporté, mais l'alerte reste émise
        self.assertEqual((res["reportes"], len(res["erreurs"])), ([J3], 1))

    def test_arret_brutal_apres_envoi_reprend_le_meme_evenement(self):
        a, b = self.faux_relais(), self.faux_relais()
        conf = self.conf([a.url, b.url], debut=J3)

        def tombe_apres_le_premier_relais(url, ev, delai):
            nt.publier_sur(url, ev, delai)
            raise RuntimeError("arrêt brutal avant l'écriture du résultat")
        with self.assertRaises(RuntimeError):
            nt.publier(conf, T0, tombe_apres_le_premier_relais)
        premier = a.evenements[0]
        res = nt.publier(conf, T0 + 3600, self.envoyer_local)
        self.assertEqual(res["publies"], [J3])
        ids = {ev["id"] for r in self.relais for ev in r.evenements}
        self.assertEqual(ids, {premier["id"]})                                       # jamais un second événement pour J3
        self.assertEqual({ev["created_at"] for r in self.relais for ev in r.evenements}, {T0})

    def test_poignee_de_main_refusee(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(2)
        srv.settimeout(5)
        self.addCleanup(srv.close)

        def repondre(corps):
            conn, _ = srv.accept()
            conn.recv(4096)
            conn.sendall(corps)
            conn.close()
        url = f"ws://127.0.0.1:{srv.getsockname()[1]}"
        for corps in (b"HTTP/1.1 400 Bad Request\r\n\r\n",
                      b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: pas-le-bon\r\n\r\n"):
            t = threading.Thread(target=repondre, args=(corps,), daemon=True)
            t.start()
            ok, message = nt.publier_sur(url, nt.evenement(CLE_TEST, J1, RACINE[J1], T0, nt.KIND_DEFAUT), 2)
            t.join()
            self.assertFalse(ok)
            self.assertIn("ConnectionError", message)

    def test_ligne_de_commande(self):
        import contextlib
        chemin_cle = self.tmp / "cle-cli.hex"
        sortie = io.StringIO()
        with contextlib.redirect_stdout(sortie):
            self.assertEqual(nt.main(["cle-generer", "--sortie", str(chemin_cle)]), 0)
        secret = chemin_cle.read_text(encoding="utf-8").strip()
        self.assertNotIn(secret, sortie.getvalue())                                  # la clé secrète n'est jamais affichée
        self.assertIn(nt.pubkey_gen(bytes.fromhex(secret)).hex(), sortie.getvalue())
        conf = self.tmp / "nostr.conf"
        conf.write_text(f"[nostr]\ndestination = {self.tmp}\njournal = {self.tmp / 'j.jsonl'}\ncle = {chemin_cle}\n"
                        f"relais = wss://a.example, wss://b.example\ndebut = {J3}\n", encoding="utf-8")
        sortie = io.StringIO()
        with contextlib.redirect_stdout(sortie):
            self.assertEqual(nt.main(["publier", "--config", str(conf), "--a-blanc"]), 0)
        self.assertNotIn(secret, sortie.getvalue())
        self.assertEqual(len(json.loads(sortie.getvalue())["evenements_a_blanc"]), 1)
        self.assertFalse((self.tmp / "j.jsonl").exists())

    def test_alerte_si_scelle_depuis_plus_de_six_heures_et_non_publie(self):
        a, b = self.faux_relais(accepte=False), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url], debut=J3)
        mtime = (self.tmp / "adn" / f"adn-{J3}.json").stat().st_mtime
        res = nt.publier(conf, int(mtime) + 7 * 3600, self.envoyer_local)
        self.assertEqual(res["en_attente"], [J3])
        self.assertEqual(len(res["erreurs"]), 1)
        res = nt.publier(conf, int(mtime) + 3600, self.envoyer_local)
        self.assertEqual(res["erreurs"], [])

    def test_relais_muet_ou_injoignable_ne_plante_pas(self):
        muet, ok1, ok2 = self.faux_relais(repond=False), self.faux_relais(), self.faux_relais()
        mort = "ws://127.0.0.1:1"
        res = nt.publier(self.conf([muet.url, mort, ok1.url, ok2.url], debut=J3, delai=0.5), T0, self.envoyer_local)
        self.assertEqual(res["publies"], [J3])
        journal = nt.lire_journal(self.tmp / "nostr" / "journal.jsonl")
        self.assertEqual([e.get("etape") for e in journal], ["avant envoi", None])   # intention d'abord, puis résultat
        entree = journal[-1]
        self.assertFalse(entree["relais"][muet.url]["ok"])
        self.assertFalse(entree["relais"][mort]["ok"])

    def test_ping_du_relais_recoit_un_pong(self):
        a, b = self.faux_relais(ping_avant=True), self.faux_relais()
        res = nt.publier(self.conf([a.url, b.url], debut=J3), T0, self.envoyer_local)
        self.assertEqual(res["publies"], [J3])
        self.assertGreaterEqual(a.reponses_pong, 1)

    def test_sans_date_de_debut_rien_n_est_publie(self):
        a, b = self.faux_relais(), self.faux_relais()
        res = nt.publier(self.conf([a.url, b.url], debut=None), T0, self.envoyer_local)
        self.assertEqual(res["publies"], [])
        self.assertIn("rien n'est publié", res["note"])
        self.assertEqual([len(r.evenements) for r in self.relais], [0, 0])
        self.assertFalse((self.tmp / "nostr").exists())

    def test_a_blanc_ne_envoie_ni_ne_journalise(self):
        a, b = self.faux_relais(), self.faux_relais()
        res = nt.publier(self.conf([a.url, b.url], debut=J3), T0, self.envoyer_local, a_blanc=True)
        self.assertEqual(len(res["evenements_a_blanc"]), 1)
        self.assertEqual([len(r.evenements) for r in self.relais], [0, 0])
        self.assertFalse((self.tmp / "nostr").exists())

    def test_racine_modifiee_apres_publication_est_refusee(self):
        a, b = self.faux_relais(), self.faux_relais()
        conf = self.conf([a.url, b.url], debut=J3)
        nt.publier(conf, T0, self.envoyer_local)
        self.ecrire_adn(J3, "d4" * 32)
        res = nt.publier(conf, T0 + 60, self.envoyer_local)
        self.assertEqual(res["publies"], [])
        self.assertEqual(len(res["erreurs"]), 1)
        self.assertEqual([len(r.evenements) for r in self.relais], [1, 1])

    def test_adn_mal_forme_refuse(self):
        self.ecrire_adn(J3, "pas-une-racine")
        a, b = self.faux_relais(), self.faux_relais()
        with self.assertRaises(ValueError):
            nt.publier(self.conf([a.url, b.url], debut=J3), T0, self.envoyer_local)

    def test_verification_presents_absents_et_divergents(self):
        a, b, c = self.faux_relais(), self.faux_relais(), self.faux_relais(accepte=False)
        conf = self.conf([a.url, b.url, c.url], debut=J2)
        nt.publier(conf, T0, self.envoyer_local)
        rap = nt.verifier(conf, lambda url, f, d: nt.lire_evenements(url, f, d))
        self.assertEqual(rap[a.url], {"presents": [J2, J3], "absents": [], "divergents": [], "invalides": 0})
        self.assertEqual(rap[c.url]["absents"], [J2, J3])
        b.evenements.pop()                                                           # le relais b « perd » un événement
        faux = nt.evenement(CLE_TEST, J2, "e5" * 32, T0 + 5, nt.KIND_DEFAUT)         # a un événement du même jour, autre racine
        a.evenements.append(faux)
        rap = nt.verifier(conf, lambda url, f, d: nt.lire_evenements(url, f, d))
        self.assertEqual(rap[b.url]["absents"], [J3])
        self.assertEqual(rap[a.url]["divergents"], [J2])
        morte = nt.verifier(self.conf(["wss://127.0.0.1:1"], min_ok=1, debut=J2))
        self.assertIn("erreur", morte["wss://127.0.0.1:1"])

    def test_pubkey_configuree_doit_correspondre_a_la_cle_secrete(self):
        a, b = self.faux_relais(), self.faux_relais()
        autre = nt.pubkey_gen(b"\x22" * 32).hex()
        with self.assertRaises(ValueError) as c:
            nt.publier(self.conf([a.url, b.url], debut=J3, pubkey=autre), T0, self.envoyer_local)
        self.assertNotIn(CLE_TEST.hex(), str(c.exception))
        self.assertEqual([len(r.evenements) for r in self.relais], [0, 0])           # rien envoyé
        self.assertFalse((self.tmp / "nostr").exists())                              # rien journalisé
        res = nt.publier(self.conf([a.url, b.url], debut=J3, pubkey=nt.pubkey_gen(CLE_TEST).hex()), T0, self.envoyer_local)
        self.assertEqual(res["publies"], [J3])

    def test_verification_avec_la_seule_cle_publique(self):
        a, b = self.faux_relais(), self.faux_relais()
        pub = nt.pubkey_gen(CLE_TEST).hex()
        nt.publier(self.conf([a.url, b.url], debut=J3, pubkey=pub), T0, self.envoyer_local)
        # « verifier » ne lit pas la clé secrète : le fichier de clé n'existe pas, seule la clé publique est configurée
        sans_secret = self.conf([a.url, b.url], debut=J3, pubkey=pub, cle=str(self.tmp / "absente.hex"))
        rap = nt.verifier(sans_secret)
        self.assertEqual(rap[a.url]["presents"], [J3])
        sans_cle = self.conf([a.url, b.url], debut=J3, pubkey=pub, cle=None)
        self.assertEqual(nt.verifier(sans_cle)[b.url]["presents"], [J3])
        with self.assertRaises(ValueError):                                          # sans pubkey, la clé secrète reste exigée
            nt.verifier(self.conf([a.url, b.url], debut=J3, cle=None))
        with self.assertRaises(ValueError):                                          # et « publier » exige toujours la clé secrète
            nt.publier(self.conf([a.url, b.url], debut=J3, pubkey=pub, cle=None), T0, self.envoyer_local)

    def test_verification_ignore_les_evenements_invalides_ou_d_une_autre_cle(self):
        a, b = self.faux_relais(), self.faux_relais()
        conf = self.conf([a.url, b.url], debut=J3)
        nt.publier(conf, T0, self.envoyer_local)
        autre = nt.evenement(b"\x22" * 32, J3, RACINE[J3], T0, nt.KIND_DEFAUT)
        a.evenements.append(autre)
        a.evenements.append(dict(a.evenements[0], sig="00" * 64))
        rap = nt.verifier(conf)
        self.assertEqual(rap[a.url]["invalides"], 2)
        self.assertEqual(rap[a.url]["presents"], [J3])


class TestCleEtConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_generation_de_cle(self):
        chemin = self.tmp / "cle.hex"
        pub = nt.generer_cle(str(chemin))
        cle = bytes.fromhex(chemin.read_text().strip())
        self.assertEqual(nt.pubkey_gen(cle).hex(), pub)
        self.assertNotIn(cle.hex(), pub)
        with self.assertRaises(FileExistsError):
            nt.generer_cle(str(chemin))
        self.assertEqual(nt.lire_cle(str(chemin)), cle) if os.name == "posix" else None

    @unittest.skipUnless(os.name == "posix", "droits Unix")
    def test_cle_lisible_par_d_autres_refusee(self):
        chemin = self.tmp / "cle.hex"
        chemin.write_text(CLE_TEST.hex(), encoding="utf-8")
        os.chmod(chemin, 0o644)
        with self.assertRaises(PermissionError):
            nt.lire_cle(str(chemin))

    def test_cle_mal_formee_sans_la_recopier(self):
        chemin = self.tmp / "cle.hex"
        chemin.write_text("secret-pas-hexa", encoding="utf-8")
        with self.assertRaises(ValueError) as c:
            nt.lire_cle(str(chemin))
        self.assertNotIn("secret-pas-hexa", str(c.exception))

    def test_configuration(self):
        f = self.tmp / "nostr.conf"
        f.write_text("[nostr]\ncle = /x/cle\nrelais = wss://a.example, wss://b.example, wss://c.example\ndebut = 2026-10-26\n",
                     encoding="utf-8")
        c = nt.lire_config(str(f))
        self.assertEqual((c["relais"], c["debut"], c["min_ok"], c["kind"]),
                         (["wss://a.example", "wss://b.example", "wss://c.example"], "2026-10-26", 2, nt.KIND_DEFAUT))
        pub = nt.pubkey_gen(CLE_TEST).hex()
        f.write_text(f"[nostr]\nrelais = wss://a.example\nmin_ok = 1\npubkey = {pub.upper()}\n", encoding="utf-8")
        c = nt.lire_config(str(f))                                                   # pour « verifier » : pas de clé secrète exigée
        self.assertEqual((c["pubkey"], c["cle"]), (pub, None))
        for pubkey_mal_formee in ("abc", pub[:-1], "z" * 64, pub + "00"):
            f.write_text(f"[nostr]\nrelais = wss://a.example\nmin_ok = 1\npubkey = {pubkey_mal_formee}\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                nt.lire_config(str(f))
        for contenu in ("[nostr]\ncle = /x\nrelais = ws://a.example\n", "[nostr]\nrelais = wss://a.example\n",
                        "[nostr]\ncle = /x\nrelais = wss://a.example\nmin_ok = 2\n",
                        "[nostr]\ncle = /x\nrelais = wss://a.example\nmin_ok = 1\ndebut = demain\n"):
            f.write_text(contenu, encoding="utf-8")
            with self.assertRaises(ValueError):
                nt.lire_config(str(f))


if __name__ == "__main__":
    unittest.main()
