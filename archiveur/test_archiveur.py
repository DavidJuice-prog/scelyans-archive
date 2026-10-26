"""Tests de l'archiveur sur des données fabriquées (aucun réseau, aucun fichier réel).

    python -m unittest -v test_archiveur
"""
import gzip, hashlib, json, os, shutil, stat, tempfile, unittest
from pathlib import Path

import archiveur as ar

J = "2026-10-15"
T0 = ar.secondes(J + "T00:00:00Z")


def bloc(index, prev, t):
    b = {"format": "trackyzz-multi-exchanges/1", "index": index, "prev_hash": prev, "collecte": ar.iso(t), "statut": "VERIFIED"}
    b["hash"] = hashlib.sha256(json.dumps(b, sort_keys=True).encode()).hexdigest()
    return b


class Source:
    """Imite /var/lib/trackyzz : registre en ajout seul, brut en membres gzip ajoutés."""

    def __init__(self, racine):
        self.d = Path(racine)
        (self.d / "registre").mkdir(parents=True)
        (self.d / "brut").mkdir()
        (self.d / "tetes").mkdir()
        self.index, self.tete = 0, "0" * 64

    def cycle(self, t, n=3):
        j = ar.jour_de(t)
        with gzip.open(self.d / "brut" / f"{j}.jsonl.gz", "at", encoding="utf-8") as f:
            f.write(json.dumps({"sha256": "x", "plateforme": "kraken", "collecte": ar.iso(t), "corps": "{\"a\": 1}"}) + "\n")
        with open(self.d / "registre" / f"{j}.jsonl", "a", encoding="utf-8") as f:
            for _ in range(n):
                b = bloc(self.index, self.tete, t)
                self.index, self.tete = self.index + 1, b["hash"]
                f.write(json.dumps(b, separators=(",", ":")) + "\n")

    def tete_du_lendemain(self, jour_str):
        lendemain = ar.jour_de(ar.secondes(jour_str + "T00:00:00Z") + 86400)
        sha = ar.sha256_fichier(self.d / "registre" / f"{jour_str}.jsonl")
        (self.d / "tetes" / f"{lendemain}.txt").write_text(f"tete x\nsha256 {sha} registre/{jour_str}.jsonl\n", encoding="utf-8")


def _rendre_modifiable(fn, p, _):
    os.chmod(p, stat.S_IWRITE)
    fn(p)


class TestArchiveur(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = Source(Path(self.tmp) / "trackyzz")
        self.conf = {"source": self.src.d, "destination": Path(self.tmp) / "archive", "debut": None, "ntfy_url": None}
        self.dest = self.conf["destination"]

    def tearDown(self):
        shutil.rmtree(self.tmp, onerror=_rendre_modifiable)

    def jour_complet(self, jour_str=J, sauf_heures=()):
        t0 = ar.secondes(jour_str + "T00:00:00Z")
        for t in range(t0 + 20, t0 + 86400, 60):
            if (t - t0) // 3600 not in sauf_heures:
                self.src.cycle(t)

    def test_heure_fermee_seulement_apres_ligne_suivante(self):
        for t in range(T0 + 20, T0 + 3600, 60):
            self.src.cycle(t)
        r = ar.executer(self.conf, now_s=T0 + 3600 + 300)       # 00h terminée, mais aucune ligne de 01h : on attend
        self.assertEqual(r["heures_fermees"], 0)
        self.src.cycle(T0 + 3600 + 20)
        r = ar.executer(self.conf, now_s=T0 + 3600 + 300)
        self.assertEqual(r["heures_fermees"], 1)
        m = ar.lire_manifeste(self.dest, T0)
        self.assertEqual((m["fermeture"], m["registre"]["lignes"], m["brut"]["lignes"]), ("normale", 60 * 3, 60))
        self.assertEqual(m["constitution"], "en_direct")

    def test_jour_complet_redonne_le_fichier_trackyzz_octet_pour_octet(self):
        self.jour_complet()
        self.src.cycle(T0 + 86400 + 20)
        self.src.tete_du_lendemain(J)
        r = ar.executer(self.conf, now_s=T0 + 86400 + 900)
        self.assertEqual(r["jours_fermes"], [J])
        b = json.loads((self.dest / "jours" / f"{J}.json").read_text(encoding="utf-8"))
        self.assertTrue(b["registre"]["concorde_fichier"])
        self.assertTrue(b["registre"]["concorde_tete"])
        self.assertTrue(b["brut"]["concorde"])
        self.assertEqual(len(b["heures"]), 24)
        self.assertEqual(r["incidents"], [])
        self.assertEqual(ar.verifier(self.conf), (24, []))

    def test_rien_n_est_reecrit_au_passage_suivant(self):
        self.jour_complet()
        self.src.cycle(T0 + 86400 + 20)
        self.src.tete_du_lendemain(J)
        ar.executer(self.conf, now_s=T0 + 86400 + 900)
        avant = {p: p.stat().st_mtime_ns for p in self.dest.rglob("*") if p.is_file()}
        r = ar.executer(self.conf, now_s=T0 + 86400 + 1200)
        self.assertEqual((r["heures_fermees"], r["jours_fermes"]), (0, []))
        self.assertEqual(avant, {p: p.stat().st_mtime_ns for p in self.dest.rglob("*") if p.is_file()})
        self.assertFalse(os.access(ar.manifeste_heure(self.dest, T0), os.W_OK))     # lecture seule

    def test_collecteur_muet_heure_fermee_par_delai_et_trou_note(self):
        for t in range(T0 + 20, T0 + 3600, 60):
            self.src.cycle(t)
        r = ar.executer(self.conf, now_s=T0 + 3 * 3600 + 120)
        self.assertEqual(r["heures_fermees"], 2)                  # 00h et 01h ; 02h attend encore
        self.assertEqual(ar.lire_manifeste(self.dest, T0)["fermeture"], "par_delai")
        self.assertEqual(ar.lire_manifeste(self.dest, T0 + 3600)["registre"]["lignes"], 0)
        trous = (self.dest / "trous.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(l)["heure"] for l in trous], [ar.iso(T0 + 3600)])

    def test_reprise_du_passe_marquee_a_posteriori(self):
        self.jour_complet()
        self.src.cycle(T0 + 86400 + 20)
        r = ar.executer(self.conf, now_s=T0 + 3 * 86400)
        self.assertEqual(r["heures_fermees"], 24 + 24 + 23)       # J, J+1 et J+2 sauf sa dernière heure (marge de 2 min)
        self.assertEqual(ar.lire_manifeste(self.dest, T0)["constitution"], "a_posteriori")

    def test_ligne_en_cours_d_ecriture_ignoree(self):
        for t in range(T0 + 20, T0 + 3600 + 60, 60):
            self.src.cycle(t)
        with open(self.src.d / "registre" / f"{J}.jsonl", "ab") as f:
            f.write(b'{"collecte":"2026-10-15T01:01:20Z","ind')       # ligne coupée en fin de fichier
        with open(self.src.d / "brut" / f"{J}.jsonl.gz", "ab") as f:
            f.write(gzip.compress(b'{"collecte":"2026-10-15T01:01:20Z"}\n')[:15])   # membre gzip incomplet
        r = ar.executer(self.conf, now_s=T0 + 3600 + 300)
        self.assertEqual(r["heures_fermees"], 1)
        self.assertEqual(r["incidents"], [])

    def test_chaine_rompue_entre_heures_signalee(self):
        for t in range(T0 + 20, T0 + 3600, 60):
            self.src.cycle(t)
        self.src.tete = "f" * 64                                   # le collecteur repart d'une autre tête
        for t in range(T0 + 3600 + 20, T0 + 2 * 3600 + 60, 60):
            self.src.cycle(t)
        r = ar.executer(self.conf, now_s=T0 + 2 * 3600 + 300)
        self.assertIn("chaine_rompue_entre_heures", r["incidents"])
        self.assertEqual(r["heures_fermees"], 2)                   # archivé tel quel : rien n'est corrigé

    def test_fichier_altere_detecte_par_verifier(self):
        for t in range(T0 + 20, T0 + 3600 + 60, 60):
            self.src.cycle(t)
        ar.executer(self.conf, now_s=T0 + 3600 + 300)
        f = ar.dossier_heure(self.dest, T0) / "00.registre.jsonl.gz"
        os.chmod(f, stat.S_IWRITE)
        f.write_bytes(gzip.compress(b"autre\n"))
        n, problemes = ar.verifier(self.conf)
        self.assertEqual(n, 1)
        self.assertEqual(len(problemes), 1)

    def test_conflit_jamais_ecrase(self):
        p = self.dest / "x.json"
        j = ar.Journal(self.dest, now_s=T0)
        ar.creer_une_fois(p, b"un\n", j)
        ar.creer_une_fois(p, b"deux\n", j)
        self.assertEqual(p.read_bytes(), b"un\n")
        self.assertEqual(len(list(self.dest.glob("x.json.conflit-*"))), 1)
        self.assertEqual([i["type"] for i in j.incidents], ["fichier_deja_present_autre_contenu"])

    def test_aucune_ecriture_dans_la_source(self):
        self.jour_complet()
        self.src.cycle(T0 + 86400 + 20)
        self.src.tete_du_lendemain(J)
        avant = {p: (p.stat().st_mtime_ns, ar.sha256_fichier(p)) for p in self.src.d.rglob("*") if p.is_file()}
        ar.executer(self.conf, now_s=T0 + 86400 + 900)
        apres = {p: (p.stat().st_mtime_ns, ar.sha256_fichier(p)) for p in self.src.d.rglob("*") if p.is_file()}
        self.assertEqual(avant, apres)


class FauxHorodateurs:
    """Aucun réseau : imite les réponses des horodateurs."""

    def __init__(self, ots=True, bitcoin=False, tsa=True, panne=False):
        self.ots, self.bitcoin, self.tsa, self.panne = ots, bitcoin, tsa, panne
        self.appels = []

    def ots_stamp(self, p):
        self.appels.append(("stamp", p.name))
        if self.panne:
            raise OSError("calendriers injoignables")
        return b"OTS-ATTENTE " + hashlib.sha256(p.read_bytes()).digest() if self.ots else None

    def ots_upgrade(self, p, octets):
        self.appels.append(("upgrade", p.name))
        return octets + b" BITCOIN" if self.bitcoin else None

    def rfc3161(self, p):
        self.appels.append(("tsa", p.name))
        return (b"TSQ", b"TSR") if self.tsa else None


class TestMerkle(unittest.TestCase):
    def test_petits_arbres_selon_la_rfc(self):
        f = [ar.feuille(bytes([i])) for i in range(3)]
        self.assertEqual(ar.racine_merkle(f[:1]), f[0])
        self.assertEqual(ar.racine_merkle(f[:2]), ar.noeud(f[0], f[1]))
        self.assertEqual(ar.racine_merkle(f), ar.noeud(ar.noeud(f[0], f[1]), f[2]))

    def test_feuille_et_noeud_separes(self):
        """Préfixes 0x00 / 0x01 : un nœud ne peut pas se faire passer pour une feuille."""
        a, b = ar.feuille(b"a"), ar.feuille(b"b")
        self.assertNotEqual(ar.noeud(a, b), ar.feuille(a + b))

    def test_tout_chemin_verifie_et_toute_alteration_echoue(self):
        for n in list(range(1, 34)) + [24]:
            f = [ar.feuille(str(i).encode()) for i in range(n)]
            r = ar.racine_merkle(f)
            for m in range(n):
                c = ar.chemin_merkle(m, f)
                self.assertTrue(ar.verifier_chemin(m, n, f[m], c, r), (n, m))
                self.assertFalse(ar.verifier_chemin(m, n, ar.feuille(b"faux"), c, r))
                if c:
                    self.assertFalse(ar.verifier_chemin(m, n, f[m], c[:-1] + [ar.feuille(b"x")], r))
                if n > 1:
                    self.assertFalse(ar.verifier_chemin((m + 1) % n, n, f[m], c, r))
            self.assertFalse(ar.verifier_chemin(n, n, f[0], [], r))


class TestJourEtAncrage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = Source(Path(self.tmp) / "trackyzz")
        self.conf = {"source": self.src.d, "destination": Path(self.tmp) / "archive", "debut": None, "ntfy_url": None}
        self.dest = self.conf["destination"]
        t0 = T0
        for t in range(t0 + 20, t0 + 86400, 60):
            self.src.cycle(t, n=1)
        self.src.cycle(T0 + 86400 + 20, n=1)
        self.src.tete_du_lendemain(J)

    def tearDown(self):
        shutil.rmtree(self.tmp, onerror=_rendre_modifiable)

    def test_racine_preuves_et_verification(self):
        r = ar.executer(self.conf, now_s=T0 + 86400 + 900, horo=FauxHorodateurs())
        self.assertEqual(r["jours_fermes"], [J])
        racine = (self.dest / "racines" / f"{J}.txt").read_text(encoding="utf-8")
        b = json.loads((self.dest / "jours" / f"{J}.json").read_text(encoding="utf-8"))
        self.assertIn(f"racine {b['merkle']['racine']}\n", racine)
        self.assertIn("concorde avec TRACKYZZ : oui", racine)
        self.assertEqual(len(list((self.dest / "preuves" / J).glob("*.json"))), 24)
        self.assertEqual(ar.verifier(self.conf), (24, []))
        p = ar.prouver(self.conf, "2026-10-15T14:00:00Z")
        self.assertEqual(p["statut"], "preuve valide")
        self.assertIn(f"racines/{J}.txt.ots", p["fichiers"])

    def test_une_heure_alteree_casse_sa_preuve(self):
        ar.executer(self.conf, now_s=T0 + 86400 + 900, horo=FauxHorodateurs())
        mp = ar.manifeste_heure(self.dest, T0 + 14 * 3600)
        os.chmod(mp, stat.S_IWRITE)
        mp.write_bytes(mp.read_bytes().replace(b'"fermeture":"normale"', b'"fermeture":"modifiee"'))
        self.assertEqual(ar.prouver(self.conf, "2026-10-15T14:00:00Z")["statut"], "PREUVE INVALIDE")
        _, problemes = ar.verifier(self.conf)
        self.assertTrue(any("Merkle" in x for x in problemes))

    def test_ancrage_une_fois_puis_complement_bitcoin_dans_un_autre_fichier(self):
        h = FauxHorodateurs()
        ar.executer(self.conf, now_s=T0 + 86400 + 900, horo=h)
        ots = self.dest / "racines" / f"{J}.txt.ots"
        avant = ots.read_bytes()
        self.assertTrue((self.dest / "racines" / f"{J}.txt.tsr").exists())
        ar.executer(self.conf, now_s=T0 + 86400 + 1200, horo=h)
        self.assertEqual([a for a in h.appels if a[0] in ("stamp", "tsa")], [("stamp", f"{J}.txt"), ("tsa", f"{J}.txt")])
        h.bitcoin = True
        ar.executer(self.conf, now_s=T0 + 2 * 86400 + 60, horo=h)       # dans la fenêtre horaire du complément
        self.assertEqual(ots.read_bytes(), avant)                          # .ots d'origine jamais touché
        self.assertEqual((self.dest / "racines" / f"{J}.txt.bitcoin.ots").read_bytes(), avant + b" BITCOIN")

    def test_panne_d_horodatage_n_arrete_rien_et_se_rattrape(self):
        h = FauxHorodateurs(panne=True)
        r = ar.executer(self.conf, now_s=T0 + 86400 + 900, horo=h)
        self.assertEqual(r["jours_fermes"], [J])
        self.assertEqual(r["ancrage"]["ots"], 0)
        self.assertTrue(r["ancrage"]["erreurs"])
        h.panne = False
        r = ar.executer(self.conf, now_s=T0 + 86400 + 1200, horo=h)
        self.assertEqual(r["ancrage"]["ots"], 1)

    def test_sans_horodateur_configure_aucun_appel(self):
        r = ar.executer(self.conf, now_s=T0 + 86400 + 900)           # ots et tsa_url absents de la configuration
        self.assertEqual((r["ancrage"]["ots"], r["ancrage"]["rfc3161"], r["ancrage"]["erreurs"]), (0, 0, []))

    def test_bilan_relu_jamais_refait(self):
        ar.executer(self.conf, now_s=T0 + 86400 + 900, horo=FauxHorodateurs())
        bp = self.dest / "jours" / f"{J}.json"
        avant = bp.read_bytes()
        os.chmod(self.dest / "racines" / f"{J}.txt", stat.S_IWRITE)
        (self.dest / "racines" / f"{J}.txt").unlink()                     # simule un arrêt avant la racine
        r = ar.executer(self.conf, now_s=T0 + 86400 + 5000, horo=FauxHorodateurs())
        self.assertEqual(bp.read_bytes(), avant)
        # le faux collecteur se tait après J+1 00:00:20 : seule l'heure J+1 00h non fermée est signalée
        self.assertEqual(r["incidents"], ["heure_non_fermee"])
        self.assertEqual(ar.verifier(self.conf), (24, []))


class FauxNtfy:
    """Remplace l'envoi réseau : garde les requêtes que l'archiveur aurait envoyées."""

    def __init__(self):
        self.requetes = []

    def __call__(self, req, timeout=None):
        self.requetes.append((req.full_url, json.loads(req.data.decode("utf-8"))))

        class R:
            def close(self):
                pass
        return R()


class TestAlertes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = Source(Path(self.tmp) / "trackyzz")
        self.conf = {"source": self.src.d, "destination": Path(self.tmp) / "archive", "debut": None,
                     "ntfy_url": "https://ntfy.sh/sujet-de-test"}
        self.dest = self.conf["destination"]
        self.ntfy = FauxNtfy()
        vrai = ar.urllib.request.urlopen
        ar.urllib.request.urlopen = self.ntfy
        self.addCleanup(setattr, ar.urllib.request, "urlopen", vrai)

    def tearDown(self):
        shutil.rmtree(self.tmp, onerror=_rendre_modifiable)

    def titres(self):
        return [corps["title"] for _, corps in self.ntfy.requetes]

    def test_format_priorite_maximale_et_titre_rouge(self):
        self.assertTrue(ar.envoyer_ntfy("https://ntfy.sh/sujet-de-test", "essai", "texte"))
        url, corps = self.ntfy.requetes[0]
        self.assertEqual(url, "https://ntfy.sh")
        self.assertEqual((corps["topic"], corps["priority"], corps["message"]), ("sujet-de-test", 5, "texte"))
        self.assertEqual(corps["title"], "\U0001F534 ARCHIVE : essai")

    def test_passage_normal_aucune_alerte(self):
        for t in range(T0 + 20, T0 + 2 * 3600 + 60, 60):
            self.src.cycle(t)
        r = ar.executer(self.conf, now_s=T0 + 2 * 3600 + 300)
        self.assertEqual((r["heures_fermees"], r["incidents"]), (2, []))
        self.assertEqual(self.ntfy.requetes, [])

    def test_heure_non_fermee_signalee_une_seule_fois(self):
        for t in range(T0 + 20, T0 + 3600, 60):
            self.src.cycle(t)                                   # puis le collecteur se tait
        r = ar.executer(self.conf, now_s=T0 + 3600 + 1000)     # 16 min après la fin : pas encore
        self.assertEqual(r["incidents"], [])
        r = ar.executer(self.conf, now_s=T0 + 3600 + 1300)     # 21 min : alerte
        self.assertEqual(r["incidents"], ["heure_non_fermee"])
        r = ar.executer(self.conf, now_s=T0 + 3600 + 1600)     # passage suivant : pas de doublon
        self.assertEqual(r["incidents"], [])
        self.assertEqual(self.titres(), ["\U0001F534 ARCHIVE : heure non fermée"])

    def test_heure_vide_signalee(self):
        for t in range(T0 + 20, T0 + 3600, 60):
            self.src.cycle(t)
        self.src.cycle(T0 + 2 * 3600 + 20)                      # rien pendant 01h, puis reprise
        ar.executer(self.conf, now_s=T0 + 2 * 3600 + 300)
        self.assertIn("\U0001F534 ARCHIVE : heure fermée vide (aucune donnée de TRACKYZZ)", self.titres())

    def test_verification_quotidienne_en_echec_signalee(self):
        for t in range(T0 + 20, T0 + 86400, 60):
            self.src.cycle(t, n=1)
        self.src.cycle(T0 + 86400 + 20, n=1)
        r = ar.executer(self.conf, now_s=T0 + 86400 + 900)      # 24 heures fermées ; le bilan attend la tête
        self.assertEqual(r["jours_fermes"], [])
        f = ar.dossier_heure(self.dest, T0) / "00.registre.jsonl.gz"
        os.chmod(f, stat.S_IWRITE)
        f.write_bytes(gzip.compress(b"altere\n"))
        self.src.tete_du_lendemain(J)
        r = ar.executer(self.conf, now_s=T0 + 86400 + 1200)
        self.assertEqual(r["jours_fermes"], [J])
        self.assertIn("verification_en_echec", r["incidents"])
        self.assertIn("\U0001F534 ARCHIVE : vérification de l'archive en échec", self.titres())

    def test_verification_quotidienne_sans_probleme_silencieuse(self):
        for t in range(T0 + 20, T0 + 86400, 60):
            self.src.cycle(t, n=1)
        self.src.cycle(T0 + 86400 + 20, n=1)
        self.src.tete_du_lendemain(J)
        r = ar.executer(self.conf, now_s=T0 + 86400 + 900, horo=FauxHorodateurs())
        self.assertEqual(r["verification"], {"heures_relues": 24, "problemes": 0})
        self.assertEqual(self.ntfy.requetes, [])

    def test_ancrage_en_echec_signale_une_seule_fois(self):
        for t in range(T0 + 20, T0 + 86400, 60):
            self.src.cycle(t, n=1)
        for t in range(T0 + 86400 + 20, T0 + 86400 + 3 * 3600, 60):
            self.src.cycle(t, n=1)                              # le collecteur continue le lendemain
        self.src.tete_du_lendemain(J)
        h = FauxHorodateurs(panne=True)
        racine = self.dest / "racines" / f"{J}.txt"
        r = ar.executer(self.conf, now_s=T0 + 86400 + 900, horo=h)
        os.utime(racine, (T0 + 86400 + 900, T0 + 86400 + 900))  # date de création simulée
        self.assertNotIn("ancrage_ots_en_echec", r["incidents"])
        r = ar.executer(self.conf, now_s=T0 + 86400 + 9000, horo=h)   # plus de 2 h après : alerte
        self.assertEqual(r["incidents"], ["ancrage_ots_en_echec"])
        r = ar.executer(self.conf, now_s=T0 + 86400 + 9300, horo=h)   # pas de doublon
        self.assertEqual(r["incidents"], [])

    def test_confirmation_bitcoin_absente_apres_48h(self):
        for t in range(T0 + 20, T0 + 86400, 60):
            self.src.cycle(t, n=1)
        self.src.tete_du_lendemain(J)
        h = FauxHorodateurs()
        ar.executer(self.conf, now_s=T0 + 86400 + 4000, horo=h)
        ots = self.dest / "racines" / f"{J}.txt.ots"
        os.utime(ots, (T0 + 86400 + 4000, T0 + 86400 + 4000))
        r = ar.executer(self.conf, now_s=T0 + 86400 + 4000 + 172800 + 400, horo=h)
        self.assertIn("ancrage_bitcoin_en_attente", r["incidents"])

    def test_commande_alerter(self):
        cfg = Path(self.tmp) / "a.conf"
        cfg.write_text("[archiveur]\nntfy_url = https://ntfy.sh/sujet-de-test\n", encoding="utf-8")
        self.assertEqual(ar.main(["alerter", "--config", str(cfg), "--titre", "passage en échec", "--texte", "x"]), 0)
        self.assertEqual(self.titres(), ["\U0001F534 ARCHIVE : passage en échec"])

    def test_sans_adresse_aucun_envoi(self):
        self.conf["ntfy_url"] = None
        for t in range(T0 + 20, T0 + 3600, 60):
            self.src.cycle(t)
        r = ar.executer(self.conf, now_s=T0 + 3600 + 1300)
        self.assertEqual(r["incidents"], ["heure_non_fermee"])     # noté dans incidents.jsonl, sans envoi
        self.assertEqual(self.ntfy.requetes, [])


if __name__ == "__main__":
    unittest.main()
