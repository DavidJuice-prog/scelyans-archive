"""Tests de l'ADN Scelyans v1 sur des données fabriquées (aucun réseau, aucun fichier réel).

    python -m unittest -v test_adn
"""
import gzip, hashlib, json, shutil, tempfile, unittest, unittest.mock
from pathlib import Path

import archiveur as ar
import adn
from test_archiveur import FauxHorodateurs, Source, _rendre_modifiable

J1, J2, J3 = "2026-10-15", "2026-10-16", "2026-10-17"
T1 = ar.secondes(J1 + "T00:00:00Z")
TETE_ASTRA = (f"{'21' * 32}  adn/{J1}.jsonl\n# blocs=11 dernier_index=10 dernier_hash={'83' * 32}\n"
              '# contenu={"prix": 11}\n')


def mth(donnees):
    """Calcul indépendant de la racine (RFC 9162, 2.1.1), écrit sans le code de l'archiveur."""
    if len(donnees) == 1:
        return hashlib.sha256(b"\x00" + donnees[0]).digest()
    k = 1 << ((len(donnees) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + mth(donnees[:k]) + mth(donnees[k:])).digest()


def faux_genes(conf, jour, now_s):
    return {"code": {"statut": "mesure", "adn_py_sha256": "aa" * 32}, "horloge": {"statut": "mesure", "ecart_ms": "0.012"},
            "bloc": {"statut": "mesure", "hauteur": 1, "hash": "bb" * 32},
            "temoin": {"statut": "indisponible", "raison": "test"},
            "astra": {"statut": "mesure", "source": "astra-m", "tete_sha256": "cc" * 32, "blocs": 11,
                      "dernier_hash": "83" * 32}}


def xml_bce(jour, usd="1.0832"):
    """Publication quotidienne de la BCE, au format réel de eurofxref-daily.xml."""
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<gesmes:Envelope xmlns:gesmes="http://www.gesmes.org/xml/2002-08-01" '
            'xmlns="http://www.ecb.int/vocabulary/2002-08-01/eurofxref">\n'
            "\t<gesmes:subject>Reference rates</gesmes:subject>\n"
            "\t<gesmes:Sender>\n\t\t<gesmes:name>European Central Bank</gesmes:name>\n\t</gesmes:Sender>\n"
            f"\t<Cube>\n\t\t<Cube time='{jour}'>\n\t\t\t<Cube currency='USD' rate='{usd}'/>\n"
            "\t\t\t<Cube currency='JPY' rate='164.12'/>\n\t\t</Cube>\n\t</Cube>\n</gesmes:Envelope>\n").encode()


def bce_hors_ligne(*a, **k):
    raise adn.urllib.error.URLError("hors ligne (test)")


class TestADN(unittest.TestCase):
    def setUp(self):
        for nom, faux in (("mesurer_genes", faux_genes), ("lire_bce", bce_hors_ligne)):   # jamais de réseau
            patch = unittest.mock.patch.object(adn, nom, faux)                           # ni de commande système
            patch.start()
            self.addCleanup(patch.stop)
        self.tmp = tempfile.mkdtemp()
        self.src = Source(Path(self.tmp) / "trackyzz")
        (self.src.d / "empreintes").mkdir()
        self.dest = Path(self.tmp) / "archive"
        self.conf = {"source": self.src.d, "destination": self.dest, "debut": None, "ntfy_url": None,
                     "empreintes": self.src.d / "empreintes", "adn_debut": None, "ots": None}

    def tearDown(self):
        shutil.rmtree(self.tmp, onerror=_rendre_modifiable)

    def jours(self, *jours, empreinte=True):
        """Collecte des jours demandés, archive fermée, empreinte TRACKYZZ du jour écrite."""
        for j in jours:
            t0 = ar.secondes(j + "T00:00:00Z")
            for t in range(t0 + 20, t0 + 86400, 300):
                self.src.cycle(t, n=2)
            self.src.cycle(t0 + 86400 + 20, n=1)
            self.src.tete_du_lendemain(j)
            fin = t0 + 86400 + 900
            ar.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
            if empreinte:
                (self.src.d / "empreintes" / f"{j}.txt").write_text(f"trackyzz-empreinte-jour/1\njour {j} (UTC)\n",
                                                                    encoding="utf-8")
        return fin

    def lire(self, j):
        return json.loads(adn.fichier_adn(self.dest, j).read_text(encoding="utf-8"))

    def test_racine_identique_a_un_calcul_independant(self):
        fin = self.jours(J1)
        r = adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        self.assertEqual(r["adn_construits"], [J1])
        a = self.lire(J1)
        donnees = [b"adn/1 veille aucune\n", b"adn/1 empreinte\n" + (self.src.d / "empreintes" / f"{J1}.txt").read_bytes()]
        donnees += [b"adn/1 releve\n" + l for l in (self.src.d / "registre" / f"{J1}.jsonl").read_bytes().splitlines(keepends=True)]
        g = faux_genes(None, J1, 0)
        donnees += [b"adn/1 gene " + n.encode() + b"\n" + json.dumps(g[n], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
                    for n in ("code", "horloge", "bloc", "temoin", "astra")]
        self.assertFalse((self.dest / "trous.jsonl").exists())    # aucun trou : pas de feuille d'incident ici
        self.assertEqual(a["racine"], mth(donnees).hex())
        self.assertEqual(a["feuilles"]["total"], len(donnees))
        self.assertEqual(a["feuilles"]["releves"], 2 * 288)
        self.assertIsNone(a["racine_veille"])
        self.assertEqual(a["racine_archive"], json.loads((self.dest / "jours" / f"{J1}.json").read_text("utf-8"))["merkle"]["racine"])

    def test_chainage_avec_la_veille(self):
        fin = self.jours(J1, J2, J3)
        r = adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        self.assertEqual(r["adn_construits"], [J1, J2, J3])
        a1, a2, a3 = self.lire(J1), self.lire(J2), self.lire(J3)
        self.assertEqual((a2["jour_veille"], a2["racine_veille"]), (J1, a1["racine"]))
        self.assertEqual((a3["jour_veille"], a3["racine_veille"]), (J2, a2["racine"]))
        self.assertEqual(adn.verifier(self.conf), (3, []))

    def test_jour_sans_empreinte_bloque_la_suite_et_alerte_une_fois(self):
        self.jours(J1)
        fin = self.jours(J2, empreinte=False)
        r = adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        self.assertEqual(r["adn_construits"], [J1])
        self.assertEqual(r["incidents"], [])                     # moins de 6 h : on attend sans alerter
        tard = ar.secondes(J2 + "T00:00:00Z") + 86400 + adn.ATTENTE_EMPREINTE_S + 60
        self.assertEqual(adn.executer(self.conf, now_s=tard, horo=FauxHorodateurs())["incidents"], ["adn_empreinte_absente"])
        self.assertEqual(adn.executer(self.conf, now_s=tard + 300, horo=FauxHorodateurs())["incidents"], [])
        self.assertFalse(adn.fichier_adn(self.dest, J2).exists())
        (self.src.d / "empreintes" / f"{J2}.txt").write_text("empreinte arrivée en retard\n", encoding="utf-8")
        self.assertEqual(adn.executer(self.conf, now_s=tard + 600, horo=FauxHorodateurs())["adn_construits"], [J2])
        self.assertEqual(self.lire(J2)["racine_veille"], self.lire(J1)["racine"])

    def test_jour_non_ferme_dans_l_archive_pas_d_adn(self):
        (self.src.d / "empreintes" / f"{J1}.txt").write_text("x\n", encoding="utf-8")
        for t in range(T1 + 20, T1 + 3600 * 5, 300):
            self.src.cycle(t)
        ar.executer(self.conf, now_s=T1 + 3600 * 5, horo=FauxHorodateurs())
        self.assertEqual(adn.executer(self.conf, now_s=T1 + 86400 * 2, horo=FauxHorodateurs())["adn_construits"], [])

    def test_preuve_d_inclusion_valide_et_alterations_refusees(self):
        fin = self.jours(J1)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        a = self.lire(J1)
        premier = json.loads((self.src.d / "registre" / f"{J1}.jsonl").read_text("utf-8").splitlines()[0])["index"]
        for idx in (premier, premier + 1, premier + 300, premier + 575):
            pr = adn.preuve(self.conf, J1, idx)
            self.assertTrue(adn.verifier_preuve(pr, a), idx)
            self.assertEqual(json.loads(pr["releve"])["index"], idx)
        pr = adn.preuve(self.conf, J1, premier + 300)
        faux = dict(pr, releve=pr["releve"].replace("VERIFIED", "VERIFIEE"))
        self.assertFalse(adn.verifier_preuve(faux, a))           # un relevé modifié
        b = pr["releve"].encode()
        self.assertFalse(adn.verifier_preuve(dict(pr, releve=(b[:-2] + bytes([b[-2] ^ 1]) + b[-1:]).decode()), a))
        self.assertFalse(adn.verifier_preuve(dict(pr, position=pr["position"] + 1), a))
        self.assertFalse(adn.verifier_preuve(dict(pr, position=0), a))
        self.assertFalse(adn.verifier_preuve(pr, dict(a, racine="00" * 32)))
        self.assertIsNone(adn.preuve(self.conf, J1, 10 ** 9))

    def test_fichier_publie_sans_releve_ni_prix(self):
        fin = self.jours(J1)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        texte = adn.fichier_adn(self.dest, J1).read_text(encoding="utf-8")
        self.assertEqual(set(json.loads(texte)), {"format", "methode", "algorithme", "jour", "racine", "racine_veille",
                                                   "jour_veille", "feuilles", "incidents_concernent", "ordre_feuilles",
                                                   "empreinte_trackyzz", "racine_archive", "genes"})
        self.assertEqual(set(json.loads(texte)["genes"]), {"code", "horloge", "bloc", "temoin", "astra"})
        for mot in ("collecte", "prev_hash", "VERIFIED", "kraken", "prix", "mediane", "observations", "@"):
            self.assertNotIn(mot, texte)

    def test_relance_sans_effet_et_meme_resultat(self):
        fin = self.jours(J1, J2)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        avant = {p.name: p.read_bytes() for p in (self.dest / "adn").iterdir()}
        r = adn.executer(self.conf, now_s=fin + 300, horo=FauxHorodateurs())
        self.assertEqual(r["adn_construits"], [])
        self.assertEqual({p.name: p.read_bytes() for p in (self.dest / "adn").iterdir()}, avant)
        self.assertFalse(list((self.dest / "adn").glob("*.conflit-*")))

    def test_verification_detecte_une_empreinte_modifiee(self):
        fin = self.jours(J1, J2)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        (self.src.d / "empreintes" / f"{J1}.txt").write_text("autre contenu\n", encoding="utf-8")
        n, problemes = adn.verifier(self.conf)
        self.assertEqual(n, 2)
        self.assertEqual(problemes, [f"adn-{J1}.json : recalcul différent (racine ou comptes)"])

    def test_incidents_ranges_au_jour_constate_avec_le_jour_concerne(self):
        self.jours(J1)
        ar.Journal(self.dest, None, T1 + 3600).incident("jour_discordant", jour=J1)
        ar.Journal(self.dest, None, T1 + 7200).incident("heure_non_fermee", heure="2026-10-14T23:00:00Z")
        adn.executer(self.conf, now_s=T1 + 86400 + 900, horo=FauxHorodateurs())
        a1 = self.lire(J1)
        self.assertEqual((a1["feuilles"]["incidents"], a1["incidents_concernent"]), (2, {J1: 1, "2026-10-14": 1}))
        scelle = adn.fichier_adn(self.dest, J1).read_bytes()
        # constaté le lendemain (J2), il concerne J1 : rangé dans J2, et J1 déjà scellé n'est jamais refait
        ar.Journal(self.dest, None, T1 + 86400 + 3600).incident("ancrage_ots_en_echec", racine=f"{J1}.txt")
        ar.Journal(self.dest, None, T1 + 86400 + 3700).trou("2026-10-09T05:00:00Z", "aucune_ligne_registre")
        fin = self.jours(J2)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        self.assertEqual(adn.fichier_adn(self.dest, J1).read_bytes(), scelle)
        self.assertEqual(self.lire(J2)["incidents_concernent"], {J1: 1, "2026-10-09": 1})
        self.assertEqual(adn.verifier(self.conf), (2, []))
        self.assertEqual(adn.concerne({"racine": "adn-2026-10-03.json"}, J2), "2026-10-03")
        self.assertEqual(adn.concerne({"type": "x"}, J2), J2)

    def test_ancrage_opentimestamps_puis_bitcoin(self):
        fin = self.jours(J1)
        self.conf["ots"] = "ots"
        h = FauxHorodateurs()
        r = adn.executer(self.conf, now_s=fin // 3600 * 3600 + 400, horo=h)
        self.assertEqual((r["ancrage"]["ots"], r["ancrage"]["bitcoin"]), (1, 0))
        self.assertNotIn("tsa", [x[0] for x in h.appels])         # ADN : OpenTimestamps seulement
        h.bitcoin = True
        r = adn.executer(self.conf, now_s=fin // 3600 * 3600 + 3600 + 60, horo=h)
        self.assertEqual((r["ancrage"]["ots"], r["ancrage"]["bitcoin"]), (1, 1))
        self.assertTrue((self.dest / "adn" / f"adn-{J1}.json.bitcoin.ots").exists())

    def test_complement_bitcoin_au_passage_de_la_50e_minute_sans_toucher_json_ni_ots(self):
        """Le minuteur passe à hh:50 : le complément Bitcoin doit y être tenté, et ne peut que CRÉER le .bitcoin.ots.
        Vrai code des horodateurs (copie temporaire), client ots simulé qui écrit dans le fichier qu'on lui donne."""
        fin = self.jours(J1, J2)
        self.conf["ots"] = "ots"
        vus, bitcoin_a_confirme = [], [False]

        def client(cmd):                                        # imite « ots stamp / upgrade / info »
            vus.append(cmd)
            cible = Path(cmd[-1])
            if cmd[1] == "stamp":
                cible.with_name(cible.name + ".ots").write_bytes(b"OTS-ATTENTE")
            elif cmd[1] == "upgrade" and bitcoin_a_confirme[0]:
                cible.write_bytes(cible.read_bytes() + b" BITCOIN")   # le client réécrit SA copie
            out = "BitcoinBlockHeaderAttestation" if cmd[1] == "info" and b"BITCOIN" in cible.read_bytes() else ""
            return type("R", (), {"stdout": out, "returncode": 0})()

        h = ar.Horodateurs(ots="ots")
        h._lancer = client
        a_50 = fin // 3600 * 3600 + 3000                        # 50e minute, comme adn.timer
        adn.executer(self.conf, now_s=a_50, horo=h)            # .ots créés, complément tenté mais pas encore confirmé
        d = self.dest / "adn"
        avant = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in d.iterdir()}
        self.assertEqual(sorted(avant), [f"adn-{J1}.json", f"adn-{J1}.json.ots", f"adn-{J2}.json", f"adn-{J2}.json.ots",
                                         f"feuilles-{J1}.txt.gz", f"feuilles-{J2}.txt.gz"])
        self.assertTrue(all(cmd[-1] not in (str(d / n) for n in avant) for cmd in vus))   # jamais les vrais fichiers
        self.assertIn("upgrade", [c[1] for c in vus])           # le complément a bien été tenté à hh:50
        bitcoin_a_confirme[0] = True
        r = adn.executer(self.conf, now_s=a_50 + 3600, horo=h)  # passage suivant, à nouveau hh:50
        self.assertEqual(r["ancrage"]["bitcoin"], 2)
        apres = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in d.iterdir()}
        nouveaux = sorted(set(apres) - set(avant))
        self.assertEqual(nouveaux, [f"adn-{J1}.json.bitcoin.ots", f"adn-{J2}.json.bitcoin.ots"])
        for n in avant:                                         # .json et .ots : octets, date et droits inchangés
            self.assertEqual(apres[n], avant[n], n)
        self.assertEqual(apres[f"adn-{J1}.json.bitcoin.ots"][0], b"OTS-ATTENTE BITCOIN")
        # passages suivants : plus rien n'est créé ni touché
        adn.executer(self.conf, now_s=a_50 + 7200, horo=h)
        self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in d.iterdir()},
                         {n: v[:2] for n, v in apres.items()})
        self.assertEqual(adn.verifier(self.conf), (2, []))

    def test_archive_existante_inchangee(self):
        fin = self.jours(J1)
        avant = {str(p): p.read_bytes() for p in self.dest.rglob("*") if p.is_file()}
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        apres = {str(p): p.read_bytes() for p in self.dest.rglob("*") if p.is_file() and "adn" not in p.parts}
        self.assertEqual(apres, avant)
        self.assertEqual(ar.verifier(self.conf)[1], [])


class TestGenes(unittest.TestCase):
    """Chaque gène et son repli, sans réseau ni commande système."""

    def test_code_empreint_les_deux_fichiers(self):
        g = adn.gene_code()
        ici = Path(adn.__file__).parent
        self.assertEqual(g["adn_py_sha256"], hashlib.sha256((ici / "adn.py").read_bytes()).hexdigest())
        self.assertEqual(g["archiveur_py_sha256"], hashlib.sha256((ici / "archiveur.py").read_bytes()).hexdigest())
        self.assertEqual(g["version_archiveur"], ar.VERSION)

    def test_horloge_chrony_timesyncd_et_repli(self):
        chrony = "Reference ID : X\nSystem time     : 0.000012345 seconds slow of NTP time\n"
        g = adn.gene_horloge(T1, lancer=lambda c: chrony)
        self.assertEqual((g["source"], g["ecart_ms"]), ("chrony", "-0.012"))

        def seulement_timesyncd(c):
            if c[0] == "chronyc":
                raise FileNotFoundError
            return "       Offset: +1.500ms\n"
        g = adn.gene_horloge(T1, lancer=seulement_timesyncd)
        self.assertEqual((g["source"], g["ecart_ms"]), ("timesyncd", "1.500"))

        def rien(c):
            raise FileNotFoundError
        self.assertEqual(adn.gene_horloge(T1, lancer=rien)["statut"], "indisponible")

    def test_bloc_dernier_avant_minuit_et_repli(self):
        fin = ar.secondes(J1 + "T00:00:00Z") + 86400
        blocs = {"h100": {"id": "h100", "height": 100, "timestamp": fin - 500, "previousblockhash": "h99"},
                 "h99": {"id": "h99", "height": 99, "timestamp": fin - 1100, "previousblockhash": "h98"},
                 "h101": {"id": "h101", "height": 101, "timestamp": fin + 200, "previousblockhash": "h100"}}

        def get(url):
            if "/mining/blocks/timestamp/" in url:
                return {"height": 101, "hash": "h101"}          # l'API renvoie ici un bloc trop tard : on recule
            if "/v1/blocks/" in url:                            # route JSON : le premier élément est la hauteur demandée
                n = int(url.rsplit("/", 1)[1])
                return [b for b in blocs.values() if b["height"] == n]
            return blocs[url.rsplit("/", 1)[1]]
        g = adn.gene_bloc(J1, get=get)
        self.assertEqual((g["statut"], g["hauteur"], g["hash"]), ("mesure", 100, "h100"))

        def panne(url):
            raise OSError("injoignable")
        self.assertEqual(adn.gene_bloc(J1, get=panne)["statut"], "indisponible")

    def _blocs_non_monotones(self):
        """Cas du 11/10/2026 : le bloc 971004 (23:55:44) précède 971005 (23:53:12), puis 971006 passe minuit."""
        fin = ar.secondes(J1 + "T00:00:00Z") + 86400
        return {"h4": {"id": "h4", "height": 4, "timestamp": fin - 256, "previousblockhash": "h3"},
                "h5": {"id": "h5", "height": 5, "timestamp": fin - 408, "previousblockhash": "h4"},
                "h6": {"id": "h6", "height": 6, "timestamp": fin + 299, "previousblockhash": "h5"}}

    def test_bloc_horodatages_non_monotones_retient_la_plus_haute_hauteur(self):
        blocs = self._blocs_non_monotones()

        def get(url):
            if "/mining/blocks/timestamp/" in url:
                return {"height": 4, "hash": "h4"}              # l'API renvoie le bloc à l'heure la plus tardive
            if "/v1/blocks/" in url:
                n = int(url.rsplit("/", 1)[1])
                return [b for b in blocs.values() if b["height"] == n]
            return blocs[url.rsplit("/", 1)[1]]
        g = adn.gene_bloc(J1, get=get)
        self.assertEqual((g["statut"], g["hauteur"], g["hash"]), ("mesure", 5, "h5"))

    def test_bloc_avec_le_vrai_http_json_sur_les_formats_reels_de_mempool(self):
        """Le faux `get` des autres tests masquait un bug : /block-height/ renvoie un hash en texte brut, que http_json
        (qui décode du JSON) ne sait pas lire, si bien que la boucle n'avançait jamais. Ici les réponses HTTP sont
        fabriquées dans leurs formats réels et c'est le vrai http_json qui les lit."""
        blocs = self._blocs_non_monotones()

        class Reponse:
            def __init__(self, corps):
                self.corps = corps

            def read(self, *a):
                return self.corps

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def urlopen(req, timeout=None):
            url = req.full_url
            if "/mining/blocks/timestamp/" in url:
                corps = json.dumps({"height": 4, "hash": "h4"})
            elif "/v1/blocks/" in url:                          # jusqu'à 15 blocs, du plus haut au plus bas
                n = int(url.rsplit("/", 1)[1])
                corps = json.dumps(sorted((b for b in blocs.values() if b["height"] <= n),
                                          key=lambda b: -b["height"]))
            elif "/block-height/" in url:                       # texte brut, pas du JSON
                n = int(url.rsplit("/", 1)[1])
                corps = next(b["id"] for b in blocs.values() if b["height"] == n)
            else:
                corps = json.dumps(blocs[url.rsplit("/", 1)[1]])
            return Reponse(corps.encode())
        with unittest.mock.patch.object(adn.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(adn.time, "sleep"):
            g = adn.gene_bloc(J1)
        self.assertEqual((g["statut"], g["hauteur"], g["hash"]), ("mesure", 5, "h5"))

    def test_temoin_present_absent_ou_illisible(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(adn.gene_temoin({}, J1)["statut"], "indisponible")
            self.assertEqual(adn.gene_temoin({"temoin": d}, J1)["statut"], "indisponible")
            (Path(d) / f"{J1}.json").write_text('{"concordance_pct": "99.874"}', encoding="utf-8")
            self.assertEqual(adn.gene_temoin({"temoin": d}, J1)["concordance_pct"], "99.87")
            (Path(d) / f"{J1}.json").write_text('{"concordance_pct": "140"}', encoding="utf-8")
            self.assertEqual(adn.gene_temoin({"temoin": d}, J1)["statut"], "indisponible")

    def test_astra_present_absent_ou_illisible(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(adn.gene_astra({}, J1)["raison"], "aucun dossier ASTRA configuré")
            self.assertEqual(adn.gene_astra({"astra": d}, J1)["raison"], "aucune tête ASTRA ce jour-là")
            f = Path(d) / f"{J1}.txt"
            f.write_bytes(TETE_ASTRA.encode("utf-8"))
            g = adn.gene_astra({"astra": d}, J1)
            self.assertEqual((g["statut"], g["fichier_sha256"], g["blocs"], g["dernier_index"], g["dernier_hash"]),
                             ("mesure", "21" * 32, 11, 10, "83" * 32))
            self.assertNotIn("contenu", json.dumps(g))                       # la ligne des types n'est pas recopiée
            self.assertEqual(g["tete_sha256"], hashlib.sha256(f.read_bytes()).hexdigest())
            f.write_bytes(TETE_ASTRA.replace("\n", "\r\n").encode("utf-8"))   # tête écrite sous Windows
            self.assertEqual(adn.gene_astra({"astra": d}, J1)["blocs"], 11)
            f.write_text(TETE_ASTRA.replace(J1, J2), encoding="utf-8")      # tête d'un autre jour
            self.assertEqual(adn.gene_astra({"astra": d}, J1)["statut"], "indisponible")
            f.write_bytes(b"x" * 5000)
            self.assertEqual(adn.gene_astra({"astra": d}, J1)["statut"], "indisponible")


def ligne(**b):
    return (json.dumps(b, sort_keys=True) + "\n").encode()


def releves_avec_incidents():
    """Un jour réel en miniature : un tour par minute (bloc écrit 140 s après la fin de sa minute), oracles toutes les
    5 minutes ; tours coupés à 09:08-09:09 et 13:00 (comme les 10/10 et 13/10/2026), minute 09:06 rattrapée en retard."""
    out = []
    for t in range(T1 + 20, T1 + 86400, 60):
        m = t // 60 * 60
        if ar.iso(m)[11:16] in ("09:08", "09:09", "13:00"):
            continue
        out.append(ligne(format="trackyzz-multi-exchanges/1", collecte=ar.iso(t), open_time=ar.iso(m - 180),
                         close_time=ar.iso(m - 120)))
        if ar.iso(m)[11:16] == "09:10":
            out.append(ligne(format="trackyzz-multi-exchanges/1", collecte=ar.iso(t), open_time=ar.iso(m - 240),
                             close_time=ar.iso(m - 180)))
        if m % 300 == 0:
            out.append(ligne(format="trackyzz-oracles/1", collecte=ar.iso(t), open_time=ar.iso(m)))
    return out


class TestGeneTours(unittest.TestCase):
    def test_tours_manquants_retards_et_oracles_perdus(self):
        g = adn.gene_tours({}, J1, releves_avec_incidents())
        self.assertEqual((g["statut"], g["minutes_sans_bloc"], g["plages_sans_bloc"]), ("mesure", 3, ["09:08-09:09", "13:00"]))
        self.assertEqual((g["minutes_en_retard"], g["plages_en_retard"], g["retard_max_s"]), (1, ["09:06"], 200))
        self.assertEqual((g["oracles_perdus"], g["creneaux_oracles_perdus"]), (1, ["13:00"]))
        texte = ar.json_canonique(g).decode()
        for mot in ("collecte", "prev_hash", "VERIFIED", "kraken", "prix", "mediane", "observations", "@"):
            self.assertNotIn(mot, texte)                       # même règle que le fichier publié

    def test_jour_sans_incident(self):
        lignes = [l for l in releves_avec_incidents()]
        t = T1 + 9 * 3600 + 8 * 60 + 20
        for k in (0, 1):                                       # les deux tours de 09:08 et 09:09, à l'heure
            lignes.append(ligne(format="trackyzz-multi-exchanges/1", collecte=ar.iso(t + 60 * k),
                                open_time=ar.iso(t - 20 + 60 * k - 180), close_time=ar.iso(t - 20 + 60 * k - 120)))
        en_retard = {"collecte": "2026-10-15T09:10:20Z", "open_time": "2026-10-15T09:06:00Z"}
        lignes = [l for l in lignes if en_retard.items() - json.loads(l).items()]     # minute 09:06 : plus de retard
        lignes.append(ligne(format="trackyzz-multi-exchanges/1", collecte=ar.iso(T1 + 13 * 3600 + 20),
                            open_time=ar.iso(T1 + 13 * 3600 - 180), close_time=ar.iso(T1 + 13 * 3600 - 120)))
        lignes.append(ligne(format="trackyzz-oracles/1", collecte=ar.iso(T1 + 13 * 3600 + 80),
                            open_time=ar.iso(T1 + 13 * 3600 + 60)))   # lecture refaite à 13:01 : créneau couvert
        g = adn.gene_tours({}, J1, lignes)
        self.assertEqual((g["minutes_sans_bloc"], g["minutes_en_retard"], g["oracles_perdus"]), (0, 0, 0))
        self.assertEqual((g["plages_sans_bloc"], g["plages_en_retard"], g["creneaux_oracles_perdus"]), ([], [], []))

    def test_releves_illisibles_ou_archive_absente(self):
        self.assertEqual(adn.gene_tours({}, J1, [b"pas du json\n"])["statut"], "indisponible")
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(adn.gene_tours({"destination": Path(d)}, J1)["statut"], "indisponible")

    def test_mesurer_genes_contient_tours_et_bce(self):
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.object(adn, "gene_bloc", lambda j: adn.indisponible("test")), \
                unittest.mock.patch.object(adn, "gene_horloge", lambda n: adn.indisponible("test")), \
                unittest.mock.patch.object(adn, "lire_bce", bce_hors_ligne):
            g = adn.mesurer_genes({"destination": Path(d)}, J1, T1)
        self.assertEqual(adn.noms_genes(g), ["code", "horloge", "bloc", "temoin", "astra", "tours", "bce"])


class TestGenesDansADN(TestADN):
    def avec_tours(self, conf, j, n):
        return {**faux_genes(conf, j, n), "tours": adn.gene_tours(conf, j)}

    def test_gene_tours_scelle_dans_l_adn_du_jour_et_recalcule(self):
        fin = self.jours(J1)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=self.avec_tours)
        a = self.lire(J1)
        t = a["genes"]["tours"]
        self.assertEqual((t["minutes_sans_bloc"], t["oracles_perdus"]), (1440 - 288, 288))   # un tour toutes les 5 min
        self.assertEqual(a["feuilles"]["genes"], 6)
        self.assertIn("astra, tours :", a["ordre_feuilles"])
        texte = adn.fichier_adn(self.dest, J1).read_text(encoding="utf-8")
        for mot in ("collecte", "prev_hash", "VERIFIED", "kraken", "prix", "mediane", "observations", "@"):
            self.assertNotIn(mot, texte)
        self.assertEqual(adn.verifier(self.conf), (1, []))
        p = adn.fichier_adn(self.dest, J1)
        p.chmod(0o666)
        p.write_text(texte.replace('"oracles_perdus":288', '"oracles_perdus":0'), encoding="utf-8")
        self.assertEqual(adn.verifier(self.conf)[1], [f"adn-{J1}.json : recalcul différent (racine ou comptes)"])

    def test_gene_tours_faux_mais_bien_scelle_detecte(self):
        """Racine cohérente avec un gène tours inventé : seul le recalcul depuis les relevés peut le voir."""
        faux = lambda c, j, n: {**faux_genes(c, j, n), "tours": {"statut": "mesure", "minutes_sans_bloc": 0}}
        fin = self.jours(J1)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=faux)
        self.assertEqual(adn.verifier(self.conf)[1], [f"adn-{J1}.json : gène tours différent du recalcul depuis les relevés"])

    def test_adn_scelle_avant_le_gene_tours_reste_valide(self):
        fin = self.jours(J1, J2)
        adn.executer(self.conf, now_s=ar.secondes(J1 + "T00:00:00Z") + 86400 + 900, horo=FauxHorodateurs())
        self.assertEqual(self.lire(J1)["feuilles"]["genes"], 5)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=self.avec_tours)
        self.assertEqual(self.lire(J2)["feuilles"]["genes"], 6)
        self.assertEqual(adn.verifier(self.conf), (2, []))

    def test_adn_produit_meme_si_tout_est_indisponible(self):
        indispo = lambda conf, j, n: {k: adn.indisponible("panne") for k in adn.NOMS_GENES}
        fin = self.jours(J1)
        r = adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=indispo)
        self.assertEqual(r["adn_construits"], [J1])
        self.assertEqual(self.lire(J1)["feuilles"]["genes"], len(adn.NOMS_GENES))
        self.assertEqual(adn.verifier(self.conf), (1, []))

    def test_ancien_adn_sans_genes_valide_et_gene_modifie_detecte(self):
        fin = self.jours(J1, J2)
        adn.executer(self.conf, now_s=ar.secondes(J1 + "T00:00:00Z") + 86400 + 900, horo=FauxHorodateurs(),
                     genes=lambda *a: None)                     # J1 scellé « à l'ancienne », sans gènes
        self.assertNotIn("genes", self.lire(J1))
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        self.assertIn("genes", self.lire(J2))
        self.assertEqual(adn.verifier(self.conf), (2, []))
        p = adn.fichier_adn(self.dest, J2)
        p.chmod(0o666)
        p.write_text(p.read_text("utf-8").replace('"hauteur":1', '"hauteur":2'), encoding="utf-8")
        self.assertEqual(adn.verifier(self.conf)[1], [f"adn-{J2}.json : recalcul différent (racine ou comptes)"])

    def test_tete_astra_scellee_et_modification_detectee(self):
        fin = self.jours(J1)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        self.assertEqual(self.lire(J1)["genes"]["astra"]["blocs"], 11)
        self.assertIn("temoin, astra :", self.lire(J1)["ordre_feuilles"])
        p = adn.fichier_adn(self.dest, J1)
        p.chmod(0o666)
        p.write_text(p.read_text("utf-8").replace('"blocs":11', '"blocs":12'), encoding="utf-8")
        self.assertEqual(adn.verifier(self.conf)[1], [f"adn-{J1}.json : recalcul différent (racine ou comptes)"])

    def test_adn_scelle_avant_le_gene_astra_reste_valide(self):
        quatre = lambda *a: {k: v for k, v in faux_genes(*a).items() if k != "astra"}
        fin = self.jours(J1, J2)
        adn.executer(self.conf, now_s=ar.secondes(J1 + "T00:00:00Z") + 86400 + 900, horo=FauxHorodateurs(), genes=quatre)
        a = self.lire(J1)
        self.assertEqual((a["feuilles"]["genes"], set(a["genes"])), (4, {"code", "horloge", "bloc", "temoin"}))
        self.assertIn("genes (code, horloge, bloc, temoin : ", a["ordre_feuilles"])   # texte d'avant, inchangé
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        self.assertEqual(self.lire(J2)["feuilles"]["genes"], 5)
        self.assertEqual(adn.verifier(self.conf), (2, []))

    def test_attend_la_tete_astra_9_h_puis_scelle_sans_elle(self):
        absente = lambda *a: {**faux_genes(*a), "astra": adn.indisponible("aucune tête ASTRA ce jour-là")}
        fin = self.jours(J1)
        self.conf["astra"] = "https://trackyzz.com/astra/tetes"
        minuit = T1 + 86400
        r = adn.executer(self.conf, now_s=minuit + 8 * 3600, horo=FauxHorodateurs(), genes=absente)
        self.assertEqual(r["adn_construits"], [])                  # le PC n'a pas encore publié : on attend
        r = adn.executer(self.conf, now_s=minuit + 8 * 3600, horo=FauxHorodateurs())
        self.assertEqual(r["adn_construits"], [J1])                # publiée : scellée avec la tête
        shutil.rmtree(self.dest / "adn", onerror=_rendre_modifiable)
        r = adn.executer(self.conf, now_s=minuit + 9 * 3600, horo=FauxHorodateurs(), genes=absente)
        self.assertEqual(r["adn_construits"], [J1])                # PC éteint : scellé sans elle après 9 h
        self.assertEqual(self.lire(J1)["genes"]["astra"]["statut"], "indisponible")
        del self.conf["astra"]
        shutil.rmtree(self.dest / "adn", onerror=_rendre_modifiable)
        self.assertEqual(adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=absente)["adn_construits"],
                         [J1])                                      # aucune source configurée : jamais d'attente

    def test_tete_astra_lue_sur_la_route_publique(self):
        vues = []
        class Reponse:
            def __init__(self, url): self.url = url
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return TETE_ASTRA.encode("utf-8")
        def ouvrir(req, timeout):
            vues.append(req.full_url)
            if J2 in req.full_url:
                raise adn.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            return Reponse(req.full_url)
        with unittest.mock.patch.object(adn.urllib.request, "urlopen", ouvrir):
            self.assertEqual(adn.gene_astra({"astra": "https://trackyzz.com/astra/tetes/"}, J1)["blocs"], 11)
            self.assertEqual(adn.gene_astra({"astra": "https://trackyzz.com/astra/tetes"}, J2)["raison"],
                             "aucune tête ASTRA ce jour-là")
        self.assertEqual(vues, [f"https://trackyzz.com/astra/tetes/{J1}.txt", f"https://trackyzz.com/astra/tetes/{J2}.txt"])

    def test_mesure_seulement_quand_le_jour_est_pret(self):
        appels = []
        fin = self.jours(J1, empreinte=False)
        adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=lambda *a: appels.append(a))
        self.assertEqual(appels, [])


J_SAMEDI = "2026-10-17"
assert adn.week_end(J_SAMEDI) and not adn.week_end(J1) and not adn.week_end(J2)


def jamais_lu(*a, **k):
    raise AssertionError("la BCE ne doit pas être interrogée")


class TestGeneBce(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, onerror=_rendre_modifiable)
        self.dest = Path(self.tmp)
        self.conf = {"destination": self.dest, "ntfy_url": None}

    def test_jour_normal_fichier_conserve_tel_quel(self):
        b = xml_bce(J1)
        g = adn.gene_bce(self.conf, J1, T1 + 86400 + 900, lire=lambda: b)
        self.assertEqual((g["statut"], g["version"], g["date_publication"], g["eur_usd"]), ("mesure", "bce/1", J1, "1.0832"))
        self.assertEqual(adn.fichier_bce(self.dest, J1).read_bytes(), b)                   # octets bruts
        self.assertEqual(g["fichier_sha256"], hashlib.sha256(b).hexdigest())
        self.assertEqual((g["fichier"], g["source"]), (f"bce/bce-{J1}.xml", adn.URL_BCE))
        self.assertEqual(adn.gene_bce(self.conf, J1, T1 + 86400 + 900, lire=jamais_lu), g)   # déjà conservé : relu

    def test_week_end_sans_publication_ni_lecture(self):
        g = adn.gene_bce(self.conf, J_SAMEDI, T1 + 3 * 86400, lire=jamais_lu)
        self.assertEqual(g, {"statut": "sans_publication", "version": "bce/1", "raison": "week-end : la BCE ne publie pas"})
        self.assertFalse((self.dest / "bce").exists())

    def test_jour_ferie_jamais_le_taux_de_la_veille(self):
        g = adn.gene_bce(self.conf, J2, T1 + 2 * 86400, lire=lambda: xml_bce(J1))    # le fichier du jour est encore J1
        self.assertEqual(g["statut"], "sans_publication")
        self.assertIn(f"dernière : {J1}", g["raison"])
        self.assertNotIn("eur_usd", g)
        self.assertFalse(adn.fichier_bce(self.dest, J2).exists())
        self.assertEqual(adn.fichier_bce(self.dest, J1).read_bytes(), xml_bce(J1))   # gardé sous sa propre date

    def test_echec_reseau(self):
        g = adn.gene_bce(self.conf, J1, T1 + 86400 + 900, lire=bce_hors_ligne)
        self.assertEqual((g["statut"], g["raison"]), ("indisponible", "échec réseau BCE : URLError"))
        self.assertFalse((self.dest / "bce").exists())

    def test_jamais_enregistre_sous_une_mauvaise_date(self):
        g = adn.gene_bce(self.conf, J1, T1 + 2 * 86400, lire=lambda: xml_bce(J2))    # déjà la publication du lendemain
        self.assertEqual(g["statut"], "indisponible")
        self.assertFalse((self.dest / "bce").exists())

    def test_fichiers_refuses(self):
        for faux in (b"<!DOCTYPE x [<!ENTITY a 'b'>]>" + xml_bce(J1), xml_bce(J1).replace(b"USD", b"GBP"),
                     xml_bce(J1).replace(b"1.0832", b"un"), b"pas du xml", xml_bce(J1) * 2, b" " * 70000 + xml_bce(J1)):
            with self.assertRaises(ValueError):
                adn.analyser_bce(faux)
            self.assertEqual(adn.gene_bce(self.conf, J1, T1, lire=lambda: faux)["statut"], "indisponible")
        self.assertFalse((self.dest / "bce").exists())

    def test_recuperation_horaire_apres_la_publication(self):
        vues = []
        lire = lambda: vues.append(1) or xml_bce(J1)
        journal = ar.Journal(self.dest)
        self.assertIsNone(adn.recuperer_bce(self.conf, T1 + 14 * 3600 + 3000, journal, lire))   # 14:50 UTC : trop tôt
        self.assertEqual(adn.recuperer_bce(self.conf, T1 + 15 * 3600 + 3000, journal, lire), J1)
        self.assertIsNone(adn.recuperer_bce(self.conf, T1 + 16 * 3600 + 3000, journal, lire))   # déjà conservé
        self.assertEqual(len(vues), 1)                                                           # une lecture par jour
        self.assertIsNone(adn.recuperer_bce(self.conf, T1 + 2 * 86400 + 16 * 3600, journal, jamais_lu))   # samedi
        self.assertIn("URLError", adn.recuperer_bce(self.conf, T1 + 86400 + 16 * 3600, journal, bce_hors_ligne))
        pas_encore = adn.recuperer_bce(self.conf, T1 + 86400 + 15 * 3600 + 3000, journal, lambda: xml_bce(J1))
        self.assertEqual(pas_encore, J1)                                    # BCE en retard : rien sous la date de J2
        self.assertFalse(adn.fichier_bce(self.dest, J2).exists())

    def test_essais_courts(self):
        delais = []
        def ouvrir(req, timeout):
            delais.append(timeout)
            raise adn.urllib.error.URLError("hors ligne (test)")
        with unittest.mock.patch.object(adn.urllib.request, "urlopen", ouvrir), \
                unittest.mock.patch.object(adn.time, "sleep", lambda s: None):
            with self.assertRaises(adn.urllib.error.URLError):
                adn.lire_bce()
        self.assertEqual(delais, [10, 10, 10])                              # 10 s au plus par essai


class TestGeneBceDansADN(TestADN):
    def avec_bce(self, conf, j, n):
        return {**faux_genes(conf, j, n), "tours": adn.gene_tours(conf, j), "bce": adn.gene_bce(conf, j, n)}

    def test_jour_normal_scelle_et_verifie_puis_fichier_modifie_detecte(self):
        fin = self.jours(J1)
        with unittest.mock.patch.object(adn, "lire_bce", lambda: xml_bce(J1)):
            adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=self.avec_bce)
        a = self.lire(J1)
        self.assertEqual((a["genes"]["bce"]["eur_usd"], a["feuilles"]["genes"]), ("1.0832", 7))
        self.assertIn("tours, bce :", a["ordre_feuilles"])
        self.assertTrue(adn.fichier_feuilles(self.dest, J1).exists())
        self.assertEqual(adn.verifier(self.conf), (1, []))
        p = adn.fichier_bce(self.dest, J1)
        p.chmod(0o666)
        p.write_bytes(xml_bce(J1, usd="1.0833"))
        self.assertEqual(adn.verifier(self.conf)[1], [f"adn-{J1}.json : fichier BCE modifié (empreinte différente du gène bce)"])
        p.unlink()
        self.assertEqual(adn.verifier(self.conf)[1], [f"adn-{J1}.json : fichier BCE conservé introuvable"])

    def test_echec_reseau_adn_scelle_quand_meme(self):
        fin = self.jours(J1)
        r = adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=self.avec_bce)
        self.assertEqual(r["adn_construits"], [J1])
        self.assertEqual(self.lire(J1)["genes"]["bce"]["statut"], "indisponible")
        self.assertEqual(adn.verifier(self.conf), (1, []))

    def test_adn_scelle_avant_le_gene_bce_reste_valide(self):
        avec_tours = lambda c, j, n: {**faux_genes(c, j, n), "tours": adn.gene_tours(c, j)}   # comme le 28/10/2026
        fin = self.jours(J1, J2)
        adn.executer(self.conf, now_s=T1 + 86400 + 900, horo=FauxHorodateurs(), genes=avec_tours)
        avant = adn.fichier_adn(self.dest, J1).read_bytes()
        a = self.lire(J1)
        self.assertNotIn("bce", a["genes"])
        self.assertTrue(a["ordre_feuilles"].endswith("(code, horloge, bloc, temoin, astra, tours : « adn/1 gene <nom> » "
                                                      "puis la valeur JSON canonique)"))     # texte d'avant, inchangé
        with unittest.mock.patch.object(adn, "lire_bce", lambda: xml_bce(J2)):
            adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=self.avec_bce)
        self.assertEqual(self.lire(J2)["genes"]["bce"]["statut"], "mesure")
        self.assertEqual(adn.verifier(self.conf), (2, []))
        self.assertEqual(adn.fichier_adn(self.dest, J1).read_bytes(), avant)


def racine_depuis_empreintes(h):
    """Racine RFC 9162 depuis les empreintes de feuilles déjà calculées, écrite sans le code de l'archiveur."""
    if len(h) == 1:
        return h[0]
    k = 1 << ((len(h) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + racine_depuis_empreintes(h[:k]) + racine_depuis_empreintes(h[k:])).digest()


class TestFeuillesPubliees(TestADN):
    def sceller(self, *jours):
        fin = self.jours(*jours)
        r = adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        return r

    def texte(self, j):
        return gzip.decompress(adn.fichier_feuilles(self.dest, j).read_bytes())

    def test_un_tiers_retrouve_la_racine_avec_les_seuls_fichiers_publies(self):
        r = self.sceller(J1, J2)
        self.assertEqual(r["feuilles_publiees"], [J1, J2])
        for j in (J1, J2):
            a, t = self.lire(j), self.texte(j)
            emp = (self.src.d / "empreintes" / f"{j}.txt").read_bytes()
            self.assertEqual(adn.verifier_feuilles(t, a, emp), [])
            lignes = t.decode("ascii").splitlines()
            self.assertEqual(len(lignes), 4 + a["feuilles"]["total"])
            h = [bytes.fromhex(l.rsplit(" ", 1)[1]) for l in lignes[4:]]
            self.assertEqual(racine_depuis_empreintes(h).hex(), a["racine"])       # calcul indépendant
            self.assertEqual(sum(l.split()[1] == "releve" for l in lignes[4:]), a["feuilles"]["releves"])
            self.assertEqual(adn.fichier_feuilles(self.dest, j).read_bytes(), gzip.compress(t, mtime=0))   # reproductible
        self.assertEqual(adn.verifier(self.conf), (2, []))

    def test_aucun_releve_ni_prix_dans_le_fichier(self):
        self.sceller(J1)
        t = self.texte(J1).decode("ascii")
        for l in t.splitlines()[4:]:
            self.assertRegex(l, adn.LIGNE_FEUILLE)
        for mot in ("collecte", "prev_hash", "VERIFIED", "kraken", "prix", "mediane", "observations", "@", "{"):
            self.assertNotIn(mot, t)
        self.assertIn(" releve 00 ", t)
        self.assertIn(" releve 23 ", t)

    def test_alterations_detectees_par_le_tiers(self):
        self.sceller(J1)
        a, t = self.lire(J1), self.texte(J1).decode("ascii")
        lignes = t.splitlines()
        k = 10
        h = lignes[k].rsplit(" ", 1)[1]
        faux = lignes[:k] + [lignes[k][:-64] + ("0" if h[0] != "0" else "1") + h[1:]] + lignes[k + 1:]
        self.assertIn("racine recalculée différente de la racine de l'ADN",
                      adn.verifier_feuilles(("\n".join(faux) + "\n").encode(), a))
        inverse = lignes[:k] + [lignes[k + 1], lignes[k]] + lignes[k + 2:]
        self.assertEqual(adn.verifier_feuilles(("\n".join(inverse) + "\n").encode(), a), [f"ligne {k + 1} illisible ou hors d'ordre"])
        self.assertIn("feuille empreinte différente du fichier d'empreinte TRACKYZZ fourni",
                      adn.verifier_feuilles(t.encode(), a, b"autre empreinte\n"))
        g = json.loads(json.dumps(a))
        g["genes"]["bloc"]["hauteur"] = 2                       # valeur publiée modifiée, racine inchangée
        self.assertEqual(adn.verifier_feuilles(t.encode(), g), ["feuille gene bloc différente de la valeur publiée dans l'ADN"])
        self.assertIn("feuille veille différente de racine_veille",
                      adn.verifier_feuilles(t.encode(), dict(a, racine_veille="ab" * 32)))
        self.assertEqual(len(adn.verifier_feuilles(t.encode(), dict(a, racine="00" * 32))), 1)    # en-tête refusé

    def test_anciens_adn_recoivent_leurs_feuilles_une_seule_fois(self):
        fin = self.jours(J1, J2)
        with unittest.mock.patch.object(adn, "ecrire_feuilles", lambda c, j: []):
            adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())     # scellés avant cette version
        self.assertFalse(adn.fichier_feuilles(self.dest, J1).exists())
        self.assertEqual(adn.executer(self.conf, now_s=fin + 3600, horo=FauxHorodateurs())["feuilles_publiees"], [J1, J2])
        self.assertEqual(adn.executer(self.conf, now_s=fin + 7200, horo=FauxHorodateurs())["feuilles_publiees"], [])
        self.assertEqual(adn.verifier(self.conf), (2, []))

    def test_jamais_de_fichier_qui_ne_redonne_pas_la_racine(self):
        fin = self.jours(J1)
        with unittest.mock.patch.object(adn, "ecrire_feuilles", lambda c, j: []):
            adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs())
        (self.src.d / "empreintes" / f"{J1}.txt").write_text("autre contenu\n", encoding="utf-8")
        r = adn.executer(self.conf, now_s=fin + 3600, horo=FauxHorodateurs())
        self.assertEqual((r["feuilles_publiees"], r["incidents"]), ([], ["adn_feuilles_incoherentes"]))
        self.assertFalse(adn.fichier_feuilles(self.dest, J1).exists())
        self.assertEqual(adn.executer(self.conf, now_s=fin + 7200, horo=FauxHorodateurs())["incidents"], [])  # une fois

    def test_verification_detecte_un_fichier_de_feuilles_modifie(self):
        self.sceller(J1)
        f = adn.fichier_feuilles(self.dest, J1)
        t = self.texte(J1)
        f.chmod(0o666)
        f.write_bytes(gzip.compress(t.replace(b" releve 00 ", b" releve 01 ", 1), mtime=0))
        self.assertEqual(adn.verifier(self.conf)[1], [f"feuilles-{J1}.txt.gz : différent des feuilles recalculées"])

    def test_commande_verifier_feuilles(self):
        self.sceller(J1)
        args = ["verifier-feuilles", "--feuilles", str(adn.fichier_feuilles(self.dest, J1)),
                "--adn", str(adn.fichier_adn(self.dest, J1))]
        with unittest.mock.patch("builtins.print"):
            self.assertEqual(adn.main(args + ["--empreinte", str(self.src.d / "empreintes" / f"{J1}.txt")]), 0)
            autre = Path(self.tmp) / "autre.txt"
            autre.write_text("x\n", encoding="utf-8")
            self.assertEqual(adn.main(args + ["--empreinte", str(autre)]), 1)


if __name__ == "__main__":
    unittest.main()
