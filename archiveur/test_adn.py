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


class TestADN(unittest.TestCase):
    def setUp(self):
        patch = unittest.mock.patch.object(adn, "mesurer_genes", faux_genes)   # jamais de réseau ni de commande système
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
        self.assertEqual(sorted(avant), [f"adn-{J1}.json", f"adn-{J1}.json.ots", f"adn-{J2}.json", f"adn-{J2}.json.ots"])
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


class TestGenesDansADN(TestADN):
    def test_adn_produit_meme_si_tout_est_indisponible(self):
        indispo = lambda conf, j, n: {k: adn.indisponible("panne") for k in adn.NOMS_GENES}
        fin = self.jours(J1)
        r = adn.executer(self.conf, now_s=fin, horo=FauxHorodateurs(), genes=indispo)
        self.assertEqual(r["adn_construits"], [J1])
        self.assertEqual(self.lire(J1)["feuilles"]["genes"], 5)
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


if __name__ == "__main__":
    unittest.main()
